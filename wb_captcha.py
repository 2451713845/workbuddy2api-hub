"""Tencent slider completion backed by CapSolver VisionEngine and Chromium."""

import base64
import io
import importlib
import json
import math
import os
import random
import socket
import socketserver
import threading
import time
from urllib.parse import quote, unquote, urlparse


CHROME_150_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/150.0.0.0 Safari/537.36"
)
CAPSOLVER_CREATE_TASK = "https://api.capsolver.com/createTask"
TENCENT_CONNECT_TO_HOSTS = frozenset((
    "t.captcha.qq.com",
    "ssl.captcha.qq.com",
    "captcha.qq.com",
    "oauth2.account.tencent.com",
))


class CaptchaSolveError(RuntimeError):
    pass


def _read_headers(sock, limit=65536):
    data = bytearray()
    while b"\r\n\r\n" not in data:
        chunk = sock.recv(min(8192, limit - len(data)))
        if not chunk:
            break
        data.extend(chunk)
        if len(data) >= limit:
            raise CaptchaSolveError("proxy request headers are too large")
    return bytes(data)


def _split_authority(authority, default_port):
    parsed = urlparse("//" + authority)
    return parsed.hostname or authority, parsed.port or default_port


def _resolve_ipv4(host, port):
    for family, socktype, proto, _, address in socket.getaddrinfo(
            host, port, socket.AF_INET, socket.SOCK_STREAM):
        if family == socket.AF_INET and socktype == socket.SOCK_STREAM:
            return address[0]
    raise CaptchaSolveError("no IPv4 address resolved for %s" % host)


def _relay(left, right):
    select = importlib.import_module("select")
    sockets = [left, right]
    while sockets:
        readable, _, exceptional = select.select(sockets, [], sockets, 30)
        if exceptional:
            break
        if not readable:
            continue
        for source in readable:
            destination = right if source is left else left
            try:
                chunk = source.recv(65536)
            except OSError:
                return
            if not chunk:
                return
            destination.sendall(chunk)


class _ThreadingTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True


class ConnectToProxy(object):
    """Local proxy that rewrites selected upstream CONNECT hosts to IPv4."""

    def __init__(self, upstream_url, connect_to_hosts=None):
        parsed = urlparse(str(upstream_url or ""))
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            raise CaptchaSolveError("captcha browser requires an HTTP proxy URL")
        self.upstream_url = str(upstream_url)
        self.host = parsed.hostname
        self.port = parsed.port or (443 if parsed.scheme == "https" else 80)
        self.username = unquote(parsed.username or "")
        self.password = unquote(parsed.password or "")
        self.connect_to_hosts = frozenset(
            str(item).strip().lower().rstrip(".")
            for item in (connect_to_hosts or TENCENT_CONNECT_TO_HOSTS)
        )
        self.server = None
        self.thread = None
        self.url = ""

    def __enter__(self):
        owner = self

        class Handler(socketserver.BaseRequestHandler):
            def handle(self):
                owner._handle(self.request)

        self.server = _ThreadingTCPServer(("127.0.0.1", 0), Handler)
        self.url = "http://127.0.0.1:%d" % self.server.server_address[1]
        self.thread = threading.Thread(
            target=self.server.serve_forever,
            name="wb-captcha-connect-proxy",
            daemon=True,
        )
        self.thread.start()
        return self

    def __exit__(self, exc_type, exc, traceback):
        if self.server is not None:
            self.server.shutdown()
            self.server.server_close()
        if self.thread is not None:
            self.thread.join(timeout=3)

    def _auth_header(self):
        if not self.username:
            return b""
        token = base64.b64encode(
            (self.username + ":" + self.password).encode("utf-8")
        ).decode("ascii")
        return ("Proxy-Authorization: Basic %s\r\n" % token).encode("ascii")

    def _handle(self, client):
        upstream = None
        try:
            client.settimeout(30)
            request = _read_headers(client)
            if not request:
                return
            first = request.split(b"\r\n", 1)[0].decode("latin-1")
            method, target, _ = first.split(" ", 2)
            upstream = socket.create_connection((self.host, self.port), timeout=30)
            upstream.settimeout(30)
            if method.upper() == "CONNECT":
                target_host, target_port = _split_authority(target, 443)
                connect_host = target_host
                if target_host.lower().rstrip(".") in self.connect_to_hosts:
                    connect_host = _resolve_ipv4(target_host, target_port)
                authority = "%s:%d" % (connect_host, target_port)
                upstream.sendall(
                    ("CONNECT %s HTTP/1.1\r\nHost: %s\r\n" %
                     (authority, authority)).encode("ascii")
                    + self._auth_header()
                    + b"Proxy-Connection: Keep-Alive\r\n\r\n"
                )
                response = _read_headers(upstream)
                status_line = response.split(b"\r\n", 1)[0]
                if b" 200 " not in status_line:
                    client.sendall(response)
                    return
                client.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                _relay(client, upstream)
                return

            lines = request.split(b"\r\n")
            forwarded = [lines[0]]
            forwarded.extend(
                line for line in lines[1:]
                if not line.lower().startswith(b"proxy-authorization:")
            )
            if self.username:
                forwarded.insert(-2, self._auth_header().rstrip(b"\r\n"))
            upstream.sendall(b"\r\n".join(forwarded))
            _relay(client, upstream)
        except (OSError, ValueError, CaptchaSolveError):
            try:
                client.sendall(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
            except OSError:
                pass
        finally:
            if upstream is not None:
                try:
                    upstream.close()
                except OSError:
                    pass


def _edge_map(image_bytes):
    Image = importlib.import_module("PIL.Image")
    ImageFilter = importlib.import_module("PIL.ImageFilter")
    numpy = importlib.import_module("numpy")

    image = Image.open(io.BytesIO(image_bytes)).convert("L")
    edges = image.filter(ImageFilter.FIND_EDGES)
    array = numpy.asarray(edges, dtype=numpy.uint8)
    threshold = max(28, int(numpy.percentile(array, 84)))
    return array >= threshold


def edge_match_distance(background_bytes, piece_bytes):
    """Return the x coordinate whose edge map best matches the puzzle piece."""
    numpy = importlib.import_module("numpy")

    background = _edge_map(background_bytes)
    piece = _edge_map(piece_bytes)
    bg_height, bg_width = background.shape
    piece_height, piece_width = piece.shape
    out_height = bg_height - piece_height + 1
    out_width = bg_width - piece_width + 1
    if out_height <= 0 or out_width <= 0:
        raise CaptchaSolveError("captcha piece is larger than its background")
    points = numpy.argwhere(piece)
    if len(points) < 8:
        raise CaptchaSolveError("captcha piece has too few edges")
    stride = max(1, int(math.ceil(len(points) / 700.0)))
    scores = numpy.zeros((out_height, out_width), dtype=numpy.uint16)
    for y, x in points[::stride]:
        scores += background[y:y + out_height, x:x + out_width]
    best_y, best_x = numpy.unravel_index(int(scores.argmax()), scores.shape)
    confidence = float(scores[best_y, best_x]) / float(len(points[::stride]))
    return float(best_x), confidence


class TencentCaptchaSolver(object):
    def __init__(self, api_key, log=None, timeout=180):
        self.api_key = str(api_key or "").strip()
        self.log = log or (lambda message, **kwargs: None)
        self.timeout = max(30.0, float(timeout))

    @property
    def enabled(self):
        return bool(self.api_key)

    def _capsolver(self, piece, background):
        requests = __import__("curl_cffi.requests", fromlist=["requests"])
        payload = {
            "clientKey": self.api_key,
            "task": {
                "type": "VisionEngine",
                "module": "slider_1",
                "image": base64.b64encode(piece).decode("ascii"),
                "imageBackground": base64.b64encode(background).decode("ascii"),
            },
        }
        response = requests.post(
            CAPSOLVER_CREATE_TASK,
            json=payload,
            impersonate="chrome150",
            timeout=min(self.timeout, 60),
        )
        try:
            data = response.json()
        except ValueError:
            raise CaptchaSolveError(
                "CapSolver returned HTTP %s with invalid JSON" % response.status_code
            )
        if int(data.get("errorId") or 0):
            raise CaptchaSolveError(
                "CapSolver %s: %s" % (
                    data.get("errorCode") or "error",
                    data.get("errorDescription") or "unknown error",
                )
            )
        return data

    @staticmethod
    def _script_url(cloud_type):
        if cloud_type == "tencent":
            return "https://turing.captcha.qcloud.com/TJCaptcha.js"
        return "https://captcha.gtimg.com/TCaptcha.js"

    @staticmethod
    def _browser_paths():
        return (
            os.environ.get("CHROMIUM_PATH") or "/usr/bin/chromium",
            os.environ.get("CHROMEDRIVER_PATH") or "/usr/bin/chromedriver",
        )

    def _solve_option(self, option, proxy, status_callback=None, cancelled=None):
        webdriver = importlib.import_module("selenium.webdriver")
        ActionChains = importlib.import_module(
            "selenium.webdriver.common.action_chains").ActionChains
        Options = importlib.import_module(
            "selenium.webdriver.chrome.options").Options
        Service = importlib.import_module(
            "selenium.webdriver.chrome.service").Service
        By = importlib.import_module("selenium.webdriver.common.by").By
        WebDriverWait = importlib.import_module(
            "selenium.webdriver.support.ui").WebDriverWait

        app_id = str(option.get("appId") or "").strip()
        cloud_type = str(option.get("cloudType") or "").strip()
        if not app_id or cloud_type not in ("teg", "tencent"):
            raise CaptchaSolveError("invalid Tencent captcha option")
        chromium_path, driver_path = self._browser_paths()
        details = {
            "provider": "CapSolver",
            "taskType": "VisionEngine",
            "module": "slider_1",
            "appId": app_id,
            "cloudType": cloud_type,
            "attempts": [],
        }
        with ConnectToProxy(proxy) as local_proxy:
            options = Options()
            options.binary_location = chromium_path
            for argument in (
                "--headless=new",
                "--no-sandbox",
                "--disable-dev-shm-usage",
                "--disable-gpu",
                "--disable-blink-features=AutomationControlled",
                "--lang=zh-CN",
                "--window-size=1280,800",
                "--proxy-server=" + local_proxy.url,
                "--user-agent=" + CHROME_150_UA,
            ):
                options.add_argument(argument)
            driver = webdriver.Chrome(service=Service(driver_path), options=options)
            try:
                details["browserVersion"] = str(
                    (driver.capabilities or {}).get("browserVersion") or ""
                )
                driver.execute_cdp_cmd("Page.addScriptToEvaluateOnNewDocument", {
                    "source": (
                        "Object.defineProperty(navigator,'webdriver',{get:()=>undefined});"
                        "Object.defineProperty(navigator,'languages',{get:()=>['zh-CN','zh']});"
                    ),
                })
                page = (
                    "<!doctype html><html><head><meta charset='utf-8'></head>"
                    "<body><script>window.__captchaResult=null;</script></body></html>"
                )
                driver.get("data:text/html;charset=utf-8," + quote(page))
                driver.execute_script(
                    "var s=document.createElement('script');s.src=arguments[0];"
                    "document.head.appendChild(s);", self._script_url(cloud_type)
                )
                wait = WebDriverWait(driver, 30)
                wait.until(lambda current: current.execute_script(
                    "return typeof window.TencentCaptcha === 'function'"
                ))
                driver.execute_script(
                    "window.__tc=new TencentCaptcha(arguments[0],function(result){"
                    "window.__captchaResult=result;},{userLanguage:'zh-cn'});"
                    "window.__tc.show();", app_id
                )

                for attempt_number in range(1, 4):
                    if cancelled and cancelled():
                        raise CaptchaSolveError("captcha solving cancelled")
                    wait.until(lambda current: current.find_elements(
                        By.CSS_SELECTOR, "iframe[id^='tcaptcha_iframe']"
                    ))
                    iframe = driver.find_element(
                        By.CSS_SELECTOR, "iframe[id^='tcaptcha_iframe']"
                    )
                    driver.switch_to.frame(iframe)
                    background = wait.until(lambda current: current.find_element(
                        By.CSS_SELECTOR, "#slideBg"
                    ))
                    def rendered_piece(current):
                        for candidate in current.find_elements(
                                By.CSS_SELECTOR, ".tc-fg-item"):
                            size = candidate.size
                            background_image = current.execute_script(
                                "return getComputedStyle(arguments[0]).backgroundImage || '';",
                                candidate,
                            )
                            if (40 <= float(size.get("width") or 0) <= 100
                                    and 40 <= float(size.get("height") or 0) <= 100
                                    and background_image != "none"):
                                return candidate
                        return False

                    piece = wait.until(rendered_piece)
                    thumb = driver.find_element(By.CSS_SELECTOR, ".tc-slider-normal")
                    time.sleep(0.3)
                    background_png = background.screenshot_as_png
                    piece_png = piece.screenshot_as_png
                    current_left = float(piece.location["x"] - background.location["x"])
                    if status_callback:
                        status_callback("capsolver", attempt_number)
                    capsolver = self._capsolver(piece_png, background_png)
                    solution = capsolver.get("solution") or {}
                    detector = "capsolver"
                    target_left = solution.get("distance")
                    confidence = None
                    if not isinstance(target_left, (int, float)) or target_left <= 0:
                        target_left, confidence = edge_match_distance(
                            background_png, piece_png
                        )
                        detector = "edge-match"
                    delta = float(target_left) - current_left
                    attempt = {
                        "number": attempt_number,
                        "taskId": capsolver.get("taskId") or "",
                        "solution": solution,
                        "detector": detector,
                        "targetLeft": round(float(target_left), 3),
                        "pieceLeft": round(current_left, 3),
                        "dragDistance": round(delta, 3),
                    }
                    if confidence is not None:
                        attempt["confidence"] = round(confidence, 4)
                    details["attempts"].append(attempt)
                    if delta < 5 or delta > float(background.size["width"]) - 5:
                        driver.switch_to.default_content()
                        raise CaptchaSolveError(
                            "captcha drag distance is out of range: %.2f" % delta
                        )
                    if status_callback:
                        status_callback("dragging", attempt_number)
                    actions = ActionChains(driver, duration=45)
                    actions.move_to_element(thumb).click_and_hold()
                    moved = 0.0
                    steps = max(12, min(30, int(abs(delta) / 4)))
                    for index in range(1, steps + 1):
                        progress = float(index) / float(steps)
                        eased = 1.0 - (1.0 - progress) ** 3
                        next_moved = delta * eased
                        step_x = int(round(next_moved - moved))
                        moved += step_x
                        step_y = random.choice((0, 0, 0, 1, -1))
                        actions.move_by_offset(step_x, step_y).pause(
                            random.uniform(0.012, 0.045)
                        )
                    remainder = int(round(delta - moved))
                    if remainder:
                        actions.move_by_offset(remainder, 0)
                    actions.pause(random.uniform(0.08, 0.18)).release().perform()
                    driver.switch_to.default_content()
                    deadline = time.monotonic() + 8
                    while time.monotonic() < deadline:
                        result = driver.execute_script(
                            "return window.__captchaResult"
                        )
                        if isinstance(result, dict):
                            attempt["ret"] = result.get("ret")
                            if (result.get("ret") == 0 and result.get("ticket")
                                    and result.get("randstr")):
                                return {
                                    "ticket": str(result["ticket"]),
                                    "randStr": str(result["randstr"]),
                                    "cloudType": cloud_type,
                                }, details
                            break
                        time.sleep(0.2)
                    driver.execute_script("window.__captchaResult=null;")
                    driver.switch_to.frame(iframe)
                    try:
                        driver.find_element(
                            By.CSS_SELECTOR, "button.tc-refresh-icon"
                        ).click()
                    except Exception:
                        pass
                    driver.switch_to.default_content()
                    time.sleep(1)
                raise CaptchaSolveError("Tencent captcha rejected three slider attempts")
            finally:
                driver.quit()

    def solve(self, options, proxy, status_callback=None, cancelled=None):
        if not self.enabled:
            raise CaptchaSolveError("CapSolver API key is not configured")
        failures = []
        for option in options:
            try:
                return self._solve_option(
                    option,
                    proxy,
                    status_callback=status_callback,
                    cancelled=cancelled,
                )
            except Exception as exc:
                failures.append({
                    "appId": str(option.get("appId") or ""),
                    "cloudType": str(option.get("cloudType") or ""),
                    "error": str(exc),
                })
                self.log(
                    "CapSolver Tencent option %s failed: %s" % (
                        option.get("cloudType") or "?", exc
                    ),
                    tag="accounts",
                )
        raise CaptchaSolveError(
            "all Tencent captcha options failed: "
            + json.dumps(failures, ensure_ascii=False)
        )
