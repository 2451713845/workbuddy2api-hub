from __future__ import annotations

import json
import os
import base64
import select
import socket
import socketserver
import tempfile
import threading
import time
from pathlib import Path
from urllib.parse import unquote, urlparse


TDID_CHANNEL = "109137"


class _ProxyBridgeHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        upstream = None
        try:
            request = b""
            while b"\r\n\r\n" not in request and len(request) < 65536:
                chunk = self.request.recv(8192)
                if not chunk:
                    return
                request += chunk
            head, marker, remainder = request.partition(b"\r\n\r\n")
            lines = head.split(b"\r\n")
            if not lines:
                return
            first = lines[0].decode("latin-1", "replace")
            method, target, _ = (first.split(" ", 2) + ["", ""])[:3]
            upstream = socket.create_connection(
                (self.server.upstream_host, self.server.upstream_port),
                timeout=self.server.connect_timeout,
            )
            auth = self.server.proxy_authorization
            filtered = [
                line for line in lines[1:]
                if not line.lower().startswith(b"proxy-authorization:")
            ]
            forwarded = b"\r\n".join(
                [lines[0], *filtered, b"Proxy-Authorization: " + auth]
            ) + b"\r\n\r\n" + remainder
            upstream.sendall(forwarded)
            if method.upper() == "CONNECT":
                response = b""
                while b"\r\n\r\n" not in response and len(response) < 65536:
                    chunk = upstream.recv(8192)
                    if not chunk:
                        break
                    response += chunk
                self.request.sendall(response)
                status_line = response.split(b"\r\n", 1)[0]
                if b" 200 " not in status_line:
                    return
            self._relay(self.request, upstream)
        except (OSError, ValueError):
            return
        finally:
            if upstream is not None:
                try:
                    upstream.close()
                except OSError:
                    pass

    @staticmethod
    def _relay(client, upstream) -> None:
        sockets = [client, upstream]
        while True:
            readable, _, _ = select.select(sockets, [], [], 30.0)
            if not readable:
                return
            for source in readable:
                data = source.recv(65536)
                if not data:
                    return
                (upstream if source is client else client).sendall(data)


class _ProxyBridgeServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True


class _ProxyBridge:
    def __init__(self, proxy: str, timeout: float) -> None:
        parsed = urlparse(proxy)
        if parsed.scheme != "http":
            raise ValueError("TDID browser proxy must use http")
        if not parsed.hostname or not parsed.port:
            raise ValueError("proxy must include host and port")
        username = unquote(parsed.username or "")
        password = unquote(parsed.password or "")
        credentials = base64.b64encode(
            (username + ":" + password).encode("utf-8")
        )
        self.server = _ProxyBridgeServer(("127.0.0.1", 0), _ProxyBridgeHandler)
        self.server.upstream_host = parsed.hostname
        self.server.upstream_port = parsed.port
        self.server.connect_timeout = min(max(float(timeout), 5.0), 30.0)
        self.server.proxy_authorization = b"Basic " + credentials
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def start(self) -> str:
        self.thread.start()
        host, port = self.server.server_address
        return "http://%s:%d" % (host, port)

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2.0)


def _fingerprint_script(fingerprint) -> str:
    """Keep the TDID page's JavaScript-visible device coherent with the UA."""
    values = {
        "platform": fingerprint.platform,
        "cores": fingerprint.hardware_concurrency,
        "memory": fingerprint.device_memory,
        "width": fingerprint.screen_width,
        "height": fingerprint.screen_height,
        "dpr": fingerprint.device_pixel_ratio,
        "webgl_vendor": fingerprint.webgl_vendor,
        "webgl_renderer": fingerprint.webgl_renderer,
    }
    return """
(() => {
  const fp = %s;
  const define = (object, name, value) => {
    try { Object.defineProperty(object, name, {get: () => value, configurable: true}); }
    catch (_) {}
  };
  define(Navigator.prototype, 'platform', fp.platform);
  define(Navigator.prototype, 'hardwareConcurrency', fp.cores);
  define(Navigator.prototype, 'deviceMemory', fp.memory);
  define(Navigator.prototype, 'webdriver', undefined);
  define(Screen.prototype, 'width', fp.width);
  define(Screen.prototype, 'height', fp.height);
  define(Screen.prototype, 'availWidth', fp.width);
  define(Screen.prototype, 'availHeight', fp.height - 40);
  define(window, 'devicePixelRatio', fp.dpr);
  const patchWebGL = (prototype) => {
    if (!prototype || !prototype.getParameter) return;
    const original = prototype.getParameter;
    Object.defineProperty(prototype, 'getParameter', {
      configurable: true,
      value: function(parameter) {
        if (parameter === 37445) return fp.webgl_vendor;
        if (parameter === 37446) return fp.webgl_renderer;
        return original.call(this, parameter);
      }
    });
  };
  patchWebGL(window.WebGLRenderingContext && WebGLRenderingContext.prototype);
  patchWebGL(window.WebGL2RenderingContext && WebGL2RenderingContext.prototype);
})();
""" % json.dumps(values, ensure_ascii=True, separators=(",", ":"))


def _proxy_extension(proxy: str, root: str) -> str:
    parsed = urlparse(proxy)
    if not parsed.hostname or not parsed.port:
        raise ValueError("proxy must include host and port")
    scheme = parsed.scheme or "http"
    username = parsed.username or ""
    password = parsed.password or ""
    manifest = {
        "manifest_version": 2,
        "name": "WorkBuddy registration proxy",
        "version": "1.0.0",
        "permissions": ["proxy", "webRequest", "webRequestBlocking", "<all_urls>"],
        "background": {"scripts": ["background.js"]},
    }
    background = """const config = %s;
chrome.proxy.settings.set({value:{mode:'fixed_servers',rules:{singleProxy:{scheme:%r,host:%r,port:%d}}},scope:'regular'});
chrome.webRequest.onAuthRequired.addListener(function(details){return {authCredentials:{username:%r,password:%r}};},{urls:['<all_urls>']},['blocking']);
""" % (json.dumps({"username": username, "password": password}), scheme, parsed.hostname, parsed.port, username, password)
    Path(root, "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    Path(root, "background.js").write_text(background, encoding="utf-8")
    return root


def acquire_device_identity(proxy: str, fingerprint, *, timeout: float = 90.0) -> dict:
    """Run the vendor's official TDID web SDK and return its token plus cookies."""
    if str(os.environ.get("WB_TDID_ENABLED", "1")).lower() in {"0", "false", "off"}:
        return {"token": "", "cookies": {}, "source": "disabled"}
    from selenium import webdriver
    from selenium.webdriver.chrome.options import Options
    from selenium.webdriver.chrome.service import Service

    chrome = os.environ.get("CHROMIUM_PATH") or "/usr/bin/chromium"
    driver = os.environ.get("CHROMEDRIVER_PATH") or "/usr/bin/chromedriver"
    options = Options()
    options.binary_location = chrome
    options.add_argument("--headless=new")
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-dev-shm-usage")
    options.add_argument("--disable-gpu")
    options.add_argument("--window-size=%d,%d" % (fingerprint.screen_width, fingerprint.screen_height))
    options.add_argument("--lang=%s" % fingerprint.accept_language.split(",", 1)[0])
    proxy_bridge = None
    if proxy:
        proxy_bridge = _ProxyBridge(proxy, timeout)
        options.add_argument("--proxy-server=" + proxy_bridge.start())
    driver_obj = None
    try:
        driver_obj = webdriver.Chrome(service=Service(driver), options=options)
        driver_obj.execute_cdp_cmd("Network.setUserAgentOverride", {
            "userAgent": fingerprint.user_agent,
            "acceptLanguage": fingerprint.accept_language,
            "platform": "Windows",
            "userAgentMetadata": {
                "brands": [
                    {"brand": "Chromium", "version": fingerprint.major_version},
                    {"brand": "Google Chrome", "version": fingerprint.major_version},
                    {"brand": "Not_A Brand", "version": "24"},
                ],
                "fullVersionList": [
                    {"brand": "Chromium", "version": fingerprint.full_version},
                    {"brand": "Google Chrome", "version": fingerprint.full_version},
                    {"brand": "Not_A Brand", "version": "24.0.0.0"},
                ],
                "fullVersion": fingerprint.full_version,
                "platform": "Windows",
                "platformVersion": fingerprint.platform_version,
                "architecture": "x86",
                "model": "",
                "mobile": False,
                "bitness": "64",
                "wow64": False,
            },
        })
        driver_obj.execute_cdp_cmd("Emulation.setTimezoneOverride", {"timezoneId": fingerprint.timezone})
        driver_obj.execute_cdp_cmd(
            "Page.addScriptToEvaluateOnNewDocument",
            {"source": _fingerprint_script(fingerprint)},
        )
        driver_obj.set_window_size(fingerprint.screen_width, fingerprint.screen_height)
        driver_obj.set_page_load_timeout(min(float(timeout), 120.0))
        driver_obj.get("https://www.workbuddy.cn/login/?platform=workbuddy&version=5.8.3")
        driver_obj.set_script_timeout(min(float(timeout), 120.0))
        deadline = time.monotonic() + float(timeout)
        token_result = {}
        while time.monotonic() < deadline:
            if not driver_obj.execute_script(
                "return typeof window._TDID !== 'undefined'"
            ):
                time.sleep(0.25)
                continue
            token_result = driver_obj.execute_async_script("""
                const done = arguments[arguments.length - 1];
                try {
                  if (typeof _TDID === 'undefined') return done({ret: -100004, err: 'TDID SDK missing'});
                  _TDID.init({channel: '109137'}, function(init) {
                    if (!init || init.ret !== 0) return done(init || {ret: -100005});
                    _TDID.getDeviceTokenInfoV3(function(result) { done(result || {}); }, true);
                  });
                } catch (error) { done({ret: -100005, err: String(error)}); }
            """)
            token = str(
                (token_result or {}).get("deviceTokenInfo") or ""
            ).strip()
            if token:
                break
            time.sleep(0.5)
        else:
            token = ""
        if not token:
            raise RuntimeError("TDID token acquisition failed: " + json.dumps(token_result, ensure_ascii=False))
        cookies = {
            str(item.get("name")): str(item.get("value"))
            for item in driver_obj.get_cookies()
            if item.get("name") and item.get("value")
        }
        return {"token": token, "cookies": cookies, "source": "official_tdid", "channel": TDID_CHANNEL}
    finally:
        if driver_obj is not None:
            driver_obj.quit()
        if proxy_bridge is not None:
            proxy_bridge.close()
