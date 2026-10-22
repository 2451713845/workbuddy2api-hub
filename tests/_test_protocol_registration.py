"""Protocol registration job, account import and dashboard contract."""

import json
import os
import sys
import tempfile
import threading
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

import wb_accounts
import wb_proxy
import wb_registration
import wb_settings
import wb_devices
from workbuddy_protocol.client import LoginContext, WorkBuddyProtocolClient
from workbuddy_protocol.config import ProtocolConfig
from workbuddy_protocol.fingerprint import BrowserFingerprint
from workbuddy_protocol.transport import ProtocolTransport


class FakeProtocolClient(object):
    def __init__(self, config, fingerprint=None):
        self.config = config
        self.fingerprint = fingerprint
        self.result = {"fingerprint": fingerprint.to_dict(), "steps": {}}

    def begin(self, phone, captcha_callback=None):
        if phone.endswith("80"):
            assert captcha_callback is not None
            verification = captcha_callback([
                {"appId": "2053989439", "cloudType": "teg"},
                {"appId": "197561220", "cloudType": "tencent"},
            ], "captcha-state")
            assert verification == {
                "ticket": "captcha-ticket",
                "randStr": "captcha-randstr",
                "cloudType": "teg",
            }
        value = {"status": "ok", "state_token": "state-1", "phone": phone}
        self.result["steps"]["sms_send"] = value
        return value

    def complete(self, otp):
        assert otp == "123456"
        self.result["steps"]["sms_verify"] = {"status": "ok", "code": otp}
        self.result["steps"]["desktop_token_poll"] = {
            "token": {
                "accessToken": "test-access-token",
                "refreshToken": "test-refresh-token",
                "domain": "www.workbuddy.cn",
            }
        }
        self.result["steps"]["desktop_account_poll"] = {
            "code": 0,
            "data": {"uid": "protocol-user-1", "nickname": "protocol-user"},
        }
        return self.result


class FakeCaptchaSolver(object):
    enabled = True

    def __init__(self):
        self.calls = []

    def solve(self, options, proxy, status_callback=None, cancelled=None):
        self.calls.append({"options": options, "proxy": proxy})
        assert not cancelled()
        status_callback("capsolver", 1)
        status_callback("dragging", 1)
        return ({
            "ticket": "captcha-ticket",
            "randStr": "captcha-randstr",
            "cloudType": "teg",
        }, {
            "provider": "CapSolver",
            "taskType": "VisionEngine",
            "module": "slider_1",
            "browserVersion": "150.0.0.0",
            "attempts": [{"taskId": "capsolver-task-1"}],
        })


def wait_for(manager, job_id, states, timeout=3.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        current = manager.snapshot(job_id)
        if current["status"] in states:
            return current
        time.sleep(0.01)
    raise AssertionError("registration job did not reach %r" % (states,))


original_client = wb_registration.WorkBuddyProtocolClient
original_choice = wb_registration.secrets.choice
original_rewards = wb_registration.run_post_registration_rewards
try:
    wb_registration.WorkBuddyProtocolClient = FakeProtocolClient
    wb_registration.run_post_registration_rewards = lambda account: {
        "ok": True,
        "msg": "test rewards complete",
        "earned_credit": 1450,
    }
    with tempfile.TemporaryDirectory() as root:
        pool = wb_accounts.AccountPool(root)
        validations = []
        slots = wb_settings.set_proxy_slots(root, [
            {"name": "disabled", "url": "http://disabled:8080", "enabled": False},
            {"name": "hong-kong", "url": "http://hk-proxy:8080", "enabled": True},
            {"name": "singapore", "url": "socks5://sg-proxy:1080", "enabled": True},
        ])

        def validate(account):
            validations.append(account)
            headers = account.headers(purpose="chat", model="deepseek-v4.1-flash")
            assert headers["X-Device-Token"] == "device-token-exact"
            assert account.proxy == "http://hk-proxy:8080"
            return {"ok": True, "reply": "live reply", "model": "deepseek-v4.1-flash"}

        manager = wb_registration.RegistrationManager(
            root, pool, validate_account=validate
        )
        chosen_ids = iter((slots[1]["id"], slots[2]["id"]))
        def choose_slot(candidates):
            wanted = next(chosen_ids)
            return next(item for item in candidates if item["id"] == wanted)
        wb_registration.secrets.choice = choose_slot
        wb_settings.set_upstream_config(root, {"device_token": "device-token-exact"})
        started = manager.start({
            "phone": "70281878",
        })
        assert started["deviceToken"] == "device-token-exact"
        assert started["proxy"] == "http://hk-proxy:8080"
        assert started["proxySlot"] == slots[1]["id"]
        assert started["proxyLabel"] == "hong-kong"
        job_id = started["id"]
        waiting = wait_for(manager, job_id, {"waiting_otp"})
        assert waiting["fingerprint"] == "chrome150"
        manager.submit_otp(job_id, "123456")
        done = wait_for(manager, job_id, {"succeeded", "failed"})
        assert done["status"] == "succeeded", done
        assert done["account"]["uid"] == "protocol-user-1"
        assert done["account"]["nickname"] == "+852 70281878"
        assert done["account"]["proxySlot"] == slots[1]["id"]
        assert done["account"]["deviceToken"] == "device-token-exact"
        assert done["result"]["account_validation"]["ok"] is True
        assert done["result"]["post_registration_rewards"]["earned_credit"] == 1450
        assert len(validations) == 1
        assert validations[0].accounts_dir == root
        assert pool.get("protocol-user-1") is not None
        assert os.path.isfile(os.path.join(root, "protocol-user-1.json"))
        state_path = os.path.join(root, "registration-jobs", job_id, "job.json")
        assert os.path.isfile(state_path)
        reloaded_manager = wb_registration.RegistrationManager(root, pool)
        restored = reloaded_manager.snapshot(job_id)
        assert restored["status"] == "succeeded"
        assert restored["account"]["uid"] == "protocol-user-1"
        recent_after_restart = reloaded_manager.recent()
        assert recent_after_restart[0]["id"] == job_id
        assert recent_after_restart[0]["proxySlot"] == slots[1]["id"]
        assert "events" not in recent_after_restart[0]
        assert "result" not in recent_after_restart[0]
        os.unlink(state_path)
        legacy_restored = wb_registration.RegistrationManager(root, pool).snapshot(job_id)
        assert legacy_restored["status"] == "succeeded"
        assert legacy_restored["result"]["account_validation"]["ok"] is True
        assert wb_settings.upstream_config(root)["device_token"] == "device-token-exact"

        # The next random choice uses another enabled slot and never accepts a
        # browser-provided proxy override.
        rotated = manager.start({
            "phone": "+85270281879",
            "proxy": "http://browser-override:9999",
        })
        assert rotated["proxy"] == "socks5://sg-proxy:1080"
        assert rotated["proxySlot"] == slots[2]["id"]
        manager.cancel(rotated["id"])
        wait_for(manager, rotated["id"], {"cancelled"})

    with tempfile.TemporaryDirectory() as root:
        pool = wb_accounts.AccountPool(root)
        manager = wb_registration.RegistrationManager(root, pool)
        wb_settings.set_upstream_config(root, {"device_token": "device-token-exact"})
        try:
            manager.start({"phone": "+85270281878"})
            raise AssertionError("an empty proxy pool must reject registration")
        except ValueError as exc:
            assert "no enabled proxy" in str(exc)

    with tempfile.TemporaryDirectory() as root:
        pool = wb_accounts.AccountPool(root)
        manager = wb_registration.RegistrationManager(
            root, pool,
            validate_account=lambda account: {
                "ok": False, "status": 401, "error": "probe failed"
            },
        )
        wb_settings.set_upstream_config(root, {"device_token": "device-token-exact"})
        wb_settings.set_proxy_slots(root, [
            {"name": "only", "url": "http://proxy:8080", "enabled": True},
        ])
        wb_registration.secrets.choice = lambda candidates: candidates[0]
        started = manager.start({
            "phone": "+85270281878",
        })
        job_id = started["id"]
        wait_for(manager, job_id, {"waiting_otp"})
        manager.submit_otp(job_id, "123456")
        done = wait_for(manager, job_id, {"failed"})
        assert done["failure"]["message"] == "account validation failed: probe failed"
        assert pool.get("protocol-user-1") is None
        assert not os.path.exists(os.path.join(root, "protocol-user-1.json"))

    with tempfile.TemporaryDirectory() as root:
        pool = wb_accounts.AccountPool(root)
        manager = wb_registration.RegistrationManager(
            root, pool,
            validate_account=lambda account: {
                "ok": False, "status": None,
                "error": "URLError: Tunnel connection failed: 803 SERVICE_UNAVAILABLE",
            },
        )
        wb_settings.set_upstream_config(root, {"device_token": "device-token-exact"})
        wb_settings.set_proxy_slots(root, [
            {"name": "only", "url": "http://proxy:8080", "enabled": True},
        ])
        wb_registration.secrets.choice = lambda candidates: candidates[0]
        started = manager.start({"phone": "+85270281878"})
        wait_for(manager, started["id"], {"waiting_otp"})
        manager.submit_otp(started["id"], "123456")
        done = wait_for(manager, started["id"], {"succeeded", "failed"})
        assert done["status"] == "succeeded", done
        assert done["result"]["account_validation_deferred"] is True
        assert pool.get("protocol-user-1") is not None

    with tempfile.TemporaryDirectory() as root:
        pool = wb_accounts.AccountPool(root)
        solver = FakeCaptchaSolver()
        manager = wb_registration.RegistrationManager(
            root, pool, captcha_solver=solver,
            validate_account=lambda account: {"ok": True},
        )
        wb_settings.set_upstream_config(root, {"device_token": "device-token-exact"})
        slots = wb_settings.set_proxy_slots(root, [
            {"name": "captcha-auto", "url": "http://proxy:8080", "enabled": True},
        ])
        wb_registration.secrets.choice = lambda candidates: candidates[0]
        started = manager.start({"phone": "+85270281880"})
        waiting = wait_for(manager, started["id"], {"waiting_otp"})
        assert waiting["captchaSolver"]["status"] == "succeeded"
        assert waiting["captchaSolver"]["module"] == "slider_1"
        assert solver.calls[0]["proxy"] == "http://proxy:8080"
        assert solver.calls[0]["options"][0]["appId"] == "2053989439"
        manager.submit_otp(started["id"], "123456")
        done = wait_for(manager, started["id"], {"succeeded", "failed"})
        assert done["status"] == "succeeded", done
        assert done["account"]["proxySlot"] == slots[0]["id"]

    with tempfile.TemporaryDirectory() as root:
        pool = wb_accounts.AccountPool(root)
        manager = wb_registration.RegistrationManager(
            root, pool, validate_account=lambda account: {"ok": True},
            captcha_solver=False,
        )
        wb_settings.set_upstream_config(root, {"device_token": "device-token-exact"})
        wb_settings.set_proxy_slots(root, [
            {"name": "captcha", "url": "http://proxy:8080", "enabled": True},
        ])
        wb_registration.secrets.choice = lambda candidates: candidates[0]
        started = manager.start({"phone": "+85270281880"})
        challenge = wait_for(manager, started["id"], {"waiting_captcha"})
        assert challenge["captcha"]["stateToken"] == "captcha-state"
        assert challenge["captcha"]["options"][0] == {
            "appId": "2053989439", "cloudType": "teg",
        }
        manager.submit_captcha(started["id"], {
            "ticket": "captcha-ticket",
            "randStr": "captcha-randstr",
            "cloudType": "teg",
        })
        wait_for(manager, started["id"], {"waiting_otp"})
        manager.submit_otp(started["id"], "123456")
        done = wait_for(manager, started["id"], {"succeeded", "failed"})
        assert done["status"] == "succeeded", done
finally:
    wb_registration.WorkBuddyProtocolClient = original_client
    wb_registration.secrets.choice = original_choice
    wb_registration.run_post_registration_rewards = original_rewards


class SigninResponse(object):
    def __init__(self, payload, status=200):
        self._payload = payload
        self.status_code = status
        self.content = json.dumps(payload).encode("utf-8")
        self.text = self.content.decode("utf-8")

    def json(self):
        return self._payload


class SigninTransport(object):
    def __init__(self):
        self.calls = []

    def get(self, url, **kwargs):
        self.calls.append(("GET", url, kwargs))
        if url.endswith("/signin/phone/login"):
            return SigninResponse({"session_state": "signin-session-1"})
        if url.endswith("/signin/finalize"):
            return SigninResponse({"code": "signin-code-1"})
        raise AssertionError("unexpected signin-v2 GET: %s" % url)

    def post(self, url, **kwargs):
        self.calls.append(("POST", url, kwargs))
        if url.endswith("/signin/phone/sms"):
            return SigninResponse({"status": "ok", "expires_in": 300})
        if url.endswith("/signin/phone/verify"):
            return SigninResponse({
                "status": "ready_to_login",
                "ticket": "signin-ticket-1",
                "nickname": "fixture",
            })
        raise AssertionError("unexpected signin-v2 POST: %s" % url)


signin_transport = SigninTransport()
signin_client = WorkBuddyProtocolClient(
    ProtocolConfig(device_token="tdid-fixture"),
    fingerprint=BrowserFingerprint.generate(seed=150),
    transport=signin_transport,
)
signin_context = LoginContext(
    desktop_state="desktop-state",
    login_session_id="login-session",
    login_owner_id="owner-id",
    ww_device_nonce="device-nonce",
    trace_id="1" * 32,
    login_url="https://www.workbuddy.cn/login/",
    oneid_login_url="https://www.workbuddy.cn/auth/realms/copilot/broker/oneid/login",
)
signin_client.context = signin_context
signin_client._begin_signin_v2("+852 70281878", signin_context, None)
signin_code = signin_client._complete_signin_v2("123456", signin_context)
assert signin_code == "signin-code-1"
assert ProtocolConfig().use_signin_v2 is True
assert signin_client._should_fallback_from_signin_v2(
    RuntimeError("UnsupportedOperation.ChineseMainlandTemplateToGlobalPhone")
)
assert not signin_client._should_fallback_from_signin_v2(
    RuntimeError("invalid_session")
)
sms_call = next(call for call in signin_transport.calls if call[1].endswith("/signin/phone/sms"))
assert sms_call[2]["json_body"] == {
    "session_state": "signin-session-1",
    "phone": "+85270281878",
}
verify_call = next(call for call in signin_transport.calls if call[1].endswith("/signin/phone/verify"))
assert verify_call[2]["json_body"] == {
    "session_state": "signin-session-1",
    "phone": "+85270281878",
    "sms_code": "123456",
    "skip_enterprise": True,
}
assert verify_call[2]["headers"]["X-Device-Token"] == "tdid-fixture"
finalize_call = next(call for call in signin_transport.calls if call[1].endswith("/signin/finalize"))
assert finalize_call[2]["params"] == {
    "ticket": "signin-ticket-1",
    "response_type": "code",
    "session_state": "signin-session-1",
}
assert finalize_call[2]["headers"]["X-Device-Token"] == "tdid-fixture"


legacy_client = WorkBuddyProtocolClient(
    ProtocolConfig(device_token="tdid-legacy", use_signin_v2=False),
    fingerprint=BrowserFingerprint.generate(seed=151),
    transport=signin_transport,
)
legacy_payload = legacy_client._legacy_sms_payload("+852 70281878", "risk-state")
assert legacy_payload["biz_type"] == "login"
assert legacy_payload["device_token"] == "tdid-legacy"
assert legacy_payload["mobile"] == "+852 70281878"
assert json.loads(legacy_payload["spi_extra"])["state"] == "risk-state"

missing_token_client = WorkBuddyProtocolClient(
    ProtocolConfig(device_token="", device_token_error=1001),
    fingerprint=BrowserFingerprint.generate(seed=153),
    transport=signin_transport,
)
missing_token_payload = missing_token_client._legacy_sms_payload(
    "+852 70281878", "risk-state"
)
assert missing_token_payload["device_token_error"] == 1001
assert "device_token" not in missing_token_payload


hybrid_client = WorkBuddyProtocolClient(
    ProtocolConfig(device_token="tdid-hybrid"),
    fingerprint=BrowserFingerprint.generate(seed=154),
    transport=signin_transport,
)
hybrid_client.context = LoginContext(
    desktop_state="desktop-state",
    login_session_id="login-session",
    login_owner_id="owner-id",
    ww_device_nonce="device-nonce",
    trace_id="3" * 32,
    login_url="https://www.workbuddy.cn/login/",
    signin_session_state="signin-session",
    signin_phone="+85270360566",
    oneid_state_token="legacy-state",
)
hybrid_client._complete_signin_v2 = lambda otp, context: (_ for _ in ()).throw(
    RuntimeError("auth-v2 fixture rejected code")
)
hybrid_client._complete_legacy = lambda otp: {"flow": "legacy", "otp": otp}
hybrid_result = hybrid_client.complete("654321")
assert hybrid_result == {"flow": "legacy", "otp": "654321"}
assert hybrid_client.result["steps"]["signin_v2_verify_fallback"]["flow"] == (
    "legacy_oneid_verify"
)


from workbuddy_protocol.tdid import _fingerprint_script
tdid_script = _fingerprint_script(BrowserFingerprint.generate(seed=152))
assert "hardwareConcurrency" in tdid_script
assert "deviceMemory" in tdid_script
assert "WebGLRenderingContext" in tdid_script
assert "webdriver" in tdid_script


assert wb_registration.extract_otp('{"code":"778899"}') == "778899"
assert wb_registration.extract_otp("0|0") == ""
assert wb_registration.extract_otp("ok|112233") == "112233"
assert wb_registration.normalize_hk_phone("70281878") == "+852 70281878"
assert wb_registration.normalize_hk_phone("85270281878") == "+852 70281878"
assert wb_registration.normalize_hk_phone("+85270281878") == "+852 70281878"
assert wb_registration.normalize_hk_phone("+852 70281878") == "+852 70281878"
for invalid_phone in ("", "7028187", "+8613800138000", "852702818780"):
    try:
        wb_registration.normalize_hk_phone(invalid_phone)
        raise AssertionError("invalid Hong Kong phone number was accepted")
    except ValueError:
        pass


class OtpResponse(object):
    def __init__(self, value):
        self.content = value.encode("utf-8")
        self.status_code = 200
        self.url = "http://sms.fixture/getcode"
        self.headers = {"Content-Type": "text/plain"}


class OtpSession(object):
    values = iter(())

    def __init__(self, impersonate=None):
        assert impersonate == "chrome150"

    def get(self, url, timeout=None):
        assert url == "http://sms.fixture/getcode"
        return OtpResponse(next(self.values))

    def close(self):
        pass


# A provider may keep returning the previous SMS after OneID rejects it.  The
# job must wait for a different value instead of immediately submitting the
# same stale code again and triggering rate limiting.
with tempfile.TemporaryDirectory() as root:
    manager = wb_registration.RegistrationManager(
        root, wb_accounts.AccountPool(root)
    )
    manager._set = lambda job, **values: job.update(values)
    OtpSession.values = iter(("1|705098", "1|705098", "1|811223"))
    fake_requests = type("OtpRequests", (), {"Session": OtpSession})
    original_import_module = wb_registration.importlib.import_module

    def otp_import(name, package=None):
        if name == "curl_cffi.requests":
            return fake_requests
        return original_import_module(name, package)

    wb_registration.importlib.import_module = otp_import
    try:
        otp_job = {
            "otpUrl": "http://sms.fixture/getcode",
            "otpTimeout": 2.0,
            "otpInterval": 0.0,
            "cancel": threading.Event(),
            "providerResponses": [],
            "rejectedOtps": {"705098"},
            "lastIgnoredOtp": "",
        }
        fresh_otp = manager._wait_otp(
            otp_job, BrowserFingerprint.generate(seed=18), b"0|0"
        )
    finally:
        wb_registration.importlib.import_module = original_import_module
    assert fresh_otp == "811223"
    assert otp_job["message"] == "忽略已拒绝的旧验证码 705098，继续等待新短信"
    assert otp_job["providerResponses"][0]["ignored"] == "rejected_otp"
    assert otp_job["providerResponses"][0]["otp"] == "705098"


class CaptureSession(object):
    cookies = None

    def __init__(self):
        self.calls = []

    def request(self, method, url, **kwargs):
        self.calls.append((method, url, kwargs))
        return type("Response", (), {
            "status_code": 200,
            "url": url,
            "headers": {},
            "request": None,
            "content": b"{}",
        })()


class CaptureTrace(object):
    def write(self, **kwargs):
        pass

    def write_error(self, **kwargs):
        pass


session = CaptureSession()
transport = ProtocolTransport(
    ProtocolConfig(
        proxy="http://proxy.example:8080",
    ).normalized(),
    BrowserFingerprint.generate(impersonate="chrome150"),
    session=session,
    trace=CaptureTrace(),
)
transport.get("https://www.workbuddy.cn/")
transport.post("https://oauth2.account.tencent.com/v1/auth/sms/code/send", json_body={})
assert "proxies" not in session.calls[0][2]
assert "proxies" not in session.calls[1][2]

original_getaddrinfo = __import__("socket").getaddrinfo
try:
    __import__("socket").getaddrinfo = lambda *args, **kwargs: [
        (2, 1, 6, "", ("43.129.115.155", 443)),
    ]
    connect_transport = ProtocolTransport(
        ProtocolConfig(
            proxy="http://proxy.example:8080",
            proxy_connect_to_hosts=("OAUTH2.ACCOUNT.TENCENT.COM.",),
        ).normalized(),
        BrowserFingerprint.generate(impersonate="chrome150"),
        trace=CaptureTrace(),
    )
    from curl_cffi import CurlOpt
    assert connect_transport.session.curl_options[CurlOpt.CONNECT_TO] == [
        "oauth2.account.tencent.com:443:43.129.115.155:443",
    ]
    assert connect_transport.session.proxies == {
        "http": "http://proxy.example:8080",
        "https": "http://proxy.example:8080",
    }
    connect_transport.session.close()
finally:
    __import__("socket").getaddrinfo = original_getaddrinfo

assert wb_proxy.Handler._is_panel_route("/registration/status") is True
assert wb_proxy.Handler._is_panel_route("/registration/start") is True
assert wb_proxy.Handler._is_panel_route("/registration/devices") is True

html = open(os.path.join(ROOT, "dashboard.html"), encoding="utf-8").read()
for required in (
    'id="btnNavRegistration"',
    'id="pageRegistration"',
    "function startProtocolRegistration(",
    "function submitProtocolOtp(",
    "function runProtocolCaptcha(",
    "captcha_solving:'CapSolver 识别中'",
    "function cancelProtocolRegistration(",
    "'/registration/start'",
    "'/registration/status?id='",
    "'/registration/captcha'",
    "'/registration/devices'",
    "'/registration/devices/save'",
    "'/registration/batch/start'",
    "手机号管理",
    "绑定用户",
    "registrationBoundUserCount",
    "registrationOtpUrlCount",
    "phone-account",
    "function registrationAccountOptions(",
    'class="registration-tabs"',
    'data-registration-page="setup"',
    'data-registration-page="status"',
    'data-registration-page="proxies"',
    'data-registration-page="phones"',
    "function switchRegistrationPage(",
    "switchRegistrationPage('status', true)",
):
    assert required in html, required
assert 'id="registrationDeviceToken"' not in html
assert 'id="registrationProxy"' not in html
assert 'id="registrationProxyPool"' not in html
assert 'id="registrationProxyBatch"' in html
assert 'id="registrationSelectedProxy"' in html
assert 'id="registrationCaptchaBox"' in html
assert "function parseRegistrationProxyBatch(" in html
assert "function saveRegistrationProxyBatch(" in html
assert 'onclick="saveRegistrationProxyBatch(this)"' in html
assert '<strong style="font-size:12px">已保存代理</strong>' not in html
assert 'id="registrationDeviceSection"' in html
assert 'id="registrationDeviceRows"' not in html
assert 'id="registrationPhoneRows"' in html
assert "function startRegistrationDeviceBatch(" in html
assert "function importRegistrationPhones(" in html
assert "function splitRegistrationPhoneImportLine(" in html
assert 'id="registrationBatchLimit"' in html
assert "registrationAvailableCount" in html
assert "注册全部未注册" in html
assert 'id="registrationBatchLog"' in html
assert "function renderRegistrationBatchJobs(" in html
assert "function selectRegistrationBatchJob(" in html
assert "function syncRegistrationBatchLogs(" in html
assert "prepareRegistrationBatchStatus();" in html
assert "每行一个：手机号----接码 URL" in html
assert "parts[2] || ''" not in html
assert 'registrationProxy: data.proxy' not in html
assert "proxy: value('registrationProxy')" not in html
assert "协议模拟设备" in html
assert "每个号码将生成独立模拟设备" in html
assert "registrationDeviceOptions" not in html
assert 'class="phone-device"' not in html


class FakeBatchRegistrations(object):
    def __init__(self):
        self.jobs = {}
        self.started = []
        self.pool = FakeAccountPool()

    def start(self, payload):
        job_id = "job-%d" % (len(self.jobs) + 1)
        job = {
            "id": job_id, "status": "succeeded", "message": "done",
            "account": {"uid": "uid-" + payload["phone"]},
        }
        self.jobs[job_id] = job
        self.started.append(dict(payload))
        return dict(job)

    def snapshot(self, job_id):
        return dict(self.jobs[job_id])

    def cancel(self, job_id):
        self.jobs[job_id]["status"] = "cancelled"
        return dict(self.jobs[job_id])


class FakeAccountPool(object):
    def __init__(self, accounts=None):
        self.accounts = list(accounts or [])
        self._lock = __import__("threading").RLock()

    def get(self, uid):
        with self._lock:
            return next((account for account in self.accounts if account.uid == uid), None)


with tempfile.TemporaryDirectory() as root:
    wb_settings.set_upstream_config(root, {"device_token": "managed-device-token"})
    fake_registrations = FakeBatchRegistrations()
    devices = wb_devices.DeviceManager(root, fake_registrations)
    initial = devices.snapshot()
    assert initial["devices"] == []
    saved = devices.save({
        "devices": [],
        "phones": [
            {"id": "phone-a", "phone": "70281878", "otpUrl": "http://sms/a",
             "deviceId": "", "enabled": True},
            {"id": "phone-b", "phone": "+852 70281879", "otpUrl": "http://sms/b",
             "deviceId": "", "enabled": True},
        ],
    })
    assert [row["phone"] for row in saved["phones"]] == ["70281878", "70281879"]
    assert len(saved["devices"]) == 2
    assert len({row["deviceId"] for row in saved["phones"]}) == 2
    assert all(device["deviceToken"] == "managed-device-token"
               for device in saved["devices"])
    assert all(device["browser"] == "Chrome 150" for device in saved["devices"])
    assert all(device["model"] != "Windows Desktop" for device in saved["devices"])
    assert all(device["fingerprint"]["accept_language"] == "zh-HK,zh;q=0.9,en;q=0.8"
               for device in saved["devices"])
    assert all(device["fingerprint"]["timezone"] == "Asia/Hong_Kong"
               for device in saved["devices"])
    assert len({device["fingerprint"]["device_id"] for device in saved["devices"]}) == 2
    started_batch = devices.start_batch({"phoneIds": ["phone-a", "phone-b"], "concurrency": 2})
    batch_id = started_batch["batch"]["id"]
    deadline = time.monotonic() + 3
    while time.monotonic() < deadline:
        current = devices.snapshot()
        if current["batch"]["id"] == batch_id and current["batch"]["status"] == "completed":
            break
        time.sleep(0.01)
    assert current["batch"]["status"] == "completed", current
    assert current["batch"]["succeeded"] == 2
    assert current["batch"]["failed"] == 0
    assert {row["lastStatus"] for row in current["phones"]} == {"succeeded"}
    assert {row["accountUid"] for row in current["phones"]} == {
        "uid-70281878", "uid-70281879",
    }
    assert len({item["deviceId"] for item in fake_registrations.started}) == 2
    assert len({item["deviceFingerprint"]["device_id"]
                for item in fake_registrations.started}) == 2
    reloaded = wb_devices.DeviceManager(root, fake_registrations).snapshot()
    assert reloaded["phones"][0]["accountUid"].startswith("uid-")
    assert [item["deviceId"] for item in reloaded["phones"]] == [
        item["deviceId"] for item in current["phones"]
    ]
    assert [item["fingerprint"] for item in reloaded["devices"]] == [
        item["fingerprint"] for item in current["devices"]
    ]

with tempfile.TemporaryDirectory() as root:
    wb_settings.set_upstream_config(root, {"device_token": "managed-device-token"})
    fake_registrations = FakeBatchRegistrations()
    devices = wb_devices.DeviceManager(root, fake_registrations)
    devices.save({
        "devices": [],
        "phones": [
            {"id": "done", "phone": "70281870", "otpUrl": "http://sms/done",
             "deviceId": "", "enabled": True,
             "lastStatus": "succeeded"},
            {"id": "one", "phone": "70281871", "otpUrl": "http://sms/one",
             "deviceId": "", "enabled": True},
            {"id": "two", "phone": "70281872", "otpUrl": "http://sms/two",
             "deviceId": "", "enabled": True},
            {"id": "incomplete", "phone": "70281873", "otpUrl": "",
             "deviceId": "", "enabled": True},
        ],
    })
    batch = devices.start_batch({"limit": 1, "concurrency": 2})["batch"]
    assert batch["total"] == 1
    assert batch["skippedRegistered"] == 1
    assert batch["requestedLimit"] == 1
    deadline = time.monotonic() + 3
    while time.monotonic() < deadline:
        current = devices.snapshot()
        if current["batch"]["status"] == "completed":
            break
        time.sleep(0.01)
    assert len(fake_registrations.started) == 1
    assert fake_registrations.started[0]["phone"] == "70281871"
    rows = {row["id"]: row for row in current["phones"]}
    assert rows["done"]["lastStatus"] == "succeeded"
    assert rows["two"]["lastStatus"] == ""

with tempfile.TemporaryDirectory() as root:
    wb_settings.set_upstream_config(root, {"device_token": "migration-device-token"})
    account = type("FakeAccount", (), {
        "uid": "existing-user", "nickname": "+852 70281878", "realm": "cn",
        "source": "protocol-registration-callback", "device_id": "device-default",
        "device_name": "默认设备", "device_model": "Windows Desktop",
    })()
    fake_registrations = FakeBatchRegistrations()
    fake_registrations.pool.accounts.append(account)
    with open(os.path.join(root, "registration-devices.json"), "w", encoding="utf-8") as handle:
        json.dump({
            "version": 1,
            "phones": [{
                "id": "phone-old", "phone": "70281878", "otpUrl": "http://sms/old",
                "deviceId": "device-default", "enabled": True,
            }],
        }, handle)
    devices = wb_devices.DeviceManager(root, fake_registrations)
    migrated = devices.snapshot()
    assert len(migrated["phones"]) == 1
    assert migrated["phones"][0]["accountUid"] == "existing-user"
    assert migrated["phones"][0]["deviceId"] != "device-default"
    assert migrated["devices"][0]["model"] != "Windows Desktop"
    assert migrated["devices"][0]["fingerprint"]["major_version"] == "150"
    assert migrated["devices"][0]["fingerprint"]["timezone"] == "Asia/Hong_Kong"
    assert migrated["accounts"][0]["uid"] == "existing-user"
    assert wb_devices.DeviceManager(root, fake_registrations).snapshot()["phones"] == migrated["phones"]
    migrated["phones"][0]["accountUid"] = ""
    unbound = devices.save({"devices": migrated["devices"], "phones": migrated["phones"]})
    assert unbound["phones"][0]["accountUid"] == ""

captcha_source = open(os.path.join(ROOT, "wb_captcha.py"), encoding="utf-8").read()
for required in (
    '"type": "VisionEngine"',
    '"module": "slider_1"',
    'Chrome/150.0.0.0',
    'class ConnectToProxy(object):',
    'def edge_match_distance(',
):
    assert required in captcha_source, required

print("protocol registration assertions passed")
