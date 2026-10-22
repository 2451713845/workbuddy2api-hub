"""Background WorkBuddy protocol registration jobs for the web dashboard."""

import base64
import importlib
import json
import os
import re
import secrets
import threading
import time
import uuid

import wb_accounts
import wb_settings

WorkBuddyProtocolClient = importlib.import_module(
    "workbuddy_protocol.client").WorkBuddyProtocolClient


def run_post_registration_rewards(account):
    """Run the same reward pipeline used by the daily scheduler."""
    return importlib.import_module("wb_tasks").run_all_rewards(
        account, trigger="registration", gap=1.0)
ProtocolConfig = importlib.import_module(
    "workbuddy_protocol.config").ProtocolConfig
BrowserFingerprint = importlib.import_module(
    "workbuddy_protocol.fingerprint").BrowserFingerprint
acquire_device_identity = importlib.import_module(
    "workbuddy_protocol.tdid").acquire_device_identity


TERMINAL_STATES = frozenset(("succeeded", "failed", "cancelled"))
HK_DIAL_CODE = "+852"


class RegistrationCancelled(RuntimeError):
    pass


def normalize_hk_phone(value):
    """Return the exact OneID representation for an 8-digit Hong Kong number."""
    compact = re.sub(r"[\s()\-]", "", str(value or "").strip())
    if compact.startswith(HK_DIAL_CODE):
        local = compact[len(HK_DIAL_CODE):]
    elif compact.startswith("852") and len(compact) > 8:
        local = compact[3:]
    else:
        local = compact
    if not re.fullmatch(r"\d{8}", local):
        raise ValueError("Hong Kong phone number must contain exactly 8 digits")
    return "%s %s" % (HK_DIAL_CODE, local)


def extract_otp(raw):
    value = str(raw or "").strip()
    if not value or value == "0|0":
        return ""
    try:
        parsed = json.loads(value)
    except (TypeError, ValueError):
        parsed = None
    if isinstance(parsed, dict):
        for key in ("code", "sms_code", "smsCode", "verify_code", "verification_code"):
            candidate = str(parsed.get(key, "")).strip()
            if re.fullmatch(r"\d{4,8}", candidate) and candidate != "0":
                return candidate
    for part in reversed(value.split("|")):
        candidate = part.strip()
        if re.fullmatch(r"\d{4,8}", candidate) and candidate != "0":
            return candidate
    matches = re.findall(r"(?<!\d)(\d{4,8})(?!\d)", value)
    return matches[-1] if matches else ""


def decode_provider_body(content):
    for encoding in ("utf-8", "gb18030"):
        try:
            return content.decode(encoding), encoding
        except UnicodeDecodeError:
            pass
    return content.decode("utf-8", errors="replace"), "utf-8-replace"


class RegistrationManager(object):
    def __init__(self, accounts_dir, pool, log=None, validate_account=None,
                 captcha_solver=None):
        self.accounts_dir = os.path.abspath(accounts_dir)
        self.jobs_dir = os.path.join(self.accounts_dir, "registration-jobs")
        self.pool = pool
        self.log = log or (lambda message, **kwargs: None)
        self.validate_account = validate_account
        self.captcha_solver = captcha_solver
        if self.captcha_solver is None:
            capsolver_key = str(os.environ.get("CAPSOLVER_API_KEY") or "").strip()
            if capsolver_key:
                solver_class = importlib.import_module(
                    "wb_captcha").TencentCaptchaSolver
                self.captcha_solver = solver_class(
                    capsolver_key, log=self.log,
                    timeout=float(os.environ.get("CAPSOLVER_TIMEOUT") or 180),
                )
        self._jobs = {}
        self._lock = threading.RLock()
        os.makedirs(self.jobs_dir, exist_ok=True)

    def _pick_proxy_slot(self):
        """Randomly choose one enabled slot shared with the account pool."""
        slots = [
            entry for entry in wb_settings.proxy_slots(self.accounts_dir)
            if entry.get("enabled") and entry.get("url")
        ]
        if not slots:
            return None
        return secrets.choice(slots)

    @staticmethod
    def _validation_is_inconclusive(validation):
        """Return True when the probe failed before the upstream judged the token."""
        if not isinstance(validation, dict) or validation.get("ok"):
            return False
        if validation.get("restricted"):
            return False
        status = validation.get("status")
        if status not in (None, "", 0):
            return False
        error = str(validation.get("error") or "").lower()
        return bool(
            validation.get("network")
            or "urlerror" in error
            or "tunnel connection failed" in error
            or "service_unavailable" in error
            or "timed out" in error
            or "timeout" in error
            or "connection reset" in error
            or "connection refused" in error
            or "temporary failure" in error
        )

    def start(self, payload):
        phone = normalize_hk_phone(payload.get("phone"))
        otp_url = str(payload.get("otpUrl") or "").strip()
        device_token = (str(payload.get("deviceToken") or "").strip()
                        or wb_accounts.resolve_device_token(self.accounts_dir))
        if not device_token:
            raise ValueError("no saved deviceToken was found")
        proxy_slot = self._pick_proxy_slot()
        if proxy_slot is None:
            raise ValueError("no enabled proxy is configured in the proxy pool")
        job_id = uuid.uuid4().hex
        root = os.path.join(self.jobs_dir, job_id)
        os.makedirs(root, exist_ok=False)
        job = {
            "id": job_id,
            "phone": phone,
            "otpUrl": otp_url,
            "proxy": (proxy_slot or {}).get("url", ""),
            "proxySlot": (proxy_slot or {}).get("id", ""),
            "proxyLabel": ((proxy_slot or {}).get("name")
                           or (proxy_slot or {}).get("id", "")),
            "deviceToken": device_token,
            "deviceId": str(payload.get("deviceId") or "").strip(),
            "deviceName": str(payload.get("deviceName") or "").strip(),
            "deviceModel": str(payload.get("deviceModel") or "").strip(),
            "deviceOs": str(payload.get("deviceOs") or "").strip(),
            "deviceFingerprint": (
                dict(payload.get("deviceFingerprint"))
                if isinstance(payload.get("deviceFingerprint"), dict) else {}
            ),
            "deviceIdentity": {"source": "configured", "tokenRefreshed": False},
            "status": "queued",
            "phase": "queued",
            "message": "任务已创建",
            "createdAt": time.time(),
            "updatedAt": time.time(),
            "finishedAt": 0,
            "account": None,
            "failure": None,
            "result": None,
            "tracePath": os.path.join(root, "raw-http-trace.jsonl"),
            "resultPath": os.path.join(root, "result.json"),
            "otpTimeout": max(30.0, min(float(payload.get("otpTimeout") or 180), 900.0)),
            "otpInterval": max(1.0, min(float(payload.get("otpInterval") or 3), 30.0)),
            "cancel": threading.Event(),
            "otpCondition": threading.Condition(),
            "otpQueue": [],
            "captchaCondition": threading.Condition(),
            "captchaQueue": [],
            "captcha": None,
            "captchaSolver": None,
            "captchaTimeout": max(
                30.0, min(float(payload.get("captchaTimeout") or 300), 900.0)
            ),
            "client": None,
            "providerResponses": [],
            "rejectedOtps": set(),
            "lastIgnoredOtp": "",
        }
        with self._lock:
            active = [j for j in self._jobs.values() if j["status"] not in TERMINAL_STATES]
            if len(active) >= 2:
                raise RuntimeError("two registration jobs are already running")
            self._jobs[job_id] = job
            self._trim_locked()
            self._persist_job_locked(job)
        thread = threading.Thread(
            target=self._run, args=(job,), name="wb-register-" + job_id[:8], daemon=True
        )
        job["thread"] = thread
        thread.start()
        return self.snapshot(job_id)

    def submit_captcha(self, job_id, payload):
        job = self._get(job_id)
        verification = {
            "ticket": str(payload.get("ticket") or "").strip(),
            "randStr": str(payload.get("randStr") or "").strip(),
            "cloudType": str(payload.get("cloudType") or "").strip(),
        }
        if not verification["ticket"] or not verification["randStr"]:
            raise ValueError("captcha ticket and randStr are required")
        if verification["cloudType"] not in ("teg", "tencent"):
            raise ValueError("captcha cloudType must be teg or tencent")
        with job["captchaCondition"]:
            job["captchaQueue"].append(verification)
            job["captchaCondition"].notify_all()
        self._set(job, status="running", phase="captcha_submitted",
                  message="安全验证已提交")
        return self.snapshot(job_id)

    def submit_otp(self, job_id, code):
        job = self._get(job_id)
        code = str(code or "").strip()
        if not re.fullmatch(r"\d{4,8}", code):
            raise ValueError("OTP must contain 4-8 digits")
        with job["otpCondition"]:
            job["otpQueue"].append(code)
            job["otpCondition"].notify_all()
        self._set(job, message="验证码已提交")
        return self.snapshot(job_id)

    def cancel(self, job_id):
        job = self._get(job_id)
        job["cancel"].set()
        with job["otpCondition"]:
            job["otpCondition"].notify_all()
        with job["captchaCondition"]:
            job["captchaCondition"].notify_all()
        if job["status"] not in TERMINAL_STATES:
            self._set(job, message="正在取消")
        return self.snapshot(job_id)

    def recent(self):
        with self._lock:
            jobs = {
                job_id: self._public(job, include_result=False)
                for job_id, job in self._jobs.items()
            }
        try:
            disk_ids = os.listdir(self.jobs_dir)
        except OSError:
            disk_ids = []
        for job_id in disk_ids:
            if job_id in jobs or not re.fullmatch(r"[0-9a-f]{32}", job_id):
                continue
            try:
                jobs[job_id] = self._disk_snapshot(
                    job_id, include_events=False, include_result=False
                )
            except KeyError:
                continue
        ordered = sorted(
            jobs.values(), key=lambda item: item.get("createdAt") or 0,
            reverse=True,
        )
        return ordered[:20]

    def snapshot(self, job_id, after=0):
        try:
            job = self._get(job_id)
        except KeyError:
            return self._disk_snapshot(job_id, after)
        data = self._public(job, include_result=True)
        data["events"] = self._trace_events(job["tracePath"], after)
        return data

    def _get(self, job_id):
        with self._lock:
            job = self._jobs.get(str(job_id or ""))
        if job is None:
            raise KeyError("registration job not found")
        return job

    def _set(self, job, **values):
        with self._lock:
            job.update(values)
            job["updatedAt"] = time.time()
            self._persist_job_locked(job)

    def _persist_job_locked(self, job):
        """Persist public job state so completed traces survive a restart."""
        path = os.path.join(os.path.dirname(job["resultPath"]), "job.json")
        tmp = path + ".tmp.%s.%s" % (os.getpid(), threading.get_ident())
        try:
            data = self._public(job, include_result=False)
            with open(tmp, "w", encoding="utf-8", newline="\n") as handle:
                json.dump(data, handle, ensure_ascii=False, indent=2)
                handle.write("\n")
            os.replace(tmp, path)
        except OSError:
            try:
                if os.path.exists(tmp):
                    os.unlink(tmp)
            except OSError:
                pass

    def _disk_snapshot(
        self, job_id, after=0, *, include_events=True, include_result=True
    ):
        job_id = str(job_id or "").strip().lower()
        if not re.fullmatch(r"[0-9a-f]{32}", job_id):
            raise KeyError("registration job not found")
        root = os.path.join(self.jobs_dir, job_id)
        trace_path = os.path.join(root, "raw-http-trace.jsonl")
        result_path = os.path.join(root, "result.json")
        state_path = os.path.join(root, "job.json")
        if not os.path.isfile(trace_path) and not os.path.isfile(result_path):
            raise KeyError("registration job not found")

        state = {}
        result = {}
        try:
            with open(state_path, encoding="utf-8") as handle:
                loaded = json.load(handle)
                if isinstance(loaded, dict):
                    state = loaded
        except (OSError, ValueError):
            pass
        try:
            with open(result_path, encoding="utf-8") as handle:
                loaded = json.load(handle)
                if isinstance(loaded, dict):
                    result = loaded
        except (OSError, ValueError):
            pass

        failure = state.get("failure") or result.get("failure")
        validation = result.get("account_validation") or {}
        status = state.get("status") or ("failed" if failure else "succeeded")
        phase = state.get("phase") or ("failed" if failure else "completed")
        message = state.get("message") or (
            str((failure or {}).get("message") or "注册失败")
            if failure else "注册完成，历史日志已从磁盘恢复"
        )
        account = state.get("account")
        uid = str((validation or {}).get("uid") or "").strip()
        if not account and uid:
            saved = self.pool.get(uid)
            account = saved.to_dict() if saved is not None else {
                "uid": uid,
                "nickname": str((validation or {}).get("nickname") or uid),
            }
        try:
            stamp = os.path.getmtime(result_path if os.path.isfile(result_path) else trace_path)
        except OSError:
            stamp = 0
        data = {
            "id": job_id,
            "phone": state.get("phone") or "",
            "otpUrl": state.get("otpUrl") or str((result.get("otp_provider") or {}).get("url") or ""),
            "proxy": state.get("proxy") or "",
            "proxySlot": state.get("proxySlot") or "",
            "proxyLabel": state.get("proxyLabel") or "",
            "deviceToken": state.get("deviceToken") or "",
            "deviceId": state.get("deviceId") or "",
            "deviceName": state.get("deviceName") or "",
            "deviceModel": state.get("deviceModel") or "",
            "deviceOs": state.get("deviceOs") or "",
            "deviceIdentity": state.get("deviceIdentity") or {},
            "status": status,
            "phase": phase,
            "captcha": state.get("captcha"),
            "captchaSolver": state.get("captchaSolver"),
            "message": message,
            "createdAt": state.get("createdAt") or stamp,
            "updatedAt": state.get("updatedAt") or stamp,
            "finishedAt": state.get("finishedAt") or stamp,
            "account": account,
            "failure": failure,
            "fingerprint": "chrome150",
            "traceFile": trace_path,
            "resultFile": result_path,
        }
        if include_result:
            data["result"] = result or None
            data["otpProvider"] = result.get("otp_provider") or {
                "url": state.get("otpUrl") or "", "responses": []
            }
        if include_events:
            data["events"] = self._trace_events(trace_path, after)
        return data

    def _trim_locked(self):
        terminal = sorted(
            (j for j in self._jobs.values() if j["status"] in TERMINAL_STATES),
            key=lambda item: item["createdAt"], reverse=True,
        )
        for old in terminal[20:]:
            self._jobs.pop(old["id"], None)

    @staticmethod
    def _public(job, include_result):
        keys = (
            "id", "phone", "otpUrl", "proxy", "proxySlot", "proxyLabel",
            "deviceToken", "deviceId", "deviceName", "deviceModel", "deviceOs",
            "deviceFingerprint",
            "deviceIdentity",
            "status", "phase", "captcha", "captchaSolver",
            "message", "createdAt", "updatedAt", "finishedAt", "account", "failure",
        )
        out = {key: job.get(key) for key in keys}
        out["fingerprint"] = "chrome150"
        out["traceFile"] = job["tracePath"]
        out["resultFile"] = job["resultPath"]
        if include_result:
            client = job.get("client")
            live = getattr(client, "result", None)
            out["result"] = job.get("result") or live
            out["otpProvider"] = {
                "url": job.get("otpUrl") or "",
                "responses": list(job.get("providerResponses") or []),
            }
        return out

    @staticmethod
    def _trace_events(path, after):
        events = []
        try:
            with open(path, encoding="utf-8") as handle:
                for line in handle:
                    try:
                        event = json.loads(line)
                    except ValueError:
                        continue
                    if int(event.get("sequence") or 0) > int(after or 0):
                        events.append(event)
        except OSError:
            pass
        return events

    def _check_cancel(self, job):
        if job["cancel"].is_set():
            raise RegistrationCancelled("registration cancelled")

    def _provider_record(self, response, phase):
        raw_bytes = bytes(response.content)
        body, encoding = decode_provider_body(raw_bytes)
        return {
            "phase": phase,
            "time": time.time(),
            "status": int(response.status_code),
            "url": str(response.url),
            "headers": dict(response.headers),
            "body": body,
            "bodyEncoding": encoding,
            "bodyBase64": base64.b64encode(raw_bytes).decode("ascii"),
        }, raw_bytes, body

    def _wait_otp(self, job, fingerprint, baseline):
        self._set(job, status="waiting_otp", phase="waiting_otp", message="等待短信验证码")
        deadline = time.monotonic() + job["otpTimeout"]
        returned = set()
        rejected = job.setdefault("rejectedOtps", set())

        def ignored(code):
            if code not in rejected:
                return False
            if job.get("lastIgnoredOtp") != code:
                job["lastIgnoredOtp"] = code
                self._set(
                    job,
                    status="waiting_otp",
                    phase="waiting_otp",
                    message="忽略已拒绝的旧验证码 %s，继续等待新短信" % code,
                )
            return True

        if job["otpUrl"]:
            requests = importlib.import_module("curl_cffi.requests")
            provider = requests.Session(impersonate=fingerprint.impersonate)
            try:
                while time.monotonic() < deadline:
                    self._check_cancel(job)
                    response = provider.get(job["otpUrl"], timeout=30)
                    record, raw_bytes, raw = self._provider_record(response, "poll")
                    job["providerResponses"].append(record)
                    otp = extract_otp(raw)
                    if otp and ignored(otp):
                        record["ignored"] = "rejected_otp"
                        record["otp"] = otp
                        job["cancel"].wait(job["otpInterval"])
                        continue
                    if otp and raw_bytes != baseline and otp not in returned:
                        returned.add(otp)
                        return otp
                    job["cancel"].wait(job["otpInterval"])
            finally:
                provider.close()
        else:
            with job["otpCondition"]:
                while time.monotonic() < deadline:
                    self._check_cancel(job)
                    if job["otpQueue"]:
                        otp = job["otpQueue"].pop(0)
                        if ignored(otp):
                            continue
                        return otp
                    remaining = max(0.0, deadline - time.monotonic())
                    job["otpCondition"].wait(min(1.0, remaining))
        raise RuntimeError("OTP polling timed out after %s seconds" % int(job["otpTimeout"]))

    def _wait_captcha(self, job, options, state_token):
        challenge = {
            "options": [
                {
                    "appId": str(item.get("appId") or ""),
                    "cloudType": str(item.get("cloudType") or ""),
                }
                for item in options
                if isinstance(item, dict) and item.get("appId")
                and item.get("cloudType") in ("teg", "tencent")
            ],
            "stateToken": str(state_token or ""),
        }
        if not challenge["options"]:
            raise RuntimeError("OneID returned an empty captcha configuration")
        solver = self.captcha_solver
        if solver and getattr(solver, "enabled", True):
            self._set(
                job,
                status="captcha_solving",
                phase="captcha_solving",
                message="CapSolver 正在识别腾讯安全验证",
                captcha=challenge,
                captchaSolver={"provider": "CapSolver", "status": "running"},
            )

            def update_solver(stage, attempt):
                if stage == "dragging":
                    message = "CapSolver 已定位拼图，正在拖动验证"
                else:
                    message = "CapSolver 正在识别腾讯拼图（第 %d 次）" % attempt
                self._set(
                    job,
                    status="captcha_solving",
                    phase="captcha_solving",
                    message=message,
                )

            try:
                verification, details = solver.solve(
                    challenge["options"],
                    proxy=job["proxy"],
                    status_callback=update_solver,
                    cancelled=job["cancel"].is_set,
                )
                self._set(
                    job,
                    status="running",
                    phase="sending_sms",
                    message="CapSolver 验证完成，重新发送短信",
                    captcha=None,
                    captchaSolver=dict(details, status="succeeded"),
                )
                return verification
            except Exception as exc:
                self._set(
                    job,
                    status="waiting_captcha",
                    phase="waiting_captcha",
                    message="CapSolver 自动验证失败，可点击开始验证：%s" % exc,
                    captcha=challenge,
                    captchaSolver={
                        "provider": "CapSolver",
                        "status": "failed",
                        "error": str(exc),
                    },
                )
                self.log("CapSolver automatic captcha failed: %s" % exc,
                         tag="accounts")
        else:
            self._set(job, status="waiting_captcha", phase="waiting_captcha",
                      message="等待完成腾讯安全验证", captcha=challenge)
        deadline = time.monotonic() + job["captchaTimeout"]
        with job["captchaCondition"]:
            while time.monotonic() < deadline:
                self._check_cancel(job)
                if job["captchaQueue"]:
                    verification = job["captchaQueue"].pop(0)
                    self._set(job, status="running", phase="sending_sms",
                              message="安全验证已完成，重新发送短信", captcha=None)
                    return verification
                remaining = max(0.0, deadline - time.monotonic())
                job["captchaCondition"].wait(min(1.0, remaining))
        raise RuntimeError(
            "captcha verification timed out after %s seconds"
            % int(job["captchaTimeout"])
        )

    def _build_account(self, result, phone="", proxy_slot="", proxy="",
                       device_token="", device_id="", device_name="",
                       device_model="", device_os=""):
        token_data = ((result.get("steps") or {}).get("desktop_token_poll") or {}).get("token") or {}
        profile_payload = (result.get("steps") or {}).get("desktop_account_poll") or {}
        profile = profile_payload.get("data") or {}
        token = str(token_data.get("accessToken") or "")
        if not token:
            raise RuntimeError("protocol result has no desktop access token")
        account = wb_accounts.Account({
            "uid": profile.get("uid") or wb_accounts.jwt_uid(token),
            "nickname": (
                str(phone or "").strip()
                or profile.get("nickname")
                or profile.get("phoneNumber")
                or ""
            ),
            "domain": token_data.get("domain") or "www.workbuddy.cn",
            "realm": "cn",
            "platform": "CLI",
            "product": "workbuddy",
            "accessToken": token,
            "refreshToken": token_data.get("refreshToken") or "",
            "expiresAt": wb_accounts.normalize_epoch(token_data.get("expiresAt")) or wb_accounts.jwt_exp(token),
            "source": "protocol-registration",
            "proxySlot": proxy_slot,
            "deviceToken": device_token,
            "deviceId": device_id,
            "deviceName": device_name,
            "deviceModel": device_model,
            "deviceOs": device_os,
            "enabled": True,
        })
        # Account.save() records the file path but does not backfill
        # accounts_dir. Set it before the first live probe so the just-added
        # account can resolve the persisted X-Device-Token without a restart.
        account.accounts_dir = self.accounts_dir
        # The account is not in AccountPool yet, so apply_proxy_slots() cannot
        # resolve its runtime route before the validation request. Keep the
        # persisted source of truth as proxySlot and prime only the live value.
        account.proxy = proxy
        return account

    def _run(self, job):
        client = None
        try:
            saved_fingerprint = job.get("deviceFingerprint") or {}
            try:
                fingerprint = BrowserFingerprint(**saved_fingerprint)
                if fingerprint.impersonate != "chrome150":
                    raise ValueError("unexpected browser profile")
            except (TypeError, ValueError):
                fingerprint = BrowserFingerprint.generate(
                    impersonate="chrome150",
                    language="zh-HK",
                    timezone="Asia/Hong_Kong",
                )
            self._set(
                job,
                status="running",
                phase="fingerprint",
                message="加载手机号专属 Chrome 150 模拟指纹",
                deviceFingerprint=fingerprint.to_dict(),
            )
            config = ProtocolConfig(
                proxy=job["proxy"],
                # The configured residential provider accepts WorkBuddy but
                # rejects CONNECT to the Tencent hostname with provider status
                # 803. Keep the URL/SNI intact while asking that same proxy to
                # open its tunnel to Tencent's resolved IPv4 address instead.
                proxy_connect_to_hosts=(
                    "oauth2.account.tencent.com",
                    "api.account.tencent.com",
                ),
                device_token=job["deviceToken"],
                language="zh-HK",
                trace_path=job["tracePath"],
                output_path=job["resultPath"],
            ).normalized()
            identity = {"source": "configured", "tokenRefreshed": False,
                        "cookies": {}}
            try:
                self._set(job, phase="device_identity", message="采集手机号专属 TDID 设备令牌")
                identity = acquire_device_identity(job["proxy"], fingerprint,
                                                    timeout=min(config.timeout * 3, 90.0))
                if identity.get("token"):
                    job["deviceToken"] = str(identity["token"])
                    config.device_token = job["deviceToken"]
                    config.device_cookies = dict(identity.get("cookies") or {})
                    identity["tokenRefreshed"] = True
                    self._set(job, deviceToken=job["deviceToken"],
                              deviceIdentity={
                                  "source": identity.get("source"),
                                  "channel": identity.get("channel"),
                                  "tokenRefreshed": True,
                                  "cookieNames": sorted(config.device_cookies),
                              },
                              message="TDID 设备令牌已生成，继续建立风险上下文")
            except Exception as exc:
                identity = {
                    "source": "configured_fallback",
                    "tokenRefreshed": False,
                    "error": str(exc),
                    "cookies": {},
                }
                self._set(job, deviceIdentity={k: v for k, v in identity.items() if k != "cookies"},
                          message="TDID 采集失败，使用已保存设备令牌继续")
            config.device_cookies = dict(identity.get("cookies") or {})
            client_identity = {k: v for k, v in identity.items() if k != "cookies"}
            client = WorkBuddyProtocolClient(config, fingerprint=fingerprint)
            client.result["device_identity"] = client_identity
            job["client"] = client
            baseline = b""
            if job["otpUrl"]:
                requests = importlib.import_module("curl_cffi.requests")
                self._set(job, phase="otp_baseline", message="读取接码接口基线")
                response = requests.get(
                    job["otpUrl"], impersonate=fingerprint.impersonate, timeout=config.timeout
                )
                record, baseline, _ = self._provider_record(response, "baseline")
                job["providerResponses"].append(record)
            self._check_cancel(job)
            self._set(job, phase="sending_sms", message="建立桌面登录状态并发送短信")
            sms_response = client.begin(
                job["phone"],
                captcha_callback=lambda options, state_token: self._wait_captcha(
                    job, options, state_token
                ),
            )
            while True:
                otp = self._wait_otp(job, fingerprint, baseline)
                self._check_cancel(job)
                self._set(job, status="running", phase="completing", message="验证码已取得，执行注册、登录与桌面回调")
                try:
                    result = client.complete(otp)
                    break
                except RuntimeError as exc:
                    if "E0010028" not in str(exc):
                        raise
                    job["rejectedOtps"].add(otp)
                    client.result["steps"].setdefault("rejected_otps", []).append(
                        {"otp": otp, "error": str(exc)}
                    )
                    self._set(
                        job,
                        phase="waiting_otp",
                        message="验证码 %s 已被拒绝，等待接码接口返回新验证码" % otp,
                    )
            result["otp_provider"] = {
                "url": job["otpUrl"], "responses": list(job["providerResponses"]),
            }
            with open(job["resultPath"], "w", encoding="utf-8") as handle:
                handle.write(json.dumps(result, ensure_ascii=False, indent=2) + "\n")
            self._check_cancel(job)
            wb_settings.set_upstream_config(
                self.accounts_dir, {"device_token": job["deviceToken"]}
            )
            account = self._build_account(
                result,
                phone=job["phone"],
                proxy_slot=job["proxySlot"],
                proxy=job["proxy"],
                device_token=job["deviceToken"],
                device_id=job["deviceId"],
                device_name=job["deviceName"],
                device_model=job["deviceModel"],
                device_os=job["deviceOs"],
            )
            validation = None
            validation_warning = ""
            if self.validate_account is not None:
                self._set(job, phase="validating_account", message="凭证已取得，验证真实模型请求")
                validation = self.validate_account(account)
                result["account_validation"] = validation
                if not validation.get("ok") and self._validation_is_inconclusive(validation):
                    validation_warning = str(
                        validation.get("error") or "模型验证链路暂时不可用"
                    )
                    result["account_validation_deferred"] = True
                    result["account_validation_warning"] = validation_warning
                elif not validation.get("ok"):
                    raise RuntimeError(
                        "account validation failed: %s" %
                        (validation.get("error") or validation.get("status") or "unknown error")
                    )
                with open(job["resultPath"], "w", encoding="utf-8") as handle:
                    handle.write(json.dumps(result, ensure_ascii=False, indent=2) + "\n")
            account = self.pool.add(account)
            self._set(
                job,
                status="running",
                phase="completing_rewards",
                message="账号已入池，执行签到、成长任务和全部积分领取",
                account=account.to_dict(),
            )
            try:
                rewards = run_post_registration_rewards(account)
            except Exception as exc:
                rewards = {
                    "ok": False,
                    "msg": "注册后任务流水异常，等待每日调度重试",
                    "failures": [str(exc)],
                }
            result["post_registration_rewards"] = rewards
            with open(job["resultPath"], "w", encoding="utf-8") as handle:
                handle.write(json.dumps(result, ensure_ascii=False, indent=2) + "\n")
            self._set(
                job,
                status="succeeded",
                phase="completed",
                message=(
                    "注册完成，账号已加入账号列表；模型验证因代理连接失败待重试"
                    if validation_warning else "注册完成，账号已加入账号列表"
                ) + "；" + str(rewards.get("msg") or "任务流水已执行"),
                result=result,
                account=account.to_dict(),
                finishedAt=time.time(),
            )
            self.log("protocol registration succeeded for account %s" % account.uid[:8], tag="accounts")
        except RegistrationCancelled as exc:
            self._set(
                job, status="cancelled", phase="cancelled", message=str(exc),
                result=getattr(client, "result", None), finishedAt=time.time(),
            )
        except BaseException as exc:
            result = getattr(client, "result", {}) or {}
            result["otp_provider"] = {
                "url": job["otpUrl"], "responses": list(job["providerResponses"]),
            }
            result["failure"] = {"type": type(exc).__name__, "message": str(exc)}
            try:
                with open(job["resultPath"], "w", encoding="utf-8") as handle:
                    handle.write(json.dumps(result, ensure_ascii=False, indent=2) + "\n")
            except OSError:
                pass
            self._set(
                job,
                status="failed",
                phase="failed",
                message=str(exc),
                result=result,
                failure=result["failure"],
                finishedAt=time.time(),
            )
            self.log("protocol registration failed: %s" % exc, level="WARN", tag="accounts")
