from __future__ import annotations

from dataclasses import asdict, dataclass
import json
import secrets
import time
from typing import Any, Callable, Optional
from urllib.parse import parse_qs, urlencode, urljoin, urlparse, urlunparse
import uuid

from .config import ProtocolConfig
from .fingerprint import BrowserFingerprint
from .html import extract_oneid_login_url
from .transport import ProtocolTransport


GRAY_FEATURES = (
    "lamp,lamp_signin_wechat,lamp_signin_qq,lamp_signin_phone,"
    "lamp_signin_email,lamp_signin_sso,lamp_signin_wecom,"
    "lamp_signin_offiaccount"
)


@dataclass
class LoginContext:
    desktop_state: str
    login_session_id: str
    login_owner_id: str
    ww_device_nonce: str
    trace_id: str
    login_url: str
    risk_state: str = ""
    oneid_login_url: str = ""
    oneid_state_token: str = ""
    signin_session_state: str = ""
    signin_phone: str = ""


def _with_query(url: str, **values: str) -> str:
    parsed = urlparse(url)
    query = parse_qs(parsed.query, keep_blank_values=True)
    for key, value in values.items():
        query[key] = [value]
    return urlunparse(parsed._replace(query=urlencode(query, doseq=True)))


class WorkBuddyProtocolClient:
    def __init__(
        self,
        config: Optional[ProtocolConfig] = None,
        *,
        fingerprint: Optional[BrowserFingerprint] = None,
        transport: Optional[ProtocolTransport] = None,
    ) -> None:
        self.config = (config or ProtocolConfig()).normalized()
        self.fingerprint = fingerprint or BrowserFingerprint.generate(
            language=self.config.language
        )
        self.transport = transport or ProtocolTransport(self.config, self.fingerprint)
        self.context: Optional[LoginContext] = None
        self.result: dict[str, Any] = {
            "fingerprint": self.fingerprint.to_dict(),
            "steps": {},
        }

    def _url(self, path: str) -> str:
        return urljoin(self.config.base_url + "/", path.lstrip("/"))

    def _oneid_url(self, path: str) -> str:
        return urljoin(self.config.oneid_url + "/", path.lstrip("/"))

    def _oneid_api_url(self, path: str) -> str:
        return urljoin(self.config.oneid_api_url + "/", path.lstrip("/"))

    def _traceparent(self, trace_id: Optional[str] = None) -> str:
        if trace_id is None:
            trace_id = self.context.trace_id if self.context else secrets.token_hex(16)
        return f"00-{trace_id}-{secrets.token_hex(8)}-01"

    @staticmethod
    def _text(response: Any) -> str:
        value = getattr(response, "text", None)
        if isinstance(value, str):
            return value
        return bytes(response.content).decode("utf-8", errors="replace")

    def _json(self, response: Any, label: str) -> dict[str, Any]:
        if not 200 <= int(response.status_code) < 300:
            raise RuntimeError(
                f"{label} returned HTTP {response.status_code}: {self._text(response)}"
            )
        try:
            value = response.json()
        except Exception as exc:
            raise RuntimeError(f"{label} returned invalid JSON: {self._text(response)}") from exc
        if not isinstance(value, dict):
            raise RuntimeError(f"{label} returned a non-object JSON value: {value!r}")
        return value

    def _api_json(
        self,
        response: Any,
        label: str,
        *,
        accepted_codes: tuple[int, ...] = (0,),
    ) -> dict[str, Any]:
        value = self._json(response, label)
        if value.get("code") not in accepted_codes:
            raise RuntimeError(f"{label} failed: {json.dumps(value, ensure_ascii=False)}")
        return value

    @staticmethod
    def _require(value: Any, path: str) -> Any:
        if value is None or value == "":
            raise RuntimeError(f"required response field is missing: {path}")
        return value

    def _device_headers(self) -> dict[str, str]:
        if self.config.device_token:
            return {"X-Device-Token": self.config.device_token}
        return {"X-Device-Token-Error": str(self.config.device_token_error)}

    def _navigation_headers(
        self,
        *,
        referer: str = "",
        destination: str = "document",
    ) -> dict[str, str]:
        headers = {
            "Accept": (
                "text/html,application/xhtml+xml,application/xml;q=0.9,"
                "image/avif,image/webp,image/apng,*/*;q=0.8,"
                "application/signed-exchange;v=b3;q=0.7"
            ),
            "Cache-Control": "no-cache",
            "Pragma": "no-cache",
            "Sec-Fetch-Dest": destination,
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "same-origin",
            "Sec-Fetch-User": "?1",
            "Upgrade-Insecure-Requests": "1",
        }
        if referer:
            headers["Referer"] = referer
        return headers

    def _api_headers(
        self,
        *,
        referer: str = "",
        device: bool = False,
        domain: bool = False,
        product: bool = False,
        origin: bool = False,
        trace: bool = True,
    ) -> dict[str, str]:
        headers = {
            "Accept": "application/json, text/plain, */*",
            "Cache-Control": "no-cache",
            "Pragma": "no-cache",
            "Sec-Fetch-Dest": "empty",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Site": "same-origin",
        }
        if referer:
            headers["Referer"] = referer
        if trace:
            headers["traceparent"] = self._traceparent()
        if device:
            headers.update(self._device_headers())
        if domain:
            headers["X-Domain"] = urlparse(self.config.base_url).netloc
        if product:
            headers["X-Product-Code"] = self.config.product_code
        if origin:
            headers["Origin"] = self.config.base_url
        return headers

    def _oneid_headers(self) -> dict[str, str]:
        return {
            "Accept": "application/json",
            "Cache-Control": "no-cache",
            "Pragma": "no-cache",
            "Origin": self.config.base_url,
            "Referer": self.config.base_url + "/",
            "Sec-Fetch-Dest": "empty",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Site": "cross-site",
            "X-TOA-LANG": self.config.language,
        }

    def _signin_headers(self, *, device: bool = False) -> dict[str, str]:
        headers = self._api_headers(
            referer=self.context.login_url if self.context else self.config.base_url + "/",
            device=device,
            origin=True,
            trace=False,
        )
        headers["Content-Type"] = "application/json; charset=utf-8"
        return headers

    def _legacy_sms_payload(self, phone: str, risk_state: str) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "spi_extra": json.dumps(
                {
                    "v": 1,
                    "state": risk_state,
                    "src": "oneid_pc",
                    "biz": "login",
                },
                ensure_ascii=False,
                separators=(",", ":"),
            ),
            "client_code": self.config.oneid_client_code,
            "mobile": phone,
            "scopes": ["openid", "mobile", "profile"],
            "biz_type": "login",
        }
        if self.config.device_token:
            payload["device_token"] = self.config.device_token
        else:
            payload["device_token_error"] = self.config.device_token_error
        return payload

    @staticmethod
    def _should_fallback_from_signin_v2(exc: Exception) -> bool:
        return "UnsupportedOperation.ChineseMainlandTemplateToGlobalPhone" in str(exc)

    def _begin_signin_v2(
        self,
        phone: str,
        context: LoginContext,
        captcha_callback: Optional[
            Callable[[list[dict[str, Any]], str], dict[str, str]]
        ],
    ) -> dict[str, Any]:
        created = self._json(
            self.transport.get(
                self._url("/auth-v2/realms/copilot/signin/phone/login"),
                params={"platform": "web"},
                headers=self._api_headers(
                    referer=context.login_url,
                    origin=True,
                    trace=False,
                ),
            ),
            "signin-v2 phone session",
        )
        context.signin_session_state = str(
            self._require(created.get("session_state"), "session_state")
        )
        context.signin_phone = phone.replace(" ", "")
        self.result["steps"]["signin_v2_session"] = created

        sms_payload: dict[str, Any] = {
            "session_state": context.signin_session_state,
            "phone": context.signin_phone,
        }
        sms: dict[str, Any] = {}
        for _ in range(3):
            sms = self._json(
                self.transport.post(
                    self._url("/auth-v2/realms/copilot/signin/phone/sms"),
                    headers=self._signin_headers(),
                    json_body=sms_payload,
                ),
                "signin-v2 SMS send",
            )
            if sms.get("status") != "captcha_required":
                break
            app_id = str(sms.get("captcha_appid") or "").strip()
            if not app_id or captcha_callback is None:
                raise RuntimeError(
                    "signin-v2 SMS send requires captcha: "
                    + json.dumps(sms, ensure_ascii=False)
                )
            verification = captcha_callback(
                [{"appId": app_id, "cloudType": "tencent"}],
                context.signin_session_state,
            )
            sms_payload["captcha_ticket"] = str(
                verification.get("ticket") or ""
            )
            sms_payload["captcha_randstr"] = str(
                verification.get("randStr")
                or verification.get("randstr")
                or ""
            )
        if sms.get("status") not in {"ok", "cooldown"}:
            raise RuntimeError(
                "signin-v2 SMS send returned unsupported status: "
                + json.dumps(sms, ensure_ascii=False)
            )
        self.result["steps"]["signin_v2_sms_send"] = sms
        self.result["steps"]["sms_send"] = sms
        self.result["context"] = asdict(context)
        return sms

    def _complete_signin_v2(self, otp: str, context: LoginContext) -> str:
        verified = self._json(
            self.transport.post(
                self._url("/auth-v2/realms/copilot/signin/phone/verify"),
                headers=self._signin_headers(device=True),
                json_body={
                    "session_state": context.signin_session_state,
                    "phone": context.signin_phone,
                    "sms_code": otp,
                    "skip_enterprise": True,
                },
            ),
            "signin-v2 phone verify",
        )
        ticket = str(self._require(verified.get("ticket"), "ticket"))
        self.result["steps"]["signin_v2_verify"] = verified
        self.result["steps"]["sms_verify"] = verified

        finalized = self._json(
            self.transport.get(
                self._url("/auth-v2/realms/copilot/signin/finalize"),
                params={
                    "ticket": ticket,
                    "response_type": "code",
                    "session_state": context.signin_session_state,
                },
                headers=self._signin_headers(device=True),
            ),
            "signin-v2 finalize",
        )
        if finalized.get("status") == "account_unavailable":
            raise RuntimeError(
                "signin-v2 account unavailable: "
                + str(finalized.get("reason") or "unknown reason")
            )
        self.result["steps"]["signin_v2_finalize"] = finalized
        return str(self._require(finalized.get("code"), "code"))

    def begin(
        self,
        phone: str,
        captcha_callback: Optional[
            Callable[[list[dict[str, Any]], str], dict[str, str]]
        ] = None,
    ) -> dict[str, Any]:
        trace_id = secrets.token_hex(16)
        desktop_auth = self._api_json(
            self.transport.post(
                self._url(f"/v2{self.config.plugin_prefix}/auth/state"),
                params={"platform": self.config.platform},
                headers=self._api_headers(
                    device=True,
                    domain=True,
                    origin=True,
                ),
                json_body={},
            ),
            "desktop auth state",
        )
        desktop_data = desktop_auth.get("data", {})
        desktop_state = str(self._require(desktop_data.get("state"), "data.state"))
        auth_url = str(self._require(desktop_data.get("authUrl"), "data.authUrl"))
        auth_url = urljoin(self.config.base_url + "/", auth_url)
        auth_url_state = (parse_qs(urlparse(auth_url).query).get("state") or [""])[0]
        if auth_url_state != desktop_state:
            raise RuntimeError(
                f"desktop auth URL state mismatch: expected {desktop_state}, got {auth_url_state}"
            )
        self.result["steps"]["desktop_auth_state"] = desktop_auth

        context = LoginContext(
            desktop_state=desktop_state,
            login_session_id=str(uuid.uuid4()),
            login_owner_id=str(uuid.uuid4()),
            ww_device_nonce=secrets.token_hex(16),
            trace_id=trace_id,
            login_url="",
        )
        initial_traceparent = self._traceparent(trace_id)
        context.login_url = _with_query(
            auth_url,
            version=self.config.version,
            loginSessionId=context.login_session_id,
            traceparent=initial_traceparent,
            login_owner_id=context.login_owner_id,
            ww_device_nonce=context.ww_device_nonce,
        )
        self.context = context
        self.result["context"] = asdict(context)

        opened = self.transport.get(
            context.login_url,
            headers=self._navigation_headers(),
            follow_redirects=True,
        )
        if opened.status_code != 200:
            raise RuntimeError(f"open login returned HTTP {opened.status_code}")
        self.result["steps"]["open_login"] = {
            "status": int(opened.status_code),
            "url": str(opened.url),
            "chain": list(self.transport.last_redirect_chain),
        }
        context.login_url = str(opened.url)

        gray = self._api_json(
            self.transport.get(
                self._url("/v2/plugin/login/gray-decision"),
                params={"feature": GRAY_FEATURES, "platform": self.config.platform},
                headers=self._api_headers(referer=context.login_url, trace=False),
            ),
            "gray decision",
        )
        self.result["steps"]["gray_decision"] = gray

        risk = self._api_json(
            self.transport.post(
                self._url("/console/auth/risk-context"),
                params={"platform": self.config.platform, "version": self.config.version},
                headers=self._api_headers(
                    referer=context.login_url,
                    device=True,
                    origin=True,
                ),
                data="",
            ),
            "risk context",
        )
        context.risk_state = str(self._require(risk.get("data", {}).get("state"), "data.state"))
        self.result["steps"]["risk_context"] = risk

        oidc = self.transport.get(
            self._url("/auth/realms/copilot/protocol/openid-connect/auth"),
            params={
                "client_id": self.config.client_id,
                "response_type": "code",
                "redirect_uri": context.login_url,
            },
            headers=self._navigation_headers(
                referer=context.login_url,
                destination="iframe",
            ),
        )
        if oidc.status_code != 200:
            raise RuntimeError(f"OIDC login page returned HTTP {oidc.status_code}")
        context.oneid_login_url = urljoin(
            str(oidc.url), extract_oneid_login_url(self._text(oidc))
        )
        self.result["context"] = asdict(context)
        self.result["steps"]["oidc_login_page"] = {
            "status": int(oidc.status_code),
            "url": str(oidc.url),
            "oneid_login_url": context.oneid_login_url,
        }

        if self.config.use_signin_v2:
            try:
                return self._begin_signin_v2(phone, context, captcha_callback)
            except RuntimeError as exc:
                if not self._should_fallback_from_signin_v2(exc):
                    raise
                self.result["steps"]["signin_v2_fallback"] = {
                    "reason": str(exc),
                    "flow": "signin_v2_session_with_legacy_oneid_hk_sms",
                }
                self.result["context"] = asdict(context)

        sms_payload = self._legacy_sms_payload(phone, context.risk_state)
        sms: dict[str, Any] = {}
        for _ in range(3):
            sms = self._json(
                self.transport.post(
                    self._oneid_url("/v1/auth/sms/code/send"),
                    headers=self._oneid_headers(),
                    json_body=sms_payload,
                ),
                "OneID SMS send",
            )
            self.result["steps"]["sms_send"] = sms
            if sms.get("status") != "need_captcha":
                break
            captcha_options = sms.get("captcha") or []
            if not captcha_callback or not isinstance(captcha_options, list):
                raise RuntimeError(
                    "OneID SMS send requires captcha: "
                    + json.dumps(sms, ensure_ascii=False)
                )
            state_token = str(sms.get("state_token") or "")
            verification = captcha_callback(captcha_options, state_token)
            sms_payload["captchaVerification"] = verification
            if state_token:
                sms_payload["state_token"] = state_token
        self.result["steps"]["sms_send"] = sms
        if sms.get("status") == "need_captcha":
            raise RuntimeError(
                "OneID SMS captcha was not accepted: "
                + json.dumps(sms, ensure_ascii=False)
            )
        context.oneid_state_token = str(
            self._require(sms.get("state_token"), "state_token")
        )
        self.result["context"] = asdict(context)
        return sms

    def complete(self, otp: str) -> dict[str, Any]:
        context = self.context
        if context is None:
            raise RuntimeError("begin(phone) must complete before complete(otp)")
        if context.signin_session_state:
            try:
                oneid_code = self._complete_signin_v2(otp, context)
                return self._complete_after_oneid_code(oneid_code)
            except RuntimeError as exc:
                if not context.oneid_state_token:
                    raise
                self.result["steps"]["signin_v2_verify_fallback"] = {
                    "reason": str(exc),
                    "flow": "legacy_oneid_verify",
                }
        return self._complete_legacy(otp)

    def _complete_legacy(self, otp: str) -> dict[str, Any]:
        context = self.context
        if context is None or not context.oneid_state_token:
            raise RuntimeError("begin(phone) must complete before complete(otp)")

        verify = self._json(
            self.transport.post(
                self._oneid_url("/v1/auth/sms/code/verify"),
                headers=self._oneid_headers(),
                json_body={"state_token": context.oneid_state_token, "code": otp},
            ),
            "OneID SMS verify",
        )
        verified_token = str(self._require(verify.get("state_token"), "state_token"))
        if verified_token != context.oneid_state_token:
            raise RuntimeError("OneID verify returned a different state_token")
        self.result["steps"]["sms_verify"] = verify

        oneid_accounts = self._json(
            self.transport.get(
                self._oneid_url("/v1/auth/accounts"),
                params={
                    "state_token": context.oneid_state_token,
                    "manual_create_personal": "true",
                },
                headers=self._oneid_headers(),
            ),
            "OneID accounts",
        )
        self.result["steps"]["oneid_accounts"] = oneid_accounts
        next_step = str(
            self._require(oneid_accounts.get("next_step"), "next_step")
        )
        oneid_authorization = oneid_accounts
        if next_step == "register":
            oneid_authorization = self._json(
                self.transport.post(
                    self._oneid_url("/authz/v1/social/personal_account"),
                    headers=self._oneid_headers(),
                    json_body={"state_token": context.oneid_state_token},
                ),
                "OneID personal account registration",
            )
            self.result["steps"]["personal_account_registration"] = (
                oneid_authorization
            )
        elif next_step != "login":
            raise RuntimeError(
                "OneID accounts returned unsupported next_step: "
                + json.dumps(oneid_accounts, ensure_ascii=False)
            )

        if (
            oneid_authorization.get("errCode")
            or oneid_authorization.get("Error")
        ):
            self.result["risk_diagnostics"] = {
                "stage": "oneid_personal_account",
                "errorCode": oneid_authorization.get("errCode"),
                "error": oneid_authorization.get("Error"),
                "deviceTokenPresent": bool(self.config.device_token),
                "deviceCookieNames": sorted(self.config.device_cookies),
                "riskContextPresent": bool(context.risk_state),
                "traceId": context.trace_id,
                "proxyConfigured": bool(self.config.proxy),
                "language": self.config.language,
                "timezone": self.fingerprint.timezone,
                "fingerprintDeviceId": self.fingerprint.device_id,
                "note": "risk rejection occurred after OTP verification and before broker callback",
            }
            raise RuntimeError(
                "OneID authorization failed: "
                + json.dumps(oneid_authorization, ensure_ascii=False)
            )
        oneid_code = str(
            self._require(oneid_authorization.get("code"), "code")
        )
        self._require(oneid_authorization.get("client_id"), "client_id")

        return self._complete_after_oneid_code(oneid_code)

    def _complete_after_oneid_code(self, oneid_code: str) -> dict[str, Any]:
        context = self.context
        if context is None:
            raise RuntimeError("login context is missing")

        broker_login_url = _with_query(
            context.oneid_login_url,
            from_oneid_login="true",
        )
        broker = self._api_json(
            self.transport.get(
                broker_login_url,
                headers=self._api_headers(referer=context.login_url),
            ),
            "OneID broker login",
        )
        broker_state = str(self._require(broker.get("state"), "state"))
        broker_endpoint = str(self._require(broker.get("redirect_uri"), "redirect_uri"))
        self.result["steps"]["broker_login"] = broker

        broker_final = self.transport.get(
            broker_endpoint,
            params={
                "code": oneid_code,
                "state": broker_state,
                "traceparent": self._traceparent(),
            },
            headers=self._navigation_headers(referer=context.login_url),
            follow_redirects=True,
        )
        broker_chain = list(self.transport.last_redirect_chain)
        if broker_final.status_code != 200:
            raise RuntimeError(
                f"Keycloak broker chain ended with HTTP {broker_final.status_code}"
            )
        final_query = parse_qs(urlparse(str(broker_final.url)).query)
        returned_state = (final_query.get("state") or [""])[0]
        if returned_state != context.desktop_state:
            raise RuntimeError(
                f"desktop state mismatch: expected {context.desktop_state}, got {returned_state}"
            )
        self._require((final_query.get("code") or [""])[0], "callback code")
        self._require((final_query.get("session_state") or [""])[0], "session_state")
        self.result["steps"]["keycloak_broker"] = {
            "chain": broker_chain,
            "final_url": str(broker_final.url),
            "callback_query": final_query,
        }

        common_api_headers = self._api_headers(
            referer=context.login_url,
            device=True,
            domain=True,
        )
        accounts_start = self.transport.get(
            self._url("/console/accounts"),
            headers=common_api_headers,
        )
        if accounts_start.status_code not in {301, 302, 303, 307, 308}:
            raise RuntimeError(
                f"accounts OIDC start expected a redirect, got HTTP {accounts_start.status_code}"
            )
        location = accounts_start.headers.get("location") or accounts_start.headers.get("Location")
        self._require(location, "accounts redirect Location")
        oidc_state = (parse_qs(urlparse(urljoin(str(accounts_start.url), location)).query).get("state") or [""])[0]
        self._require(oidc_state, "accounts OIDC state")
        accounts_response = self.transport.get(
            urljoin(str(accounts_start.url), location),
            headers=common_api_headers,
            follow_redirects=True,
        )
        accounts_chain = list(self.transport.last_redirect_chain)
        callback_states = []
        for hop in accounts_chain:
            parsed = urlparse(hop["url"])
            if parsed.path.endswith("/.apisix/redirect"):
                callback_states.extend(parse_qs(parsed.query).get("state", []))
        if callback_states and any(value != oidc_state for value in callback_states):
            raise RuntimeError("accounts OIDC state changed during APISIX callback")
        accounts = self._api_json(accounts_response, "accounts")
        self.result["steps"]["accounts"] = {
            "response": accounts,
            "chain": accounts_chain,
        }

        refresh_validation = self._api_json(
            self.transport.get(
                self._url("/console/validate/refresh-token"),
                headers=self._api_headers(
                    referer=context.login_url,
                    domain=True,
                ),
            ),
            "refresh-token validation",
        )
        self.result["steps"]["refresh_token_validation"] = refresh_validation

        token_response = self._api_json(
            self.transport.post(
                self._url("/console/login/enterprise"),
                params={"state": context.desktop_state},
                headers=self._api_headers(
                    referer=context.login_url,
                    device=True,
                    domain=True,
                    product=True,
                    origin=True,
                ),
                data="",
            ),
            "enterprise token issuance",
        )
        token_data = token_response.get("data", {})
        self._require(token_data.get("accessToken"), "data.accessToken")
        self._require(token_data.get("refreshToken"), "data.refreshToken")
        self.result["steps"]["token_issuance"] = token_response

        switched = self._api_json(
            self.transport.post(
                self._url("/console/account/switch"),
                headers=self._api_headers(
                    referer=context.login_url,
                    origin=True,
                ),
                json_body={},
            ),
            "account switch",
        )
        self.result["steps"]["account_switch"] = switched

        login_type = self._api_json(
            self.transport.get(
                self._url("/console/login/type"),
                headers=self._api_headers(
                    referer=context.login_url,
                    device=True,
                ),
            ),
            "login type",
        )
        self.result["steps"]["login_type"] = login_type

        account = self._api_json(
            self.transport.get(
                self._url("/console/account"),
                headers=self._api_headers(referer=context.login_url),
            ),
            "account",
        )
        self.result["steps"]["account"] = account

        login_data = login_type.get("data", {})
        if login_data.get("loginType") == "register":
            user_id = str(self._require(login_data.get("userId"), "data.userId"))
            registration = self._api_json(
                self.transport.get(
                    self._url("/auth/realms/copilot/overseas/user/register"),
                    params={"userId": user_id},
                    headers=self._api_headers(referer=context.login_url),
                ),
                "new user registration",
                accepted_codes=(200,),
            )
            self.result["steps"]["registration"] = registration
        else:
            self.result["steps"]["registration"] = {
                "skipped": True,
                "reason": "loginType is not register",
            }

        if self.config.enable_attribution and (
            self.config.from_source or self.config.traffic_params
        ):
            attribution = self._api_json(
                self.transport.post(
                    self._url("/console/user/from"),
                    headers=self._api_headers(
                        referer=context.login_url,
                        origin=True,
                        trace=False,
                    ),
                    json_body={
                        "from_source": self.config.from_source,
                        "traffic_params": self.config.traffic_params,
                    },
                ),
                "user attribution",
            )
            self.result["steps"]["attribution"] = attribution
        else:
            self.result["steps"]["attribution"] = {
                "skipped": True,
                "reason": "no attribution values were supplied",
            }

        if self.config.enable_trial:
            time.sleep(1.5)
            trial = self._api_json(
                self.transport.post(
                    self._url("/billing/ide/trial"),
                    headers={
                        **self._api_headers(
                            referer=context.login_url,
                            origin=True,
                            trace=False,
                        ),
                        "Content-Type": "application/x-www-form-urlencoded",
                    },
                    data="",
                ),
                "trial activation",
                accepted_codes=(0, 14051),
            )
            self.result["steps"]["trial"] = trial
        else:
            self.result["steps"]["trial"] = {"skipped": True}

        callback_response = self.transport.get(
            self._url("/console/auth/login"),
            params={
                "platform": self.config.platform,
                "state": context.desktop_state,
                "domain": urlparse(self.config.base_url).netloc,
            },
            headers=self._api_headers(
                referer=context.login_url,
                domain=True,
            ),
            follow_redirects=True,
        )
        callback_chain = list(self.transport.last_redirect_chain)
        callback_record = {
            "status": int(callback_response.status_code),
            "url": str(callback_response.url),
            "chain": callback_chain,
            "body": self._text(callback_response),
        }
        self.result["steps"]["desktop_callback"] = callback_record
        if callback_response.status_code != 200:
            raise RuntimeError(
                f"desktop callback ended with HTTP {callback_response.status_code}: "
                f"{self._text(callback_response)}"
            )
        callback_query = parse_qs(urlparse(str(callback_response.url)).query)
        callback_state = (callback_query.get("state") or [""])[0]
        if callback_state != context.desktop_state:
            raise RuntimeError(
                f"desktop callback state mismatch: expected {context.desktop_state}, got {callback_state}"
            )

        poll_deadline = time.monotonic() + self.config.desktop_poll_timeout
        desktop_token: Optional[dict[str, Any]] = None
        desktop_token_attempts: list[dict[str, Any]] = []
        while time.monotonic() < poll_deadline:
            poll_response = self.transport.get(
                self._url(f"/v2{self.config.plugin_prefix}/auth/token"),
                params={"state": context.desktop_state},
                headers=self._api_headers(domain=True),
            )
            poll_value = self._json(poll_response, "desktop token poll")
            desktop_token_attempts.append(poll_value)
            if poll_value.get("code") == 0 and isinstance(poll_value.get("data"), dict):
                candidate = poll_value["data"]
                if candidate.get("accessToken"):
                    desktop_token = candidate
                    break
            if poll_value.get("code") != 11217:
                raise RuntimeError(
                    "desktop token poll failed: "
                    + json.dumps(poll_value, ensure_ascii=False)
                )
            time.sleep(self.config.desktop_poll_interval)
        if desktop_token is None:
            raise RuntimeError("desktop token polling timed out")
        self.result["steps"]["desktop_token_poll"] = {
            "attempts": desktop_token_attempts,
            "token": desktop_token,
        }

        desktop_access_token = str(
            self._require(desktop_token.get("accessToken"), "desktop token accessToken")
        )
        desktop_account = self._api_json(
            self.transport.get(
                self._url(f"/v2{self.config.plugin_prefix}/login/account"),
                params={"state": context.desktop_state},
                headers={
                    **self._api_headers(domain=True),
                    "Authorization": f"Bearer {desktop_access_token}",
                },
            ),
            "desktop account poll",
        )
        self.result["steps"]["desktop_account_poll"] = desktop_account
        self.result["cookies"] = self.transport.cookies()
        self.result["context"] = asdict(context)
        return self.result

    def run(self, phone: str, otp_provider: Callable[[dict[str, Any]], str]) -> dict[str, Any]:
        sms_response = self.begin(phone)
        while True:
            otp = otp_provider(sms_response)
            if not otp:
                raise RuntimeError("OTP is empty")
            try:
                return self.complete(otp)
            except RuntimeError as exc:
                if "E0010028" not in str(exc):
                    raise
                self.result["steps"].setdefault("rejected_otps", []).append(
                    {"otp": otp, "error": str(exc)}
                )
