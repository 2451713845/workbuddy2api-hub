from __future__ import annotations

import json
import socket
import time
from typing import Any, Mapping, Optional, Union
from urllib.parse import urlencode, urljoin

from .config import ProtocolConfig
from .fingerprint import BrowserFingerprint
from .trace import RawTraceWriter


class _ConnectToCurl:
    """Build a curl_cffi Curl subclass with CURLOPT_CONNECT_TO slist support."""

    @staticmethod
    def create() -> Any:
        from curl_cffi import Curl, CurlOpt
        from curl_cffi._wrapper import ffi, lib

        class ConnectToCurl(Curl):
            def __init__(self, *args: Any, **kwargs: Any) -> None:
                super().__init__(*args, **kwargs)
                self._connect_to = ffi.NULL

            def setopt(self, option: Any, value: Any) -> int:
                if option != CurlOpt.CONNECT_TO:
                    return super().setopt(option, value)
                if self._connect_to != ffi.NULL:
                    lib._curl_easy_setopt(self._curl, option, ffi.NULL)
                    lib.curl_slist_free_all(self._connect_to)
                    self._connect_to = ffi.NULL
                for entry in value:
                    if isinstance(entry, str):
                        entry = entry.encode("utf-8")
                    self._connect_to = lib.curl_slist_append(
                        self._connect_to, entry
                    )
                result = lib._curl_easy_setopt(
                    self._curl, option, self._connect_to
                )
                self._check_error(result, "setopt", option, value)
                return result

            def reset(self) -> None:
                super().reset()
                if self._connect_to != ffi.NULL:
                    lib.curl_slist_free_all(self._connect_to)
                    self._connect_to = ffi.NULL

            def close(self) -> None:
                super().close()
                if self._connect_to != ffi.NULL:
                    lib.curl_slist_free_all(self._connect_to)
                    self._connect_to = ffi.NULL

        return ConnectToCurl()


def _proxy_connect_to_entries(hosts: tuple[str, ...]) -> list[str]:
    entries = []
    for host in hosts:
        addresses = socket.getaddrinfo(
            host, 443, family=socket.AF_INET, type=socket.SOCK_STREAM
        )
        address = next(
            (
                item[4][0]
                for item in addresses
                if item[4] and item[4][0]
            ),
            "",
        )
        if not address:
            raise OSError("no IPv4 address resolved for %s" % host)
        entries.append("%s:443:%s:443" % (host, address))
    return entries


class ProtocolTransport:
    """curl_cffi transport with explicit redirects and lossless HTTP tracing."""

    def __init__(
        self,
        config: ProtocolConfig,
        fingerprint: BrowserFingerprint,
        *,
        session: Optional[Any] = None,
        trace: Optional[RawTraceWriter] = None,
    ) -> None:
        self.config = config
        self.fingerprint = fingerprint
        self.trace = trace or RawTraceWriter(config.trace_path)
        self.default_headers = fingerprint.browser_headers()
        self.sequence = 0
        self.last_redirect_chain: list[dict[str, Any]] = []

        if session is None:
            from curl_cffi import CurlOpt, requests

            proxies = None
            if config.proxy:
                proxies = {"http": config.proxy, "https": config.proxy}
            connect_to = []
            if config.proxy and config.proxy_connect_to_hosts:
                connect_to = _proxy_connect_to_entries(
                    config.proxy_connect_to_hosts
                )
            session = requests.Session(
                curl=_ConnectToCurl.create() if connect_to else None,
                impersonate=fingerprint.impersonate,
                verify=config.verify_tls,
                proxies=proxies,
                headers=self.default_headers,
                curl_options=(
                    {CurlOpt.CONNECT_TO: connect_to} if connect_to else None
                ),
            )
        self.session = session
        if config.device_cookies:
            jar = getattr(self.session, "cookies", None)
            setter = getattr(jar, "set", None)
            if callable(setter):
                for name, value in config.device_cookies.items():
                    try:
                        setter(name, value, domain=".workbuddy.cn", path="/")
                    except TypeError:
                        setter(name, value)

    @staticmethod
    def _encode_body(
        headers: dict[str, str],
        *,
        json_body: Optional[Any],
        data: Optional[Any],
    ) -> Union[bytes, str, None]:
        if json_body is not None and data is not None:
            raise ValueError("json_body and data are mutually exclusive")
        if json_body is not None:
            headers.setdefault("Content-Type", "application/json")
            return json.dumps(json_body, ensure_ascii=False, separators=(",", ":"))
        if isinstance(data, Mapping):
            headers.setdefault("Content-Type", "application/x-www-form-urlencoded")
            return urlencode(data, doseq=True)
        return data

    def _cookies(self) -> dict[str, str]:
        jar = getattr(self.session, "cookies", None)
        if jar is None:
            return {}
        getter = getattr(jar, "get_dict", None)
        if callable(getter):
            return dict(getter())
        return {str(cookie.name): str(cookie.value) for cookie in jar}

    def _request_once(
        self,
        method: str,
        url: str,
        *,
        headers: Optional[Mapping[str, str]],
        params: Optional[Mapping[str, Any]],
        body: Union[bytes, str, None],
    ) -> Any:
        request_headers = dict(self.default_headers)
        if headers:
            request_headers.update(headers)

        attempts = 1 + max(0, self.config.retries)
        for attempt in range(attempts):
            try:
                response = self.session.request(
                    method,
                    url,
                    headers=request_headers,
                    params=params,
                    data=body,
                    allow_redirects=False,
                    timeout=self.config.timeout,
                )
            except Exception as exc:
                self.sequence += 1
                error_url = url
                if params:
                    separator = "&" if "?" in error_url else "?"
                    error_url += separator + urlencode(params, doseq=True)
                self.trace.write_error(
                    sequence=self.sequence,
                    method=method,
                    url=error_url,
                    request_headers=request_headers,
                    request_body=body,
                    error=exc,
                    cookies=self._cookies(),
                )
                if attempt + 1 >= attempts or method not in {"GET", "HEAD", "OPTIONS"}:
                    raise
                time.sleep(self.config.retry_backoff * (2**attempt))
                continue
            self.sequence += 1
            actual_headers = request_headers
            prepared = getattr(response, "request", None)
            if prepared is not None and getattr(prepared, "headers", None) is not None:
                actual_headers = dict(prepared.headers)
            self.trace.write(
                sequence=self.sequence,
                method=method,
                url=str(response.url),
                request_headers=actual_headers,
                request_body=body,
                response=response,
                cookies=self._cookies(),
            )
            should_return = (
                response.status_code not in {502, 503, 504}
                or attempt + 1 >= attempts
                or method not in {"GET", "HEAD", "OPTIONS"}
            )
            if should_return:
                return response
            time.sleep(self.config.retry_backoff * (2**attempt))
        raise AssertionError("request retry loop exited unexpectedly")

    def request(
        self,
        method: str,
        url: str,
        *,
        headers: Optional[Mapping[str, str]] = None,
        params: Optional[Mapping[str, Any]] = None,
        json_body: Optional[Any] = None,
        data: Optional[Any] = None,
        follow_redirects: bool = False,
        max_redirects: Optional[int] = None,
    ) -> Any:
        method = method.upper()
        request_headers = dict(headers or {})
        body = self._encode_body(request_headers, json_body=json_body, data=data)
        response = self._request_once(
            method,
            url,
            headers=request_headers,
            params=params,
            body=body,
        )
        self.last_redirect_chain = [
            {"status": int(response.status_code), "url": str(response.url)}
        ]
        if not follow_redirects:
            return response

        limit = max_redirects if max_redirects is not None else self.config.max_redirects
        for _ in range(limit):
            if response.status_code not in {301, 302, 303, 307, 308}:
                return response
            location = response.headers.get("location") or response.headers.get("Location")
            if not location:
                return response
            next_url = urljoin(str(response.url), location)
            if response.status_code == 303 or (
                response.status_code in {301, 302} and method not in {"GET", "HEAD"}
            ):
                method = "GET"
                body = None
                request_headers = {
                    key: value
                    for key, value in request_headers.items()
                    if key.lower() not in {"content-type", "content-length"}
                }
            response = self._request_once(
                method,
                next_url,
                headers=request_headers,
                params=None,
                body=body,
            )
            self.last_redirect_chain.append(
                {"status": int(response.status_code), "url": str(response.url)}
            )
        raise RuntimeError(f"redirect limit exceeded ({limit}) at {response.url}")

    def get(self, url: str, **kwargs: Any) -> Any:
        return self.request("GET", url, **kwargs)

    def post(self, url: str, **kwargs: Any) -> Any:
        return self.request("POST", url, **kwargs)

    def cookies(self) -> dict[str, str]:
        return self._cookies()
