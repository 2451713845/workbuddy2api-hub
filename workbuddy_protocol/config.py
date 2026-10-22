from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass
class ProtocolConfig:
    base_url: str = "https://www.workbuddy.cn"
    oneid_url: str = "https://oauth2.account.tencent.com"
    oneid_api_url: str = "https://api.account.tencent.com"
    platform: str = "workbuddy"
    product_code: str = "workbuddy"
    version: str = "5.8.3"
    client_id: str = "console"
    oneid_client_code: str = "codebuddy"
    plugin_prefix: str = "/plugin"
    language: str = "zh-CN"
    timeout: float = 30.0
    retries: int = 2
    retry_backoff: float = 0.5
    max_redirects: int = 12
    desktop_poll_timeout: float = 60.0
    desktop_poll_interval: float = 2.0
    verify_tls: bool = True
    proxy: str = ""
    proxy_connect_to_hosts: tuple[str, ...] = ()
    device_token: str = ""
    device_token_error: int = 1001
    device_cookies: dict[str, str] = None
    trace_path: Path = Path("output/raw-http-trace.jsonl")
    output_path: Path = Path("output/result.json")
    enable_trial: bool = True
    enable_attribution: bool = True
    from_source: str = ""
    traffic_params: str = ""
    use_signin_v2: bool = True

    def normalized(self) -> "ProtocolConfig":
        self.base_url = self.base_url.rstrip("/")
        self.oneid_url = self.oneid_url.rstrip("/")
        self.oneid_api_url = self.oneid_api_url.rstrip("/")
        self.proxy_connect_to_hosts = tuple(
            str(host).strip().lower().rstrip(".")
            for host in self.proxy_connect_to_hosts
            if str(host).strip()
        )
        self.trace_path = Path(self.trace_path)
        self.output_path = Path(self.output_path)
        if not isinstance(self.device_cookies, dict):
            self.device_cookies = {}
        self.device_cookies = {
            str(key): str(value) for key, value in self.device_cookies.items()
            if str(key).strip() and value is not None
        }
        return self
