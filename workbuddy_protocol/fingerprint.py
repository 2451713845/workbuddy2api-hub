from __future__ import annotations

from dataclasses import asdict, dataclass
import random
import re
import secrets
import uuid
from typing import Optional


_SCREENS = (
    (1920, 1080, 1.0, 8, 8),
    (1920, 1080, 1.0, 12, 8),
    (1536, 864, 1.25, 8, 8),
    (1366, 768, 1.0, 4, 8),
    (2560, 1440, 1.0, 16, 8),
)

_WEBGL = (
    (
        "Google Inc. (Intel)",
        "ANGLE (Intel, Intel(R) UHD Graphics 630 Direct3D11 vs_5_0 ps_5_0, D3D11)",
    ),
    (
        "Google Inc. (Intel)",
        "ANGLE (Intel, Intel(R) Iris(R) Xe Graphics Direct3D11 vs_5_0 ps_5_0, D3D11)",
    ),
    (
        "Google Inc. (NVIDIA)",
        "ANGLE (NVIDIA, NVIDIA GeForce RTX 3060 Direct3D11 vs_5_0 ps_5_0, D3D11)",
    ),
)


@dataclass(frozen=True)
class BrowserFingerprint:
    impersonate: str
    browser_family: str
    major_version: str
    full_version: str
    user_agent: str
    sec_ch_ua: str
    sec_ch_ua_mobile: str
    sec_ch_ua_platform: str
    accept_language: str
    platform: str
    platform_version: str
    screen_width: int
    screen_height: int
    device_pixel_ratio: float
    hardware_concurrency: int
    device_memory: int
    timezone: str
    timezone_offset: int
    webgl_vendor: str
    webgl_renderer: str
    canvas_seed: str
    audio_seed: str
    device_id: str

    @classmethod
    def generate(
        cls,
        *,
        impersonate: str = "chrome150",
        language: str = "zh-CN",
        timezone: str = "Asia/Shanghai",
        seed: Optional[int] = None,
    ) -> "BrowserFingerprint":
        rng = random.Random(seed) if seed is not None else random.SystemRandom()
        width, height, dpr, cores, memory = rng.choice(_SCREENS)
        webgl_vendor, webgl_renderer = rng.choice(_WEBGL)
        version_match = re.fullmatch(r"chrome(\d+)", impersonate)
        major = version_match.group(1) if version_match else "150"
        full = f"{major}.0.0.0"
        return cls(
            impersonate=impersonate,
            browser_family="chrome",
            major_version=major,
            full_version=full,
            user_agent=(
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                f"Chrome/{full} Safari/537.36"
            ),
            sec_ch_ua=(
                f'"Chromium";v="{major}", "Google Chrome";v="{major}", '
                '"Not_A Brand";v="24"'
            ),
            sec_ch_ua_mobile="?0",
            sec_ch_ua_platform='"Windows"',
            accept_language=f"{language},{language.split('-')[0]};q=0.9,en;q=0.8",
            platform="Win32",
            platform_version="10.0.0",
            screen_width=width,
            screen_height=height,
            device_pixel_ratio=dpr,
            hardware_concurrency=cores,
            device_memory=memory,
            timezone=timezone,
            timezone_offset=-480,
            webgl_vendor=webgl_vendor,
            webgl_renderer=webgl_renderer,
            canvas_seed=secrets.token_hex(16),
            audio_seed=secrets.token_hex(16),
            device_id=str(uuid.uuid4()),
        )

    def browser_headers(self) -> dict[str, str]:
        return {
            "User-Agent": self.user_agent,
            "Accept-Language": self.accept_language,
            "sec-ch-ua": self.sec_ch_ua,
            "sec-ch-ua-mobile": self.sec_ch_ua_mobile,
            "sec-ch-ua-platform": self.sec_ch_ua_platform,
        }

    def to_dict(self) -> dict[str, object]:
        return asdict(self)
