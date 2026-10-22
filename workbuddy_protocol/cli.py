from __future__ import annotations

import argparse
import base64
import json
from pathlib import Path
import re
import sys
import time
from typing import Any, Optional

from curl_cffi import requests

from .client import WorkBuddyProtocolClient
from .config import ProtocolConfig
from .fingerprint import BrowserFingerprint


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="workbuddy-protocol",
        description="WorkBuddy OneID SMS protocol registration/login client",
    )
    parser.add_argument("--phone", required=True, help="OneID mobile value, including country code")
    parser.add_argument("--otp", help="SMS code; omitted means prompt after sending")
    parser.add_argument("--otp-url", help="Polling URL that returns the SMS code")
    parser.add_argument("--otp-timeout", type=float, default=180.0)
    parser.add_argument("--otp-interval", type=float, default=3.0)
    parser.add_argument("--base-url", default="https://www.workbuddy.cn")
    parser.add_argument("--oneid-url", default="https://oauth2.account.tencent.com")
    parser.add_argument("--version", default="5.8.3")
    parser.add_argument("--proxy", default="", help="HTTP/SOCKS proxy URL")
    parser.add_argument("--device-token", default="", help="Exact X-Device-Token value")
    parser.add_argument(
        "--device-token-error",
        type=int,
        default=1001,
        help="X-Device-Token-Error used when --device-token is empty",
    )
    parser.add_argument("--impersonate", default="chrome150")
    parser.add_argument("--fingerprint-seed", type=int)
    parser.add_argument("--timeout", type=float, default=30.0)
    parser.add_argument("--retries", type=int, default=2)
    parser.add_argument("--no-verify-tls", action="store_true")
    parser.add_argument("--no-trial", action="store_true")
    parser.add_argument("--no-attribution", action="store_true")
    parser.add_argument("--from-source", default="")
    parser.add_argument("--traffic-params", default="")
    parser.add_argument("--trace", type=Path, default=Path("output/raw-http-trace.jsonl"))
    parser.add_argument("--output", type=Path, default=Path("output/result.json"))
    return parser


def extract_otp(raw: str) -> str:
    value = raw.strip()
    if not value or value == "0|0":
        return ""
    try:
        parsed: Any = json.loads(value)
    except (json.JSONDecodeError, TypeError):
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


def decode_provider_body(content: bytes) -> tuple[str, str]:
    for encoding in ("utf-8", "gb18030"):
        try:
            return content.decode(encoding), encoding
        except UnicodeDecodeError:
            continue
    return content.decode("utf-8", errors="replace"), "utf-8-replace"


def write_result(path: Path, result: dict[str, object]) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    rendered = json.dumps(result, ensure_ascii=False, indent=2)
    path.write_text(rendered + "\n", encoding="utf-8")
    return rendered


def main(argv: Optional[list[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    config = ProtocolConfig(
        base_url=args.base_url,
        oneid_url=args.oneid_url,
        version=args.version,
        timeout=args.timeout,
        retries=args.retries,
        verify_tls=not args.no_verify_tls,
        proxy=args.proxy,
        device_token=args.device_token,
        device_token_error=args.device_token_error,
        trace_path=args.trace,
        output_path=args.output,
        enable_trial=not args.no_trial,
        enable_attribution=not args.no_attribution,
        from_source=args.from_source,
        traffic_params=args.traffic_params,
    ).normalized()
    fingerprint = BrowserFingerprint.generate(
        impersonate=args.impersonate,
        language=config.language,
        seed=args.fingerprint_seed,
    )
    client = WorkBuddyProtocolClient(config, fingerprint=fingerprint)
    otp_poll_log: list[dict[str, object]] = []
    returned_otps: set[str] = set()
    otp_baseline = b""
    if args.otp_url:
        baseline_response = requests.get(
            args.otp_url,
            impersonate=fingerprint.impersonate,
            timeout=config.timeout,
        )
        otp_baseline = bytes(baseline_response.content)
        baseline_text, baseline_encoding = decode_provider_body(otp_baseline)
        otp_poll_log.append(
            {
                "phase": "baseline",
                "status": int(baseline_response.status_code),
                "url": str(baseline_response.url),
                "headers": dict(baseline_response.headers),
                "body": baseline_text,
                "body_encoding": baseline_encoding,
                "body_base64": base64.b64encode(otp_baseline).decode("ascii"),
            }
        )

    def otp_provider(sms_response: dict[str, object]) -> str:
        if args.otp is not None:
            return args.otp.strip()
        if args.otp_url:
            deadline = time.monotonic() + args.otp_timeout
            provider = requests.Session(impersonate=fingerprint.impersonate)
            try:
                while time.monotonic() < deadline:
                    response = provider.get(args.otp_url, timeout=config.timeout)
                    raw_bytes = bytes(response.content)
                    raw, encoding = decode_provider_body(raw_bytes)
                    otp_poll_log.append(
                        {
                            "phase": "poll",
                            "status": int(response.status_code),
                            "url": str(response.url),
                            "headers": dict(response.headers),
                            "body": raw,
                            "body_encoding": encoding,
                            "body_base64": base64.b64encode(raw_bytes).decode("ascii"),
                        }
                    )
                    print(
                        f"otp-provider: HTTP {response.status_code} "
                        f"{json.dumps(raw, ensure_ascii=True)}",
                        flush=True,
                    )
                    otp = extract_otp(raw)
                    if otp and raw_bytes != otp_baseline and otp not in returned_otps:
                        returned_otps.add(otp)
                        return otp
                    time.sleep(args.otp_interval)
            finally:
                provider.close()
            raise RuntimeError(f"OTP polling timed out after {args.otp_timeout} seconds")
        print(json.dumps({"sms_send": sms_response}, ensure_ascii=False), flush=True)
        return input("SMS OTP: ").strip()

    try:
        result = client.run(args.phone, otp_provider)
    except BaseException as exc:
        result = client.result
        result["failure"] = {"type": type(exc).__name__, "message": str(exc)}
        if args.otp_url:
            result["otp_provider"] = {
                "url": args.otp_url,
                "responses": otp_poll_log,
            }
        write_result(config.output_path, result)
        raise
    if args.otp_url:
        result["otp_provider"] = {
            "url": args.otp_url,
            "responses": otp_poll_log,
        }
    rendered = write_result(config.output_path, result)
    print(rendered)
    print(f"result={config.output_path.resolve()}", file=sys.stderr)
    print(f"trace={config.trace_path.resolve()}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
