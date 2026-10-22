"""Persistent device and phone bindings for protocol-registration batches."""

import json
import importlib
import os
import secrets
import threading
import time
import uuid

import wb_accounts
from wb_registration import TERMINAL_STATES, normalize_hk_phone
BrowserFingerprint = importlib.import_module(
    "workbuddy_protocol.fingerprint").BrowserFingerprint


MAX_PHONES = 2000
MAX_DEVICES = MAX_PHONES

_SIMULATED_HARDWARE = (
    ("ThinkPad X1 Carbon Gen 12", "Windows 11 24H2"),
    ("Dell XPS 15 9530", "Windows 11 23H2"),
    ("HP EliteBook 840 G11", "Windows 11 24H2"),
    ("ASUS Zenbook 14 UX3405", "Windows 11 23H2"),
    ("Surface Laptop 6", "Windows 11 24H2"),
    ("Acer Swift Go 14 SFG14", "Windows 11 23H2"),
)


def _local_phone(value):
    return normalize_hk_phone(value).split(" ", 1)[1]


def _text(value, limit):
    return str(value or "").strip()[:limit]


class DeviceManager(object):
    """Owns saved device profiles and a two-worker registration queue."""

    def __init__(self, accounts_dir, registrations, log=None):
        self.accounts_dir = os.path.abspath(accounts_dir)
        self.path = os.path.join(self.accounts_dir, "registration-devices.json")
        self.registrations = registrations
        self.log = log or (lambda message, **kwargs: None)
        self._lock = threading.RLock()
        self._cancel = threading.Event()
        self._batch = self._empty_batch()
        self._state = self._load()
        with self._lock:
            if self._needs_account_migration:
                self._migrate_account_phones_locked()
            changed = self._ensure_phone_devices_locked()
            if self._needs_account_migration or self._needs_device_migration or changed:
                self._state["version"] = 5
                self._save_locked()

    @staticmethod
    def _empty_batch():
        return {
            "id": "", "status": "idle", "total": 0, "queued": 0,
            "running": 0, "succeeded": 0, "failed": 0, "cancelled": 0,
            "skipped": 0, "skippedRegistered": 0, "skippedIncomplete": 0,
            "requestedLimit": 0,
            "createdAt": 0, "updatedAt": 0, "finishedAt": 0,
            "activeJobIds": [],
        }

    def _load(self):
        try:
            with open(self.path, encoding="utf-8") as handle:
                raw = json.load(handle)
        except (OSError, ValueError):
            raw = {}
        try:
            version = int(raw.get("version") or 1)
        except (TypeError, ValueError):
            version = 1
        self._needs_account_migration = version < 3
        self._needs_device_migration = version < 5
        return self._normalise_state(raw)

    def _normalise_state(self, raw):
        raw = raw if isinstance(raw, dict) else {}
        devices = []
        seen_devices = set()
        for index, item in enumerate(raw.get("devices") or []):
            if not isinstance(item, dict) or len(devices) >= MAX_DEVICES:
                continue
            device_id = _text(item.get("id"), 80) or "device-%03d" % (index + 1)
            if device_id in seen_devices:
                continue
            seen_devices.add(device_id)
            fingerprint = item.get("fingerprint")
            if not isinstance(fingerprint, dict):
                fingerprint = {}
            else:
                fingerprint = dict(fingerprint)
                if (fingerprint.get("impersonate") == "chrome150"
                        and fingerprint.get("major_version") == "150"):
                    # This manager owns a Hong Kong number pool. Preserve the
                    # persistent hardware identity while replacing legacy
                    # server-local language and timezone defaults.
                    fingerprint["accept_language"] = "zh-HK,zh;q=0.9,en;q=0.8"
                    fingerprint["timezone"] = "Asia/Hong_Kong"
                    fingerprint["timezone_offset"] = -480
            devices.append({
                "id": device_id,
                "name": _text(item.get("name"), 120) or "协议模拟设备 %02d" % (index + 1),
                "model": _text(item.get("model"), 120),
                "os": _text(item.get("os"), 120),
                "browser": _text(item.get("browser"), 80) or "Chrome 150",
                "deviceToken": _text(item.get("deviceToken"), 4096),
                "fingerprint": fingerprint,
                "enabled": item.get("enabled") is not False,
                "createdAt": float(item.get("createdAt") or time.time()),
                "updatedAt": float(item.get("updatedAt") or time.time()),
            })
        phones = []
        seen_phones = set()
        for index, item in enumerate(raw.get("phones") or []):
            if not isinstance(item, dict) or len(phones) >= MAX_PHONES:
                continue
            try:
                phone = _local_phone(item.get("phone"))
            except ValueError:
                continue
            if phone in seen_phones:
                continue
            seen_phones.add(phone)
            phone_id = _text(item.get("id"), 80) or "phone-%s" % phone
            phones.append({
                "id": phone_id,
                "phone": phone,
                "otpUrl": _text(item.get("otpUrl"), 4096),
                "deviceId": _text(item.get("deviceId"), 80),
                "enabled": item.get("enabled") is not False,
                "lastJobId": _text(item.get("lastJobId"), 80),
                "lastStatus": _text(item.get("lastStatus"), 40),
                "lastMessage": _text(item.get("lastMessage"), 1000),
                "accountUid": _text(item.get("accountUid"), 200),
                "updatedAt": float(item.get("updatedAt") or time.time()),
            })
        return {"version": 5, "devices": devices, "phones": phones}

    def _account_objects(self):
        pool = getattr(self.registrations, "pool", None)
        if pool is None:
            return []
        lock = getattr(pool, "_lock", None)
        if lock is None:
            return list(getattr(pool, "accounts", ()) or ())
        with lock:
            return list(getattr(pool, "accounts", ()) or ())

    def _account_rows(self):
        rows = []
        for account in self._account_objects():
            uid = _text(getattr(account, "uid", ""), 200)
            if not uid:
                continue
            rows.append({
                "uid": uid,
                "nickname": _text(getattr(account, "nickname", ""), 200) or uid,
                "realm": _text(getattr(account, "realm", ""), 20),
                "source": _text(getattr(account, "source", ""), 80),
                "deviceId": _text(getattr(account, "device_id", ""), 80),
                "deviceName": _text(getattr(account, "device_name", ""), 120),
                "deviceModel": _text(getattr(account, "device_model", ""), 120),
            })
        return rows

    def _migrate_account_phones_locked(self):
        """Import pre-manager protocol accounts once, using their phone nickname."""
        known_phones = {item["phone"]: item for item in self._state["phones"]}
        accounts = {item["uid"]: item for item in self._account_rows()}
        objects = {getattr(item, "uid", ""): item for item in self._account_objects()}
        for uid, account in accounts.items():
            source = account.get("source") or ""
            if not source.startswith("protocol-registration"):
                continue
            try:
                phone = _local_phone(getattr(objects.get(uid), "nickname", ""))
            except ValueError:
                continue
            existing = known_phones.get(phone)
            if existing is not None:
                if not existing.get("accountUid"):
                    existing["accountUid"] = uid
                    existing["lastStatus"] = existing.get("lastStatus") or "succeeded"
                    existing["lastMessage"] = existing.get("lastMessage") or "已关联现有协议注册账号"
                    existing["updatedAt"] = time.time()
                continue
            now = time.time()
            self._state["phones"].append({
                "id": "phone-" + phone,
                "phone": phone,
                "otpUrl": "",
                "deviceId": "",
                "enabled": True,
                "lastJobId": "",
                "lastStatus": "succeeded",
                "lastMessage": "由现有协议注册账号导入",
                "accountUid": uid,
                "updatedAt": now,
            })
            known_phones[phone] = self._state["phones"][-1]

    def _save_locked(self):
        os.makedirs(self.accounts_dir, exist_ok=True)
        tmp = self.path + ".tmp.%s.%s" % (os.getpid(), threading.get_ident())
        try:
            with open(tmp, "w", encoding="utf-8", newline="\n") as handle:
                json.dump(self._state, handle, ensure_ascii=False, indent=2)
                handle.write("\n")
            os.replace(tmp, self.path)
        finally:
            try:
                if os.path.exists(tmp):
                    os.unlink(tmp)
            except OSError:
                pass

    @staticmethod
    def _valid_fingerprint(value):
        return (
            isinstance(value, dict)
            and value.get("impersonate") == "chrome150"
            and value.get("major_version") == "150"
            and bool(value.get("device_id"))
            and value.get("accept_language") == "zh-HK,zh;q=0.9,en;q=0.8"
            and value.get("timezone") == "Asia/Hong_Kong"
            and value.get("timezone_offset") == -480
        )

    def _new_simulated_device_locked(self, phone="", token=""):
        seed = secrets.randbits(63)
        fingerprint = BrowserFingerprint.generate(
            impersonate="chrome150",
            language="zh-HK",
            timezone="Asia/Hong_Kong",
            seed=seed,
        )
        model, os_name = _SIMULATED_HARDWARE[seed % len(_SIMULATED_HARDWARE)]
        now = time.time()
        suffix = phone[-4:] if phone else fingerprint.device_id[:6].upper()
        return {
            "id": "device-" + fingerprint.device_id,
            "name": "协议模拟设备 " + suffix,
            "model": model,
            "os": os_name,
            "browser": "Chrome 150",
            "deviceToken": token or wb_accounts.resolve_device_token(self.accounts_dir),
            "fingerprint": fingerprint.to_dict(),
            "enabled": True,
            "createdAt": now,
            "updatedAt": now,
        }

    def _ensure_phone_devices_locked(self):
        """Give every phone one persistent protocol-simulated device profile."""
        by_id = {item["id"]: item for item in self._state["devices"]}
        shared_token = wb_accounts.resolve_device_token(self.accounts_dir)
        used = set()
        devices = []
        changed = False
        for phone in self._state["phones"]:
            current = by_id.get(phone.get("deviceId") or "")
            reusable = (
                current is not None
                and current["id"] not in used
                and self._valid_fingerprint(current.get("fingerprint"))
                and current.get("model") not in ("", "Windows Desktop")
            )
            if reusable:
                device = current
                if not device.get("deviceToken") and shared_token:
                    device["deviceToken"] = shared_token
                    device["updatedAt"] = time.time()
                    changed = True
            else:
                inherited_token = (current or {}).get("deviceToken") or shared_token
                device = self._new_simulated_device_locked(
                    phone.get("phone") or "", inherited_token
                )
                phone["deviceId"] = device["id"]
                phone["updatedAt"] = time.time()
                changed = True
            used.add(device["id"])
            devices.append(device)
        if [item.get("id") for item in devices] != [
            item.get("id") for item in self._state["devices"]
        ]:
            changed = True
        self._state["devices"] = devices
        device_by_id = {item["id"]: item for item in devices}
        accounts = {
            _text(getattr(item, "uid", ""), 200): item
            for item in self._account_objects()
        }
        for phone in self._state["phones"]:
            account = accounts.get(phone.get("accountUid") or "")
            device = device_by_id.get(phone.get("deviceId") or "")
            if account is None or device is None:
                continue
            values = {
                "device_id": device["id"],
                "device_name": device["name"],
                "device_model": device["model"],
                "device_os": device["os"],
                "device_token": device["deviceToken"],
            }
            if any(getattr(account, key, "") != value for key, value in values.items()):
                for key, value in values.items():
                    setattr(account, key, value)
                saver = getattr(account, "save", None)
                if callable(saver):
                    saver(self.accounts_dir)
                changed = True
        return changed

    def snapshot(self):
        with self._lock:
            if self._ensure_phone_devices_locked():
                self._save_locked()
            data = json.loads(json.dumps(self._state, ensure_ascii=False))
            data["accounts"] = self._account_rows()
            data["batch"] = dict(self._batch)
            return data

    def save(self, payload):
        if not isinstance(payload, dict):
            raise ValueError("device payload must be an object")
        if not isinstance(payload.get("devices"), list):
            raise ValueError("devices must be a list")
        if not isinstance(payload.get("phones"), list):
            raise ValueError("phones must be a list")
        if len(payload["devices"]) > MAX_DEVICES or len(payload["phones"]) > MAX_PHONES:
            raise ValueError("device or phone list exceeds the supported limit")
        with self._lock:
            if self._batch["status"] in ("queued", "running", "cancelling"):
                raise RuntimeError("device bindings cannot be edited while a batch is running")
            old_devices = {item["id"]: item for item in self._state["devices"]}
            old_phones = {item["id"]: item for item in self._state["phones"]}
            merged = {"version": 5, "devices": [], "phones": []}
            for item in payload.get("devices") or self._state["devices"]:
                if not isinstance(item, dict):
                    continue
                old = old_devices.get(_text(item.get("id"), 80), {})
                row = dict(item)
                row["deviceToken"] = (_text(item.get("deviceToken"), 4096)
                                      or old.get("deviceToken")
                                      or wb_accounts.resolve_device_token(self.accounts_dir))
                row["fingerprint"] = (
                    item.get("fingerprint")
                    if isinstance(item.get("fingerprint"), dict)
                    else old.get("fingerprint") or {}
                )
                row["createdAt"] = old.get("createdAt") or time.time()
                row["updatedAt"] = time.time()
                merged["devices"].append(row)
            for item in payload["phones"]:
                if not isinstance(item, dict):
                    continue
                old = old_phones.get(_text(item.get("id"), 80), {})
                row = dict(item)
                for key in ("lastJobId", "lastStatus", "lastMessage"):
                    row[key] = old.get(key, row.get(key))
                account_uid = _text(row.get("accountUid"), 200)
                pool = getattr(self.registrations, "pool", None)
                old_account_uid = _text(old.get("accountUid"), 200)
                if (account_uid and account_uid != old_account_uid
                        and (pool is None or pool.get(account_uid) is None)):
                    raise ValueError("phone %s references an unknown account" % row.get("phone"))
                row["accountUid"] = account_uid
                merged["phones"].append(row)
            state = self._normalise_state(merged)
            self._state = state
            self._ensure_phone_devices_locked()
            self._save_locked()
        return self.snapshot()

    def generate(self, payload=None):
        payload = payload if isinstance(payload, dict) else {}
        with self._lock:
            device = self._new_simulated_device_locked()
            device["name"] = _text(payload.get("name"), 120) or device["name"]
            self._state["devices"].append(device)
            self._save_locked()
        result = self.snapshot()
        result["generated"] = dict(device)
        return result

    def start_batch(self, payload=None):
        payload = payload if isinstance(payload, dict) else {}
        requested = payload.get("phoneIds")
        if requested is not None and not isinstance(requested, list):
            raise ValueError("phoneIds must be a list")
        selected = set(str(item) for item in (requested or []))
        try:
            concurrency = int(payload.get("concurrency") or 2)
        except (TypeError, ValueError):
            raise ValueError("concurrency must be a whole number")
        concurrency = max(1, min(concurrency, 2))
        try:
            limit = int(payload.get("limit") or 0)
        except (TypeError, ValueError):
            raise ValueError("limit must be a whole number")
        if limit < 0:
            raise ValueError("limit must be zero or greater")
        limit = min(limit, MAX_PHONES)
        with self._lock:
            if self._batch["status"] in ("queued", "running", "cancelling"):
                raise RuntimeError("a registration batch is already running")
            self._ensure_phone_devices_locked()
            devices = {item["id"]: item for item in self._state["devices"]
                       if item["enabled"] and item["deviceToken"]}
            rows = []
            skipped_registered = 0
            skipped_incomplete = 0
            for phone in self._state["phones"]:
                if not phone["enabled"] or (selected and phone["id"] not in selected):
                    continue
                if phone.get("accountUid") or phone.get("lastStatus") == "succeeded":
                    skipped_registered += 1
                    continue
                if not phone["otpUrl"] or phone["deviceId"] not in devices:
                    skipped_incomplete += 1
                    continue
                rows.append(phone["id"])
                if limit and len(rows) >= limit:
                    break
            if not rows:
                raise ValueError("no unregistered phone with a complete OTP URL and device is available")
            now = time.time()
            self._cancel = threading.Event()
            self._batch = {
                "id": uuid.uuid4().hex, "status": "queued", "total": len(rows),
                "queued": len(rows), "running": 0, "succeeded": 0,
                "failed": 0, "cancelled": 0, "createdAt": now,
                "skipped": skipped_registered + skipped_incomplete,
                "skippedRegistered": skipped_registered,
                "skippedIncomplete": skipped_incomplete,
                "requestedLimit": limit,
                "updatedAt": now, "finishedAt": 0, "activeJobIds": [],
            }
            for phone_id in rows:
                row = self._phone_locked(phone_id)
                row.update({"lastJobId": "", "lastStatus": "queued",
                            "lastMessage": "等待批量注册",
                            "updatedAt": now})
            self._save_locked()
            batch_id = self._batch["id"]
        thread = threading.Thread(
            target=self._run_batch, args=(batch_id, rows, concurrency),
            name="wb-device-batch-" + batch_id[:8], daemon=True,
        )
        thread.start()
        return self.snapshot()

    def cancel_batch(self):
        with self._lock:
            if self._batch["status"] not in ("queued", "running", "cancelling"):
                return self.snapshot()
            self._batch["status"] = "cancelling"
            self._batch["updatedAt"] = time.time()
            active = list(self._batch["activeJobIds"])
            self._cancel.set()
        for job_id in active:
            try:
                self.registrations.cancel(job_id)
            except KeyError:
                pass
        return self.snapshot()

    def _phone_locked(self, phone_id):
        for row in self._state["phones"]:
            if row["id"] == phone_id:
                return row
        raise KeyError("saved phone was removed")

    def _run_batch(self, batch_id, phone_ids, concurrency):
        queue_lock = threading.Lock()
        queue = list(phone_ids)

        def worker():
            while True:
                with queue_lock:
                    if self._cancel.is_set() or not queue:
                        return
                    phone_id = queue.pop(0)
                self._run_phone(batch_id, phone_id)

        with self._lock:
            if self._batch["id"] != batch_id:
                return
            self._batch["status"] = "running"
            self._batch["updatedAt"] = time.time()
        workers = [threading.Thread(target=worker, daemon=True,
                                    name="wb-device-worker-%d" % index)
                   for index in range(min(concurrency, len(phone_ids)))]
        for worker_thread in workers:
            worker_thread.start()
        for worker_thread in workers:
            worker_thread.join()
        with self._lock:
            if self._batch["id"] != batch_id:
                return
            if self._cancel.is_set():
                for phone_id in queue:
                    row = self._phone_locked(phone_id)
                    row.update({"lastStatus": "cancelled", "lastMessage": "批量任务已取消",
                                "updatedAt": time.time()})
                self._batch["cancelled"] += len(queue)
                self._batch["queued"] = 0
                self._batch["status"] = "cancelled"
            else:
                self._batch["status"] = "completed"
            self._batch["running"] = 0
            self._batch["activeJobIds"] = []
            self._batch["updatedAt"] = time.time()
            self._batch["finishedAt"] = time.time()
            self._save_locked()

    def _run_phone(self, batch_id, phone_id):
        job_id = ""
        try:
            with self._lock:
                if self._batch["id"] != batch_id or self._cancel.is_set():
                    return
                phone = dict(self._phone_locked(phone_id))
                device = next((dict(item) for item in self._state["devices"]
                               if item["id"] == phone["deviceId"]), None)
                if device is None:
                    raise ValueError("bound device no longer exists")
                row = self._phone_locked(phone_id)
                row.update({"lastStatus": "starting", "lastMessage": "正在创建注册任务",
                            "updatedAt": time.time()})
                self._batch["queued"] = max(0, self._batch["queued"] - 1)
                self._batch["running"] += 1
                self._batch["updatedAt"] = time.time()
                self._save_locked()
            started = self.registrations.start({
                "phone": phone["phone"], "otpUrl": phone["otpUrl"],
                "deviceId": device["id"], "deviceName": device["name"],
                "deviceModel": device["model"], "deviceOs": device["os"],
                "deviceToken": device["deviceToken"],
                "deviceFingerprint": device["fingerprint"],
            })
            job_id = started["id"]
            with self._lock:
                row = self._phone_locked(phone_id)
                row.update({"lastJobId": job_id, "lastStatus": started["status"],
                            "lastMessage": started["message"], "updatedAt": time.time()})
                self._batch["activeJobIds"].append(job_id)
                self._save_locked()
            while not self._cancel.wait(1.0):
                job = self.registrations.snapshot(job_id)
                with self._lock:
                    row = self._phone_locked(phone_id)
                    row.update({"lastStatus": job["status"],
                                "lastMessage": job.get("message") or "",
                                "updatedAt": time.time()})
                    self._save_locked()
                if job["status"] in TERMINAL_STATES:
                    break
            if self._cancel.is_set():
                try:
                    self.registrations.cancel(job_id)
                except KeyError:
                    pass
                deadline = time.monotonic() + 5.0
                job = self.registrations.snapshot(job_id)
                while job["status"] not in TERMINAL_STATES and time.monotonic() < deadline:
                    time.sleep(0.05)
                    job = self.registrations.snapshot(job_id)
            else:
                job = self.registrations.snapshot(job_id)
            status = job["status"]
            with self._lock:
                row = self._phone_locked(phone_id)
                account = job.get("account") or {}
                row.update({"lastStatus": status, "lastMessage": job.get("message") or "",
                            "updatedAt": time.time()})
                if account.get("uid"):
                    row["accountUid"] = account["uid"]
                self._batch[status if status in ("succeeded", "failed", "cancelled") else "failed"] += 1
        except BaseException as exc:
            with self._lock:
                try:
                    row = self._phone_locked(phone_id)
                    row.update({"lastStatus": "failed", "lastMessage": str(exc),
                                "updatedAt": time.time()})
                except KeyError:
                    pass
                self._batch["failed"] += 1
                self.log("device registration batch row failed: %s" % exc,
                         level="WARN", tag="accounts")
        finally:
            with self._lock:
                if self._batch["id"] == batch_id:
                    self._batch["running"] = max(0, self._batch["running"] - 1)
                    if job_id in self._batch["activeJobIds"]:
                        self._batch["activeJobIds"].remove(job_id)
                    self._batch["updatedAt"] = time.time()
                    self._save_locked()
