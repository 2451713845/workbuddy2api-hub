"""Portable-package updater (issue #560).

These tests never touch a real gateway or GitHub: the zip is built locally,
downloads use file:// URLs, and stop/start/health are patched. They pin the
parts that can destroy an install: path traversal, version mismatch, backup,
replace, and rollback.
"""
import hashlib
import json
import os
import sys
import tempfile
import unittest
import zipfile
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import wb_update_portable as U


def proxy_source(version):
    return 'server_version = "wb-proxy/%s"\n' % version


def read(path):
    with open(path, encoding="utf-8") as fh:
        return fh.read()


def make_zip(path, version, files):
    manifest = {
        "schema": 1,
        "version": version,
        "root": "wb-proxy",
        "files": list(files),
        "protected": ["accounts/", "usage/"],
    }
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("release-manifest.json",
                    json.dumps(manifest, ensure_ascii=False))
        for rel, data in files.items():
            zf.writestr("wb-proxy/" + rel, data)
    return path


def new_files(version):
    return {
        "wb_proxy.py": proxy_source(version),
        "dashboard.html": "<html>%s</html>" % version,
        "wb_update_apply.py": "# helper %s\n" % version,
    }


class ChecksumTests(unittest.TestCase):
    def test_parse_checksums(self):
        text = "%s  workbuddy2api-hub-v2.0.0.zip\n%s *other.ipk\n" % ("a" * 64, "b" * 64)
        parsed = U.parse_checksums(text)
        self.assertEqual(parsed["workbuddy2api-hub-v2.0.0.zip"], "a" * 64)
        self.assertEqual(parsed["other.ipk"], "b" * 64)

    def test_asset_urls(self):
        zip_url, sha_url, name = U.asset_urls("o/r", "v2.0.0", "2.0.0")
        self.assertEqual(name, "workbuddy2api-hub-v2.0.0.zip")
        self.assertEqual(zip_url, "https://github.com/o/r/releases/download/v2.0.0/" + name)
        self.assertEqual(sha_url, "https://github.com/o/r/releases/download/v2.0.0/SHA256SUMS")


class ExtractTests(unittest.TestCase):
    def test_safe_extract_keeps_manifest_and_root_only(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "a.zip")
            with zipfile.ZipFile(path, "w") as zf:
                zf.writestr("release-manifest.json", "{}")
                zf.writestr("wb-proxy/a.txt", "ok")
                zf.writestr("other/b.txt", "drop")
            out = os.path.join(d, "out")
            U.safe_extract(path, out, "wb-proxy")
            self.assertTrue(os.path.isfile(os.path.join(out, "wb-proxy", "a.txt")))
            self.assertFalse(os.path.exists(os.path.join(out, "other")))

    def test_safe_extract_rejects_traversal(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "bad.zip")
            with zipfile.ZipFile(path, "w") as zf:
                zf.writestr("../evil.txt", "x")
            with self.assertRaises(U.UpdateError):
                U.safe_extract(path, os.path.join(d, "out"), "wb-proxy")


class StageTests(unittest.TestCase):
    def test_validate_stage(self):
        with tempfile.TemporaryDirectory() as d:
            stage = os.path.join(d, "stage")
            files = new_files("2.0.0")
            manifest = {"version": "2.0.0", "root": "wb-proxy",
                        "files": list(files)}
            os.makedirs(os.path.join(stage, "wb-proxy"))
            for rel, data in files.items():
                with open(os.path.join(stage, "wb-proxy", rel), "w",
                          encoding="utf-8") as fh:
                    fh.write(data)
            with open(os.path.join(stage, "release-manifest.json"), "w",
                      encoding="utf-8") as fh:
                json.dump(manifest, fh)
            got = U.validate_stage(stage, "2.0.0", "wb-proxy")
            self.assertEqual(got["version"], "2.0.0")
            with self.assertRaises(U.UpdateError):
                U.validate_stage(stage, "3.0.0", "wb-proxy")


class ApplyTests(unittest.TestCase):
    def _layout(self, d):
        package = os.path.join(d, "package")
        root = os.path.join(package, "wb-proxy")
        os.makedirs(os.path.join(root, "accounts"))
        with open(os.path.join(root, "wb_proxy.py"), "w", encoding="utf-8") as fh:
            fh.write(proxy_source("1.0.0"))
        with open(os.path.join(root, "dashboard.html"), "w", encoding="utf-8") as fh:
            fh.write("old")
        with open(os.path.join(root, "accounts", "keep.json"), "w", encoding="utf-8") as fh:
            fh.write("keep")
        with open(os.path.join(package, "release-manifest.json"), "w",
                  encoding="utf-8") as fh:
            json.dump({"version": "1.0.0", "root": "wb-proxy",
                       "files": ["wb_proxy.py", "dashboard.html"]}, fh)
        return package, root

    def test_backup_apply_restore(self):
        with tempfile.TemporaryDirectory() as d:
            package, root = self._layout(d)
            stage = os.path.join(d, "stage")
            files = new_files("2.0.0")
            os.makedirs(os.path.join(stage, "wb-proxy"))
            for rel, data in files.items():
                with open(os.path.join(stage, "wb-proxy", rel), "w",
                          encoding="utf-8") as fh:
                    fh.write(data)
            manifest = {"version": "2.0.0", "root": "wb-proxy",
                        "files": list(files)}
            with open(os.path.join(stage, "release-manifest.json"), "w",
                      encoding="utf-8") as fh:
                json.dump(manifest, fh)
            backup, saved, absent = U.backup_current(
                root, package, manifest["files"], "2.0.0")
            U.apply_stage(stage, root, package, manifest)
            self.assertIn("2.0.0", read(os.path.join(root, "wb_proxy.py")))
            self.assertEqual(read(os.path.join(root, "accounts", "keep.json")),
                             "keep")
            U.restore_backup(backup, root, package, saved, absent)
            self.assertIn("1.0.0", read(os.path.join(root, "wb_proxy.py")))
            self.assertEqual(read(os.path.join(root, "dashboard.html")), "old")

    def test_run_update_success_and_rollback(self):
        with tempfile.TemporaryDirectory() as d:
            package, root = self._layout(d)
            files = new_files("2.0.0")
            zip_path = os.path.join(d, "new.zip")
            make_zip(zip_path, "2.0.0", files)
            with open(zip_path, "rb") as fh:
                sha = hashlib.sha256(fh.read()).hexdigest()
            sha_path = os.path.join(d, "SHA256SUMS")
            with open(sha_path, "w", encoding="utf-8") as fh:
                fh.write("%s  new.zip\n" % sha)
            status_file = os.path.join(root, "updates", "status.json")

            def fake_urls(repo, tag, version):
                return ("file:///" + zip_path.replace(os.sep, "/"),
                        "file:///" + sha_path.replace(os.sep, "/"),
                        "new.zip")

            with mock.patch.object(U, "asset_urls", fake_urls), \
                    mock.patch.object(U, "status_path", lambda: status_file), \
                    mock.patch.object(U, "stop_gateway", lambda pid: None), \
                    mock.patch.object(U, "wait_port_free", lambda port: True), \
                    mock.patch.object(U, "start_service", lambda *a: None), \
                    mock.patch.object(U, "wait_health", lambda port: True):
                code = U.run_update(root, package, "v2.0.0", "2.0.0",
                                    8788, False, 1234, "o/r")
            self.assertEqual(code, 0)
            with open(status_file, encoding="utf-8") as fh:
                self.assertEqual(json.load(fh)["state"], "succeeded")
            self.assertIn("2.0.0", read(os.path.join(root, "wb_proxy.py")))

            # A second run whose new build never becomes healthy must roll back.
            package, root = self._layout(os.path.join(d, "second"))
            status_file = os.path.join(root, "updates", "status.json")
            with mock.patch.object(U, "asset_urls", fake_urls), \
                    mock.patch.object(U, "status_path", lambda: status_file), \
                    mock.patch.object(U, "stop_gateway", lambda pid: None), \
                    mock.patch.object(U, "wait_port_free", lambda port: True), \
                    mock.patch.object(U, "start_service", lambda *a: None), \
                    mock.patch.object(U, "wait_health", lambda port: False):
                code = U.run_update(root, package, "v2.0.0", "2.0.0",
                                    8788, False, 1234, "o/r")
            self.assertEqual(code, 1)
            with open(status_file, encoding="utf-8") as fh:
                self.assertEqual(json.load(fh)["state"], "rolled_back")
            self.assertIn("1.0.0", read(os.path.join(root, "wb_proxy.py")))


class RequestTests(unittest.TestCase):
    def test_bridge_reports_portable_install_enabled(self):
        import wb_update_request as R
        with mock.patch.object(R, "_systemd_enabled", return_value=False), \
                mock.patch.object(R.wb_update_portable, "available",
                                  return_value=True), \
                mock.patch.object(R.wb_update_portable, "status",
                                  return_value={"state": "idle", "version": "",
                                                "message": ""}):
            self.assertTrue(R.install_enabled())
            self.assertEqual(R.status(), {
                "install_enabled": True,
                "installation": {"state": "idle", "version": "",
                                 "message": ""},
            })

    def test_unavailable_in_a_source_checkout(self):
        self.assertFalse(U.available())
        with self.assertRaises(U.UpdateError):
            U.request_install("v2.0.0", "1.0.0")

    def test_request_spawns_helper_with_port_and_mode(self):
        with tempfile.TemporaryDirectory() as d:
            root = os.path.join(d, "wb-proxy")
            os.makedirs(root)
            open(os.path.join(root, "wb_update_apply.py"), "w").close()
            status_file = os.path.join(root, "updates", "status.json")
            with mock.patch.object(U, "available", lambda: True), \
                    mock.patch.object(U, "app_root", lambda: root), \
                    mock.patch.object(U, "package_root", lambda: d), \
                    mock.patch.object(U, "status_path", lambda: status_file), \
                    mock.patch.object(U.subprocess, "Popen") as popen:
                result = U.request_install("v2.0.0", "1.0.0",
                                           port=8899, lan=True)
                self.assertEqual(result["state"], "queued")
                cmd = popen.call_args[0][0]
                self.assertIn("--tag", cmd)
                self.assertIn("v2.0.0", cmd)
                self.assertIn("--port", cmd)
                self.assertIn("8899", cmd)
                self.assertIn("--lan", cmd)
                self.assertIn("1", cmd)
                self.assertEqual(U.status()["state"], "queued")
                with self.assertRaises(U.UpdateError):
                    U.request_install("v1.0.0", "1.0.0")


if __name__ == "__main__":
    unittest.main()

