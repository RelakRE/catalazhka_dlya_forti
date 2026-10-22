"""Run this module alone on Windows: no Unix-only imports, files, IPC or routes."""
import contextlib
import io
import json
import unittest
from unittest import mock

import desktop_entry
import platform_contract
import profile_model
import setup_flow
import json_codec


class CrossPlatformCoreTests(unittest.TestCase):
    def test_json_depth_limit_is_explicit_not_c_decoder_dependent(self):
        with self.assertRaises(ValueError):
            json_codec.loads("[" * 65 + "0" + "]" * 65)
        literal = "[" * 1000 + '\\"' + "]" * 1000
        self.assertEqual(json_codec.loads(json.dumps({"text": literal})), {"text": literal})
        self.assertEqual(json_codec.loads(b'{"n": 1}'), {"n": 1})

    def test_windows_backend_is_explicitly_unavailable(self):
        info = platform_contract.describe("Windows", "AMD64", "11")
        output = io.StringIO()
        with mock.patch.object(desktop_entry, "describe", return_value=info), \
             mock.patch.dict("sys.modules", {"gui_backend": None}), contextlib.redirect_stdout(output):
            self.assertEqual(desktop_entry.main(["status"]), 2)
        self.assertEqual(json.loads(output.getvalue())["flow"]["stage"], "unsupported")

    def test_profile_wire_format_is_platform_neutral(self):
        value = {"schema": 1, "session_minutes": 0, "work_ipv4": ["10.77.1.20"]}
        self.assertEqual(profile_model.parse("\ufeff" + json.dumps(value)), value)

    def test_profile_has_no_paths_commands_or_credentials(self):
        for field in ("path", "command", "password", "token"):
            text = json.dumps({"schema": 1, "session_minutes": 0, "work_ipv4": ["10.77.1.20"], field: "x"})
            with self.assertRaises(ValueError):
                profile_model.parse(text)

    def test_mac_backend_is_not_selected_for_an_unknown_platform(self):
        from platform_adapters import UnavailableBackend, select_backend
        self.assertIsInstance(select_backend(platform_contract.describe("Other", "x86_64", "")), UnavailableBackend)

    def test_wizard_output_is_serializable_for_a_future_windows_ui(self):
        result = setup_flow.flow({"profile": {"ready": False}, "session": None})
        self.assertEqual(json.loads(json.dumps(result))["action"], "import-profile")

    def test_incomplete_recovery_cannot_offer_a_new_session(self):
        result = setup_flow.flow({"latest_status": "rollback_unconfirmed", "service": {"installed": False}})
        self.assertTrue(result["blocked"])
        self.assertNotEqual(result["action"], "enable")


if __name__ == "__main__":
    unittest.main()
