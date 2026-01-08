import socket

import pytest

from tests.mock_tcp import MockAutomationSimulator
from wpshelper import (
    _recv_and_parse,
    WPSTimeoutError,
    wps_close,
    wps_export_html,
    wps_find_installations,
    wps_open_capture,
    wps_set_resolving_list,
    wps_update_matter_keys,
    wps_wireless_devices,
)


def test_recv_and_parse_matches_expectations():
    with MockAutomationSimulator(connect_responses=[b"CMD;OK;extra;Reason=ready\r\n"]) as simulator:
        handle = simulator.create_handle()
        ok, parsed, raw = _recv_and_parse(
            handle,
            expected_cmd="CMD",
            expected_status="OK",
            expected_reason="Reason=ready\r\n",
        )

        assert ok is True
        assert parsed == ["CMD", "OK", "extra", "Reason=ready\r\n"]
        assert raw == "CMD;OK;extra;Reason=ready\r\n"


def test_recv_and_parse_mismatch_returns_false():
    with MockAutomationSimulator(connect_responses=[b"CMD;OK;extra;Reason=ready\r\n"]) as simulator:
        handle = simulator.create_handle()
        ok, parsed, raw = _recv_and_parse(handle, expected_cmd="NOPE")

        assert ok is False
        assert parsed[0] == "CMD"
        assert raw.startswith("CMD;")


def test_recv_and_parse_timeout_logs_and_returns_false():
    with MockAutomationSimulator() as simulator:
        handle = simulator.create_handle(timeout=0.01)
        ok, parsed, raw = _recv_and_parse(handle)

        assert ok is False
        assert parsed is None
        assert raw is None
        assert any("timed out" in entry for entry in handle["log"])


def test_wps_export_html_builds_command_and_waits_for_success():
    with MockAutomationSimulator(responses=[b"HTML EXPORT;SUCCEEDED;Reason=done\r\n"]) as simulator:
        handle = simulator.create_handle()

        wps_export_html(
            handle,
            html_absolute_filename="out.html",
            summary=1,
            databytes=0,
            decode=None,
            frames="selected",
            frame_range_upper=2,
            frame_range_lower=1,
            layers=["LE BB", "LE BIS"],
        )

        sent_command = simulator.received[0].decode()
        assert (
            sent_command
            == "HTML Export;summary=1;databytes=0;decode=0;frames=selected;"
            "frame range upper=2;frame range lower=1;layers=LE BB,LE BIS;file=out.html"
        )


def test_wps_export_html_rejects_invalid_summary():
    with MockAutomationSimulator(responses=[b"HTML EXPORT;SUCCEEDED;Reason=done\r\n"]) as simulator:
        handle = simulator.create_handle()

        with pytest.raises(ValueError, match="summary must be 0 or 1"):
            wps_export_html(handle, summary=2)


def test_wps_update_matter_keys_sends_expected_command():
    with MockAutomationSimulator(responses=[b"OK"]) as simulator:
        handle = simulator.create_handle()

        wps_update_matter_keys(handle, "0x1", ["0x2", "0x3"])

        sent_command = simulator.received[0].decode()
        assert sent_command == "Update Matter;matterkeys=0x1,0x2,0x3"


def test_wps_update_matter_keys_rejects_invalid_inputs():
    with MockAutomationSimulator(responses=[b"OK"]) as simulator:
        handle = simulator.create_handle()

        with pytest.raises(ValueError, match="source_node_id"):
            wps_update_matter_keys(handle, "1234", ["0x2"])

        with pytest.raises(ValueError, match="session_keys must be a list"):
            wps_update_matter_keys(handle, "0x1", "0x2")


def test_wps_set_resolving_list_sends_expected_command():
    with MockAutomationSimulator(
        responses=[b"SET RESOLVING LIST;SUCCEEDED;123;resolving_list_set=all|0x001122334455\r\n"]
    ) as simulator:
        handle = simulator.create_handle()

        reason = wps_set_resolving_list(handle, ["0x001122334455", "0xAABBCCDDEEFF"])

        sent_command = simulator.received[0].decode()
        assert sent_command == "Set Resolving List;0x001122334455,0xAABBCCDDEEFF"
        assert reason == "resolving_list_set=all|0x001122334455\r\n"


def test_wps_set_resolving_list_allows_clear():
    with MockAutomationSimulator(
        responses=[b"SET RESOLVING LIST;SUCCEEDED;123;resolving_list_set=clear\r\n"]
    ) as simulator:
        handle = simulator.create_handle()

        reason = wps_set_resolving_list(handle, "")

        sent_command = simulator.received[0].decode()
        assert sent_command == "Set Resolving List;"
        assert reason == "resolving_list_set=clear\r\n"


def test_wps_set_resolving_list_returns_reason_on_failure():
    with MockAutomationSimulator(
        responses=[
            b"SET RESOLVING LIST;FAILED;123;resolving_list_set=none|resolving_list_error=error0\r\n"
        ]
    ) as simulator:
        handle = simulator.create_handle()

        reason = wps_set_resolving_list(handle, ["0x001122334455"])

        assert reason == "resolving_list_set=none|resolving_list_error=error0\r\n"


def test_wps_wireless_devices_sends_expected_command_and_parses_reason():
    with MockAutomationSimulator(
        responses=[b"WIRELESS DEVICES;SUCCEEDED;REASON=ok;123\r\n"]
    ) as simulator:
        handle = simulator.create_handle()

        reason = wps_wireless_devices(handle, "browse", {"type": "wifi"})

        sent_command = simulator.received[0].decode()
        assert sent_command == "Wireless Devices;browse;type=wifi"
        assert reason == "REASON=ok"


def test_wps_wireless_devices_returns_empty_reason_when_missing():
    with MockAutomationSimulator(responses=[b"WIRELESS DEVICES;SUCCEEDED;123\r\n"]) as simulator:
        handle = simulator.create_handle()

        reason = wps_wireless_devices(handle, "browse", "type=bluetooth")

        assert reason == ""


def test_wps_wireless_devices_select_rejects_invalid_address():
    with MockAutomationSimulator(responses=[b"WIRELESS DEVICES;SUCCEEDED;123\r\n"]) as simulator:
        handle = simulator.create_handle()

        with pytest.raises(ValueError, match="device address"):
            wps_wireless_devices(
                handle,
                "select",
                {"type": "wifi", "address": "invalid", "select": "yes", "favorite": "no"},
            )


def test_wps_wireless_devices_select_rejects_invalid_flags():
    with MockAutomationSimulator(responses=[b"WIRELESS DEVICES;SUCCEEDED;123\r\n"]) as simulator:
        handle = simulator.create_handle()

        with pytest.raises(ValueError, match="select value"):
            wps_wireless_devices(
                handle,
                "select",
                {"type": "wifi", "address": "all", "select": "maybe", "favorite": "no"},
            )

        with pytest.raises(ValueError, match="favorite value"):
            wps_wireless_devices(
                handle,
                "select",
                {"type": "wifi", "address": "all", "select": "yes", "favorite": "maybe"},
            )


def test_wps_set_resolving_list_rejects_invalid_address():
    with MockAutomationSimulator(
        responses=[b"SET RESOLVING LIST;FAILED;123;resolving_list_set=none\r\n"]
    ) as simulator:
        handle = simulator.create_handle()

        with pytest.raises(ValueError, match="BD_ADDR"):
            wps_set_resolving_list(handle, ["0x1234"])


def test_wps_find_installations_returns_latest(tmp_path):
    base_dir = tmp_path / "Teledyne LeCroy Wireless"
    base_dir.mkdir()
    (base_dir / "Wireless Protocol Suite 4.00").mkdir()
    (base_dir / "Wireless Protocol Suite 4.25").mkdir()
    (base_dir / "Wireless Protocol Suite 4.30 (BETA)").mkdir()

    result = wps_find_installations(str(base_dir))

    assert result["latest"]["version"] == "4.30"
    assert result["latest"]["is_beta"] is True
    assert result["paths_by_version"]["4.25"] == [str(base_dir / "Wireless Protocol Suite 4.25")]


def test_wps_find_installations_handles_missing_directory(tmp_path):
    missing_dir = tmp_path / "missing"
    result = wps_find_installations(str(missing_dir))

    assert result["installations"] == []
    assert result["latest"] is None


def test_wps_open_capture_waits_until_max_wait_time_then_raises_wpstimeouterror():
    with MockAutomationSimulator() as simulator:
        handle = simulator.create_handle(timeout=0.01)
        handle["max_wait_time"] = 0.05

        with pytest.raises(WPSTimeoutError):
            wps_open_capture(handle, "C:\\temp\\large.cfax")


def test_wps_close_is_best_effort_on_timeouts():
    with MockAutomationSimulator() as simulator:
        handle = simulator.create_handle(timeout=0.01)
        handle["max_wait_time"] = 0.05

        # Should not raise even if the server never responds.
        wps_close(handle)
