import socket

import pytest

from wpshelper import _recv_and_parse, wps_export_html, wps_update_matter_keys


class DummySocket:
    def __init__(self, responses=None):
        self._responses = list(responses or [])
        self.sent = []

    def recv(self, _max_to_read):
        if not self._responses:
            raise AssertionError("No more responses configured for DummySocket.")
        response = self._responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return response

    def send(self, data):
        self.sent.append(data)


def make_handle(responses=None):
    return {
        "socket": DummySocket(responses=responses),
        "max_data_from_automation_server": 1000,
        "sleep_time": 0,
        "max_wait_time": 1,
        "log": [],
    }


def test_recv_and_parse_matches_expectations():
    handle = make_handle(responses=[b"CMD;OK;extra;Reason=ready\r\n"])
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
    handle = make_handle(responses=[b"CMD;OK;extra;Reason=ready\r\n"])
    ok, parsed, raw = _recv_and_parse(handle, expected_cmd="NOPE")

    assert ok is False
    assert parsed[0] == "CMD"
    assert raw.startswith("CMD;")


def test_recv_and_parse_timeout_logs_and_returns_false():
    handle = make_handle(responses=[socket.timeout("timed out")])
    ok, parsed, raw = _recv_and_parse(handle)

    assert ok is False
    assert parsed is None
    assert raw is None
    assert any("timed out" in entry for entry in handle["log"])


def test_wps_export_html_builds_command_and_waits_for_success():
    handle = make_handle(responses=[b"HTML EXPORT;SUCCEEDED;Reason=done\r\n"])

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

    sent_command = handle["socket"].sent[0].decode()
    assert (
        sent_command
        == "HTML Export;summary=1;databytes=0;decode=0;frames=selected;"
        "frame range upper=2;frame range lower=1;layers=LE BB,LE BIS;file=out.html"
    )


def test_wps_export_html_rejects_invalid_summary():
    handle = make_handle(responses=[b"HTML EXPORT;SUCCEEDED;Reason=done\r\n"])

    with pytest.raises(ValueError, match="summary must be 0 or 1"):
        wps_export_html(handle, summary=2)


def test_wps_update_matter_keys_sends_expected_command():
    handle = make_handle(responses=[b"OK"])

    wps_update_matter_keys(handle, "0x1", ["0x2", "0x3"])

    sent_command = handle["socket"].sent[0].decode()
    assert sent_command == "Update Matter;matterkeys=0x1,0x2,0x3"


def test_wps_update_matter_keys_rejects_invalid_inputs():
    handle = make_handle(responses=[b"OK"])

    with pytest.raises(ValueError, match="source_node_id"):
        wps_update_matter_keys(handle, "1234", ["0x2"])

    with pytest.raises(ValueError, match="session_keys must be a list"):
        wps_update_matter_keys(handle, "0x1", "0x2")
