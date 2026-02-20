# Overview
The objective is to provide a set of helper functions for automation tasks using [Teledyne LeCroy's Frontline Wireless Protocol Suite](https://www.teledynelecroy.com/support/softwaredownload/psgdocuments.aspx?standardid=2&mseries=671) software that is used for wireless technology capture as well as logic and wired serial protocols. The philosophy is to keep the tools as simple as possible with a functional feel. Also internal state is exposed as much as possible to simplify modification and experimentation. Other repositories show how the code is used.

# Setup (dev)
The tests are run in CI with Python 3.14, so using Python 3.14 locally is recommended. Note that the tests use a TCP mock and don’t require the actual WPS software installed.

Create and activate a virtual environment, then install test dependencies:

```bash
uv venv
source .venv/bin/activate
uv pip install --upgrade pip
uv pip install -r requirements.txt
```

(On Windows PowerShell, activation is typically `.\.venv\Scripts\Activate.ps1`.)

# Running tests
Run the full test suite:

```bash
pytest
```

Run a subset (example):

```bash
pytest -k recv_and_parse -q
```

# Notes
Following [PEP-0008](https://peps.python.org/pep-0008/#package-and-module-names) naming for the package name using just undercase

# Receive retry overrides
The following helper functions support per-call socket receive retry overrides:

- `recv_retry_attempts=None`
- `recv_retry_sleep=None`

Supported functions:

- `wps_open_capture`
- `wps_close_capture`
- `wps_configure`
- `wps_start_record`
- `wps_stop_record`
- `wps_save_capture`
- `wps_get_available_streams_audio`
- `wps_add_bookmark`
- `wps_set_resolving_list`
- `wps_wireless_devices`
- `wps_send_command`

When omitted, each function falls back to the defaults configured on the `handle`
(`recv_retry_attempts`, `recv_retry_sleep`, and existing `sleep_time` fallback behavior).
