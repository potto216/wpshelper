# Test architecture and Mock TCP behavior

This test suite validates `wpshelper` without requiring a local installation of
Teledyne LeCroy Wireless Protocol Suite.

The core idea is to replace the real automation TCP server with a deterministic
in-process mock server (`MockAutomationSimulator`) so tests can verify:

- the exact command strings sent by helper functions,
- parser behavior for successful and failed responses,
- timeout and retry behavior,
- input validation and error handling.

## How the mock TCP server works

The mock lives in `tests/mock_tcp.py` as `MockAutomationSimulator`.

### 1) Server setup

When initialized, the simulator:

- creates a TCP socket on `127.0.0.1`,
- binds to port `0` (ephemeral/free port chosen by the OS),
- stores the resolved `(host, port)` in `self.address`,
- prepares a background thread (`_serve`) to emulate the automation server.

This means each test gets an isolated server endpoint and avoids hardcoded port
collisions.

### 2) Context-managed lifecycle

Most tests use:

```python
with MockAutomationSimulator(...) as simulator:
    handle = simulator.create_handle()
```

- `__enter__()` starts listening and spawns the background thread.
- `__exit__()` performs best-effort cleanup of client sockets, accepted server
  connection, and thread shutdown.

This keeps tests independent and prevents leaked sockets between tests.

### 3) The synthetic handle object

`create_handle()` opens a real client socket connected to the mock server and
returns a dict shaped like the production `wpshelper` handle:

- `socket`: connected socket object,
- `max_data_from_automation_server`: byte limit used by receive helpers,
- `sleep_time`, `max_wait_time`: timing controls used by polling loops,
- `log`: mutable list where timeout/debug messages are appended.

Because the handle uses a real socket, tests exercise the same send/receive code
paths used in production.

### 4) Deterministic response queues

The simulator takes two optional queues:

- `connect_responses`: bytes sent immediately after accepting a connection
  (useful when testing direct receive/parsing without sending a request first),
- `responses`: bytes sent one-by-one after each client `recv` event.

The server loop behavior is:

1. wait for one connection,
2. emit all `connect_responses` in order,
3. for each data payload received from client:
   - append payload bytes to `simulator.received`,
   - pop one entry from `responses`,
   - send it unless the entry is `None`.

Using `None` lets tests simulate "no response" / timeout scenarios while still
confirming that the command was transmitted.

### 5) Capturing outbound commands

Every payload sent by client code is collected in `simulator.received`. Tests
usually decode the first captured payload and compare it to an exact expected
command string.

This is how tests verify formatting details such as:

- command capitalization,
- argument ordering,
- separators (`;`, `,`),
- default field values.

## What the tests validate with this mock

`tests/test_wpshelper.py` uses the simulator to cover both happy paths and edge
cases across the API:

- `_recv_and_parse` success, mismatch, and timeout logging behavior,
- command builders (`wps_export_html`, `wps_update_matter_keys`,
  `wps_wireless_devices`, etc.),
- strict input validation via `ValueError` assertions,
- timeout escalation (`WPSTimeoutError`) for long waits,
- best-effort close/shutdown behavior that should not raise on timeout,
- filesystem-only helpers (`wps_find_installations`) with `tmp_path`.

## Why this approach is useful

- **Fast:** no external service startup, hardware, or GUI dependency.
- **Deterministic:** byte-for-byte scripted responses remove flakiness.
- **Realistic enough:** uses actual sockets and thread timing instead of fully
  stubbed function calls.
- **Focused:** isolates transport/protocol behavior from the vendor software.

## Typical debugging workflow when adding tests

1. Add expected server response bytes to `responses` or `connect_responses`.
2. Call the target helper with a handle from `create_handle()`.
3. Assert return values / exceptions.
4. Assert emitted command string from `simulator.received`.
5. For timeout behavior, omit response bytes or use `None` and assert log or
   raised timeout exception.

## Running the suite

From repository root:

```bash
pytest
```

Target only tests that use a specific helper (example):

```bash
pytest -k wireless_devices -q
```
