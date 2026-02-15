import os
import re
import socket
import time

class WPSTimeoutError(TimeoutError):
    """Custom exception for WPS command timeouts."""
    def __init__(self, message, handle=None):
        super().__init__(message)
        self.handle = handle


def wps_find_installations(
    base_dir=r"C:\\Program Files (x86)\\Teledyne LeCroy Wireless",
    show_log=False,
):
    """
    Find Wireless Protocol Suite installations.

    This scans for directories matching "Wireless Protocol Suite <version>" in
    the provided base directory and returns a summary of what was found.

    :param str base_dir: Base directory that contains WPS installs.
    :param bool show_log: If True, print log messages.
    :returns: Dict with installations list, latest info, and paths by version.
    :rtype: dict
    """
    log = []
    if not base_dir or not os.path.isdir(base_dir):
        log_entry = f"wps_find_installations: base_dir '{base_dir}' not found."
        log.append(log_entry)
        if show_log:
            print(log_entry)
        return {"installations": [], "latest": None, "paths_by_version": {}, "log": log}

    def _parse_version(dir_name):
        match = re.match(r"^Wireless Protocol Suite (?P<version>\d+(?:\.\d+)*)", dir_name)
        if not match:
            return None
        version = match.group("version")
        version_parts = tuple(int(part) for part in version.split("."))
        is_beta = "beta" in dir_name.lower()
        return version, version_parts, is_beta

    installations = []
    paths_by_version = {}

    for entry in os.listdir(base_dir):
        full_path = os.path.join(base_dir, entry)
        if not os.path.isdir(full_path):
            continue
        parsed = _parse_version(entry)
        if parsed is None:
            continue
        version, version_parts, is_beta = parsed
        installations.append(
            {
                "name": entry,
                "version": version,
                "path": full_path,
                "is_beta": is_beta,
                "version_parts": version_parts,
            }
        )
        paths_by_version.setdefault(version, []).append(full_path)

    installations.sort(key=lambda item: (item["version_parts"], not item["is_beta"]))

    latest = None
    if installations:
        latest_entry = max(
            installations,
            key=lambda item: (item["version_parts"], not item["is_beta"]),
        )
        latest = {
            "name": latest_entry["name"],
            "version": latest_entry["version"],
            "path": latest_entry["path"],
            "is_beta": latest_entry["is_beta"],
        }

    log_entry = f"wps_find_installations: found {len(installations)} installs."
    log.append(log_entry)
    if show_log:
        print(log_entry)

    for item in installations:
        item.pop("version_parts", None)

    return {
        "installations": installations,
        "latest": latest,
        "paths_by_version": paths_by_version,
        "log": log,
    }


def _recv_and_parse(
    handle,
    expected_cmd=None,
    expected_status=None,
    expected_reason=None,
    show_log=False,
    *,
    retry_attempts=None,
    retry_sleep=None,
    decode_errors="strict",
    context="",
):
    """Receive data from the socket, decode and split by ';'.

    If expected_cmd / expected_status / expected_reason are provided, this
    helper will return a tuple (ok, result_parse, raw_str) where `ok` is True
    when all provided expectations match, otherwise False.
    """
    s = handle["socket"]
    max_to_read = handle["max_data_from_automation_server"]

    try:
        if retry_attempts is None and retry_sleep is None:
            rcv_data = s.recv(max_to_read)
        else:
            rcv_data = _recv_with_retries(
                handle,
                max_to_read,
                retry_attempts=retry_attempts,
                retry_sleep=retry_sleep,
                show_log=show_log,
                context=context or "_recv_and_parse",
            )
    except (socket.timeout, TimeoutError) as e:
        log_entry = f"_recv_and_parse: Socket receive timed out: {e}"
        handle["log"].append(log_entry)
        if show_log:
            print(log_entry)
        return False, None, None

    result_str = rcv_data.decode(errors=decode_errors)
    result_parse = result_str.split(";")

    log_entry = f"_recv_and_parse: {result_str}"
    handle["log"].append(log_entry)
    if show_log:
        print(log_entry)

    ok = True
    if expected_cmd is not None and (len(result_parse) == 0 or result_parse[0] != expected_cmd):
        ok = False
    if expected_status is not None and (len(result_parse) < 2 or result_parse[1] != expected_status):
        ok = False
    if expected_reason is not None and (len(result_parse) < 4 or result_parse[3] != expected_reason):
        ok = False

    return ok, result_parse, result_str

def _recv_with_retries(handle, max_to_read=None, retry_attempts=None, retry_sleep=None, show_log=False, context=""):
    """Receive data from the socket with configurable retry attempts on timeout."""
    s = handle["socket"]
    if max_to_read is None:
        max_to_read = handle["max_data_from_automation_server"]

    retries = handle.get("recv_retry_attempts", 0) if retry_attempts is None else retry_attempts
    sleep_time = handle.get("recv_retry_sleep", handle.get("sleep_time", 1)) if retry_sleep is None else retry_sleep
    last_exc = None

    for attempt in range(retries + 1):
        try:
            return s.recv(max_to_read)
        except (socket.timeout, TimeoutError) as exc:
            last_exc = exc
            log_entry = (
                f"_recv_with_retries: timeout in {context or 'recv'} "
                f"(attempt {attempt + 1}/{retries + 1}): {exc}"
            )
            handle["log"].append(log_entry)
            if show_log:
                print(log_entry)
            if attempt < retries:
                time.sleep(sleep_time)

    raise last_exc


def _wait_for_command_result(
    handle,
    expected_cmd: str,
    *,
    expected_status: str = "SUCCEEDED",
    show_log: bool = False,
    context: str = "",
    retry_attempts=None,
    retry_sleep=None,
    decode_errors="strict",
):
    """Wait up to handle['max_wait_time'] for a specific command result.

    This is used for commands that can legitimately take longer than the socket
    timeout (e.g., Save Capture, exports). It polls recv until it sees a message
    whose command matches expected_cmd. If that message's status is FAILED, it
    raises RuntimeError. If it never arrives before max_wait_time, it raises
    WPSTimeoutError.

    :returns: (result_parse, result_str)
    """
    start_time = time.monotonic()
    max_wait = handle.get('max_wait_time', 60)

    while True:
        if time.monotonic() - start_time > max_wait:
            error_msg = (
                f"{context or expected_cmd}: Timeout waiting for '{expected_cmd} {expected_status}' "
                f"after {max_wait} seconds."
            )
            handle['log'].append(error_msg)
            if show_log:
                print(error_msg)
            raise WPSTimeoutError(error_msg, handle=handle)

        _, result_parse, result_str = _recv_and_parse(
            handle,
            show_log=show_log,
            retry_attempts=retry_attempts,
            retry_sleep=retry_sleep,
            decode_errors=decode_errors,
            context=context or expected_cmd,
        )

        # Socket timeout: keep waiting until max_wait_time.
        if result_parse is None:
            continue

        # Unexpected/async message: ignore and keep waiting.
        if len(result_parse) == 0 or result_parse[0] != expected_cmd:
            log_entry = f"{context or expected_cmd}: ignoring unexpected response: {result_str}"
            handle['log'].append(log_entry)
            if show_log:
                print(log_entry)
            continue

        status = result_parse[1] if len(result_parse) > 1 else None
        if status == expected_status:
            return result_parse, result_str
        if status == "FAILED":
            raise RuntimeError(f"{context or expected_cmd}: {result_str}")

        # Any other status: keep waiting.
        time.sleep(handle.get('sleep_time', 1))

def wps_open(
    tcp_ip="127.0.0.1",
    tcp_port=22901,
    max_to_read=1000,
    wps_executable_path=None,
    personality_key=None,
    sleep_time=1,
    max_wait_time=60,
    recv_retry_attempts=0,
    recv_retry_sleep=None,
    show_log=False,
):
    """
    Open a connection to the WPS automation server and start the FTS.

    :param str tcp_ip: IP address of the automation server.
    :param int tcp_port: Port of the automation server.
    :param int max_to_read: Maximum bytes to read from the socket at once.
    :param str wps_executable_path: Full path to the FTSAutoServer executable.
    :param str personality_key: Personality key for the hardware. Current valid values are "SODERA", "X240", "X500", "X500e","VIEW".
    :param int sleep_time: Seconds to sleep between polling attempts.
    :param int max_wait_time: Max seconds to wait before timing out.
    :param int recv_retry_attempts: Number of recv retries on timeout.
    :param float recv_retry_sleep: Seconds to sleep between recv retries (defaults to sleep_time).
    :param bool show_log: If True, print log messages.
    :returns: A dict handle containing socket, settings, and log.
    :rtype: dict
    :raises WPSTimeoutError: On startup/initialization timeout.
    :raises socket.error: On socket connection failure.
    """
    
    if wps_executable_path is None or not str(wps_executable_path):
        raise ValueError("wps_executable_path must be a non-empty string.")
    if personality_key is None or not str(personality_key):
        raise ValueError("personality_key must be a non-empty string.")
    elif personality_key not in ("SODERA", "X240", "X500", "X500e","VIEW"):
        raise ValueError("personality_key must be one of: 'SODERA', 'X240', 'X500', 'X500e', 'VIEW'.")

    handle={
        'max_data_from_automation_server':max_to_read,
        'tcp_ip':tcp_ip,
        'tcp_port':tcp_port,
        'sleep_time':sleep_time,
        'max_wait_time': max_wait_time,
        'recv_retry_attempts': recv_retry_attempts,
        'recv_retry_sleep': sleep_time if recv_retry_sleep is None else recv_retry_sleep,
    }
    handle['log']=[]
    MAX_TO_READ = handle['max_data_from_automation_server']
    handle['wps_executable_path']=wps_executable_path

    try:
        s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        # Use a socket timeout so higher-level timeouts cannot be blocked
        s.settimeout(handle['sleep_time'])
        s.connect((handle['tcp_ip'],handle['tcp_port']))
        handle['socket'] = s
        data=_recv_with_retries(handle, show_log=show_log, context="wps_open: initial recv")
        log_entry = f"wps_open: Trying connection. Receiving: {data}"
        handle['log'].append(log_entry)
        if show_log:
            print(log_entry)
    except socket.error as e:
        log_entry = f"wps_open: Socket connection failed: {e}"
        handle['log'].append(log_entry)
        if show_log:
            print(log_entry)
        raise  # Re-raise the socket error

    # Start Wireless Protocol Suite
    FTE_CMD="Start FTS"+";" + str(wps_executable_path) + ";" + personality_key
    send_data=FTE_CMD.encode(encoding='UTF-8',errors='strict')
    log_entry = f"wps_open: s1 sending: {send_data}"
    handle['log'].append(log_entry)
    if show_log:
        print(log_entry)
    s.send(send_data)

    # Wait to hear the start succeeded
    start_time = time.monotonic()
    is_done_waiting = False
    EXPECTED_COMMAND="START FTS"
    EXPECTED_STATUS="SUCCEEDED"

    while not is_done_waiting:
        if time.monotonic() - start_time > handle['max_wait_time']:
            error_msg = f"wps_open: Timeout waiting for '{EXPECTED_COMMAND} {EXPECTED_STATUS}' after {handle['max_wait_time']} seconds."
            handle['log'].append(error_msg)
            if show_log: print(error_msg)
            raise WPSTimeoutError(error_msg, handle=handle)

        ok, result_parse, result_str = _recv_and_parse(handle, EXPECTED_COMMAND, EXPECTED_STATUS, show_log=show_log)
        if ok:
            is_done_waiting=True
        else:
            log_entry = f"wps_open: Received data parsed to {result_parse}, which indicates startup is not complete. Still waiting for the command {EXPECTED_COMMAND} with a status of {EXPECTED_STATUS}."
            handle['log'].append(log_entry)
            if show_log:
                print(log_entry)
            time.sleep(handle['sleep_time'])  # Use configurable sleep time

    # Wait for FTS to be ready
    start_time = time.monotonic()
    is_done_waiting = False
    EXPECTED_COMMAND_INIT = "IS INITIALIZED"
    EXPECTED_STATUS_INIT = "SUCCEEDED"
    while not is_done_waiting:
        if time.monotonic() - start_time > handle['max_wait_time']:
            error_msg = f"wps_open: Timeout waiting for '{EXPECTED_COMMAND_INIT} {EXPECTED_STATUS_INIT}' after {handle['max_wait_time']} seconds."
            handle['log'].append(error_msg)
            if show_log: print(error_msg)
            raise WPSTimeoutError(error_msg, handle=handle)

        FTE_CMD="Is Initialized"
        send_data=FTE_CMD.encode(encoding='UTF-8',errors='strict')
        log_entry = f"wps_open: s2 sending: {send_data}"
        handle['log'].append(log_entry)
        if show_log:
            print(log_entry)
        s.send(send_data)

        ok, result_parse, result_str = _recv_and_parse(handle, EXPECTED_COMMAND_INIT, EXPECTED_STATUS_INIT, show_log=show_log)
        if ok:
            is_done_waiting=True
        else:
            log_entry = f"wps_open: Parse of received: {result_parse}. Not the desired result so still waiting.."
            handle['log'].append(log_entry)
            if show_log:
                print(log_entry)
            time.sleep(handle['sleep_time'])  # Use configurable sleep time
    return handle

def wps_configure(handle, personality_key, capture_technology, show_log=False):
    """
    Configure the capture settings in WPS before recording.

    :param dict handle: Connection handle returned by wps_open().
    :param str personality_key: Personality key for the hardware.
    :param str capture_technology: Capture technology string, e.g. "LE" or "BR/EDR".
    :param bool show_log: If True, print log messages.
    :returns: None
    :raises WPSTimeoutError: If configuration does not succeed before timeout.
    """    
    s = handle['socket']
    MAX_TO_READ = handle['max_data_from_automation_server']
    # Start Wireless Protocol Suite
    if "X240" in personality_key:
        log_entry = "wps_configure: The X240 requires that the capture technology is setup before running this function."
        handle['log'].append(log_entry)
        if show_log:
            print(log_entry)
        FTE_CMD="Config Settings;IOParameters;" + personality_key + ";analyze=inquiryprocess-off|pagingnoconn-off|nullsandpolls-off|emptyle-on|anonymousadv-on|meshadv-off|lecrcerrors=on;"
    else:
        FTE_CMD="Config Settings;IOParameters;" + personality_key + ";analyze=inquiryprocess-off|pagingnoconn-off|nullsandpolls-off|emptyle-on|anonymousadv-on|meshadv-off|lecrcerrors=on;" +  capture_technology

    send_data=FTE_CMD.encode(encoding='UTF-8',errors='strict')
    log_entry = f"wps_configure: sending: {send_data}"
    handle['log'].append(log_entry)
    if show_log:
        print(log_entry)
    s.send(send_data)

    # Wait to hear the start succeeded
    start_time = time.monotonic()
    is_done_waiting = False
    EXPECTED_COMMAND = "CONFIG SETTINGS"
    EXPECTED_STATUS = "SUCCEEDED"
    while not is_done_waiting:
        if time.monotonic() - start_time > handle['max_wait_time']:
            error_msg = f"wps_configure: Timeout waiting for '{EXPECTED_COMMAND} {EXPECTED_STATUS}' after {handle['max_wait_time']} seconds."
            handle['log'].append(error_msg)
            if show_log: print(error_msg)
            raise WPSTimeoutError(error_msg, handle=handle)

        ok, result_parse, result_str = _recv_and_parse(handle, EXPECTED_COMMAND, EXPECTED_STATUS, show_log=show_log)
        if ok:
            is_done_waiting=True
        else:
            log_entry = f"wps_configure: Parse of received: {result_parse}. Not the desired result so still waiting."
            handle['log'].append(log_entry)
            if show_log:
                print(log_entry)
            time.sleep(handle['sleep_time'])

def wps_start_record(handle, show_log=False):
    """
    Start recording on the WPS.

    :param dict handle: Connection handle returned by wps_open().
    :param bool show_log: If True, print the send/receive log.
    :returns: None
    """    
    s = handle['socket']
    MAX_TO_READ = handle['max_data_from_automation_server']
    # Start the recording
    FTE_CMD="Start Record"
    send_data=FTE_CMD.encode(encoding='UTF-8',errors='strict')
    log_entry = f"wps_start_record: sending: {send_data}"
    handle['log'].append(log_entry)
    if show_log:
        print(log_entry)
    s.send(send_data)
    data=_recv_with_retries(handle, MAX_TO_READ, show_log=show_log, context="wps_start_record")
    log_entry = f"wps_start_record: Receiving: {data}"
    handle['log'].append(log_entry)
    if show_log:
        print(log_entry)

def wps_stop_record(handle, show_log=False):
    """
    Stop recording on the WPS.

    :param dict handle: Connection handle returned by wps_open().
    :param bool show_log: If True, print the send/receive log.
    :returns: None
    """    
    s = handle['socket']
    MAX_TO_READ = handle['max_data_from_automation_server']
    # Stop Record
    FTE_CMD="Stop Record"
    send_data=FTE_CMD.encode(encoding='UTF-8',errors='strict')
    log_entry = f"wps_stop_record: sending: {send_data}"
    handle['log'].append(log_entry)
    if show_log:
        print(log_entry)
    s.send(send_data)

    # Stop can take longer than the socket timeout; wait up to max_wait_time.
    start_time = time.monotonic()
    expected_cmd = "STOP RECORD"
    expected_status = "SUCCEEDED"
    while True:
        if time.monotonic() - start_time > handle.get('max_wait_time', 60):
            error_msg = (
                f"wps_stop_record: Timeout waiting for '{expected_cmd} {expected_status}' "
                f"after {handle.get('max_wait_time', 60)} seconds."
            )
            handle['log'].append(error_msg)
            if show_log:
                print(error_msg)
            raise WPSTimeoutError(error_msg, handle=handle)

        ok, result_parse, result_str = _recv_and_parse(
            handle,
            expected_cmd=expected_cmd,
            expected_status=expected_status,
            show_log=show_log,
        )

        # Timeout in _recv_and_parse yields (False, None, None): keep waiting.
        if result_parse is None:
            continue

        # If it's the STOP RECORD response, either succeed or fail fast.
        if len(result_parse) >= 2 and result_parse[0] == expected_cmd:
            if ok:
                log_entry = f"wps_stop_record: receiving: {result_str}"
                handle['log'].append(log_entry)
                if show_log:
                    print(log_entry)
                return
            raise RuntimeError(f"wps_stop_record: Stop Record failed: {result_str}")

        # Unexpected/async message; keep waiting.
        log_entry = f"wps_stop_record: ignoring unexpected response: {result_str}"
        handle['log'].append(log_entry)
        if show_log:
            print(log_entry)
def wps_analyze_capture_start(handle, show_log=False, recv_retry_attempts=None, recv_retry_sleep=None):
    """
    Start analysis on the WPS and wait for the START ANALYZE success response.

    :param dict handle: Connection handle returned by wps_open().
    :param bool show_log: If True, print send/receive log.
    :param int recv_retry_attempts: Override handle recv retry attempts for this call.
    :param float recv_retry_sleep: Override handle recv retry sleep for this call.
    :returns: None
    :raises RuntimeError: If start analyze does not succeed.
    """
    s = handle['socket']

    # • Start Analyze
    FTE_CMD = "Start Analyze"
    send_data = FTE_CMD.encode(encoding='UTF-8', errors='strict')
    log_entry = f"wps_analyze_capture: sending: {send_data}"
    handle['log'].append(log_entry)
    s.send(send_data)

    ok, result_parse, result_str = _recv_and_parse(
        handle,
        "START ANALYZE",
        "SUCCEEDED",
        show_log=show_log,
        retry_attempts=recv_retry_attempts,
        retry_sleep=recv_retry_sleep,
        decode_errors="replace",
        context="wps_analyze_capture:start",
    )
    if not ok:
        log_entry = (
            f"wps_analyze_capture: ERROR failed to start analysis with a parsed value of: {result_parse}"
        )
        handle['log'].append(log_entry)
        raise RuntimeError(f"Failed to start analysis: {result_str}")


def wps_analyze_capture_stop(handle, show_log=False, recv_retry_attempts=None, recv_retry_sleep=None):
    """
    Wait for analysis completion, stop analysis, then wait for capture state and processing completion.

    This performs:
    - polling "IS ANALYZE COMPLETE" until Reason=analyze_complete=yes
    - sending "Stop Analyze"
    - polling "Query State" until CAPTURE STOPPED
    - polling "Is Processing Complete" until Reason=TRUE

    :param dict handle: Connection handle returned by wps_open().
    :param bool show_log: If True, print send/receive log.
    :param int recv_retry_attempts: Override handle recv retry attempts for this call.
    :param float recv_retry_sleep: Override handle recv retry sleep for this call.
    :returns: None
    :raises WPSTimeoutError: If any polling stage times out.
    """
    s = handle['socket']

    # • Is Analyze Complete
    start_time = time.monotonic()
    is_done_waiting = False
    EXPECTED_COMMAND_AC = "IS ANALYZE COMPLETE"
    EXPECTED_STATUS_AC = "SUCCEEDED"
    EXPECTED_REASON_AC = "Reason=analyze_complete=yes\r\n"
    while not is_done_waiting:
        if time.monotonic() - start_time > handle['max_wait_time']:
            error_msg = (
                f"wps_analyze_capture: Timeout waiting for '{EXPECTED_COMMAND_AC} {EXPECTED_STATUS_AC}' "
                f"with reason '{EXPECTED_REASON_AC}' after {handle['max_wait_time']} seconds."
            )
            handle['log'].append(error_msg)
            if show_log:
                print(error_msg)
            raise WPSTimeoutError(error_msg, handle=handle)

        FTE_CMD = "IS ANALYZE COMPLETE"
        send_data = FTE_CMD.encode(encoding='UTF-8', errors='strict')
        log_entry = f"wps_analyze_capture: sending: {send_data}"
        handle['log'].append(log_entry)
        s.send(send_data)

        ok, result_parse, _result_str = _recv_and_parse(
            handle,
            EXPECTED_COMMAND_AC,
            EXPECTED_STATUS_AC,
            EXPECTED_REASON_AC,
            show_log=show_log,
            retry_attempts=recv_retry_attempts,
            retry_sleep=recv_retry_sleep,
            decode_errors="replace",
            context="wps_analyze_capture:is_analyze_complete",
        )
        if ok:
            is_done_waiting = True
        else:
            log_entry = (
                f"wps_analyze_capture: Parse of received: {result_parse}. Not the desired result so still waiting."
            )
            handle['log'].append(log_entry)
            time.sleep(handle['sleep_time'])

    # • Stop Analyze
    FTE_CMD = "Stop Analyze"
    send_data = FTE_CMD.encode(encoding='UTF-8', errors='strict')
    log_entry = f"wps_analyze_capture: sending: {send_data}"
    handle['log'].append(log_entry)
    s.send(send_data)
    _ok, _parsed, _result_str = _recv_and_parse(
        handle,
        show_log=show_log,
        retry_attempts=recv_retry_attempts,
        retry_sleep=recv_retry_sleep,
        decode_errors="replace",
        context="wps_analyze_capture:stop_analyze",
    )

    # • Query State
    start_time = time.monotonic()
    is_done_waiting = False
    EXPECTED_COMMAND_QS = "QUERY STATE"
    EXPECTED_STATUS_QS = "SUCCEEDED"
    EXPECTED_REASON_QS1 = "Reason=CAPTURE STOPPED|CurrentState=CAPTURE STOPPED\r\n"
    EXPECTED_REASON_QS2 = "Reason=CAPTURE STOPPED|CurrentState=CAPTURE ACTIVE NO DATA\r\n"
    while not is_done_waiting:
        if time.monotonic() - start_time > handle['max_wait_time']:
            error_msg = (
                f"wps_analyze_capture: Timeout waiting for '{EXPECTED_COMMAND_QS} {EXPECTED_STATUS_QS}' "
                f"with reason '{EXPECTED_REASON_QS1}' or '{EXPECTED_REASON_QS2}' after {handle['max_wait_time']} seconds."
            )
            handle['log'].append(error_msg)
            if show_log:
                print(error_msg)
            raise WPSTimeoutError(error_msg, handle=handle)

        FTE_CMD = "Query State"
        send_data = FTE_CMD.encode(encoding='UTF-8', errors='strict')
        log_entry = f"wps_analyze_capture: sending: {send_data}"
        s.send(send_data)

        ok, result_parse, _result_str = _recv_and_parse(
            handle,
            EXPECTED_COMMAND_QS,
            EXPECTED_STATUS_QS,
            show_log=show_log,
            retry_attempts=recv_retry_attempts,
            retry_sleep=recv_retry_sleep,
            decode_errors="replace",
            context="wps_analyze_capture:query_state",
        )
        if ok and len(result_parse) > 3 and (
            result_parse[3] == EXPECTED_REASON_QS1 or result_parse[3] == EXPECTED_REASON_QS2
        ):
            is_done_waiting = True
        else:
            log_entry = (
                f"wps_analyze_capture: Parse of received: {result_parse}. Not the desired result so still waiting."
            )
            handle['log'].append(log_entry)
            time.sleep(handle['sleep_time'])

    # • Is Processing Complete
    start_time = time.monotonic()
    is_done_waiting = False
    EXPECTED_COMMAND_PC = "IS PROCESSING COMPLETE"
    EXPECTED_STATUS_PC = "SUCCEEDED"
    EXPECTED_REASON_PC = "Reason=TRUE\r\n"
    while not is_done_waiting:
        if time.monotonic() - start_time > handle['max_wait_time']:
            error_msg = (
                f"wps_analyze_capture: Timeout waiting for '{EXPECTED_COMMAND_PC} {EXPECTED_STATUS_PC}' "
                f"with reason '{EXPECTED_REASON_PC}' after {handle['max_wait_time']} seconds."
            )
            handle['log'].append(error_msg)
            if show_log:
                print(error_msg)
            raise WPSTimeoutError(error_msg, handle=handle)

        FTE_CMD = "Is Processing Complete"
        send_data = FTE_CMD.encode(encoding='UTF-8', errors='strict')
        log_entry = f"wps_analyze_capture: sending: {send_data}"
        handle['log'].append(log_entry)
        s.send(send_data)

        ok, result_parse, _result_str = _recv_and_parse(
            handle,
            EXPECTED_COMMAND_PC,
            EXPECTED_STATUS_PC,
            EXPECTED_REASON_PC,
            show_log=show_log,
            retry_attempts=recv_retry_attempts,
            retry_sleep=recv_retry_sleep,
            decode_errors="replace",
            context="wps_analyze_capture:is_processing_complete",
        )
        if ok:
            is_done_waiting = True
        else:
            log_entry = (
                f"wps_analyze_capture: Parse of received: {result_parse}. Not the desired result so still waiting."
            )
            handle['log'].append(log_entry)
            time.sleep(handle['sleep_time'])

def wps_analyze_capture(handle, show_log=False, recv_retry_attempts=None, recv_retry_sleep=None):
    """
    Analyze the capture on the WPS (start, poll until complete, stop).

    :param dict handle: Connection handle returned by wps_open().
    :param bool show_log: If True, print send/receive log.
    :param int recv_retry_attempts: Override handle recv retry attempts for this call.
    :param float recv_retry_sleep: Override handle recv retry sleep for this call.
    :returns: None
    :raises WPSTimeoutError: If any polling stage times out.
    """
    wps_analyze_capture_start(
        handle,
        show_log=show_log,
        recv_retry_attempts=recv_retry_attempts,
        recv_retry_sleep=recv_retry_sleep,
    )
    wps_analyze_capture_stop(
        handle,
        show_log=show_log,
        recv_retry_attempts=recv_retry_attempts,
        recv_retry_sleep=recv_retry_sleep,
    )

def wps_open_capture(handle, capture_absolute_filename, show_log=False):
    """
    Open an existing capture file in WPS.

    :param dict handle: Connection handle returned by wps_open().
    :param str capture_absolute_filename: Path to the capture file.
    :param bool show_log: If True, print send/receive log.
    :returns: None
    :raises WPSTimeoutError: If final confirmation does not arrive in time.
    """    
    s = handle['socket']
    MAX_TO_READ = handle['max_data_from_automation_server']

    # • Open Capture File
    FTE_CMD=r"Open Capture File;" + str(capture_absolute_filename) + r";notify=1"
    send_data=FTE_CMD.encode(encoding='UTF-8',errors='strict')
    log_entry = f"wps_open_capture: sending: {send_data}"
    handle['log'].append(log_entry)
    if show_log:
        print(log_entry)
    s.send(send_data)

    # Opening large captures can take longer than the socket timeout.
    # Keep polling until we see the final "OPEN CAPTURE FILE;SUCCEEDED" response
    # (ignoring interim notifications like Reason=yes), or until max_wait_time.
    start_time = time.monotonic()
    expected_cmd = "OPEN CAPTURE FILE"
    max_wait = handle.get('max_wait_time', 60)

    while True:
        if time.monotonic() - start_time > max_wait:
            error_msg = (
                f"wps_open_capture: Timeout waiting for '{expected_cmd} SUCCEEDED' "
                f"after {max_wait} seconds."
            )
            handle['log'].append(error_msg)
            if show_log:
                print(error_msg)
            raise WPSTimeoutError(error_msg, handle=handle)

        _, result_parse, result_str = _recv_and_parse(handle, show_log=show_log)

        # Socket timeout: keep waiting until max_wait_time.
        if result_parse is None:
            continue

        # Unexpected/async message: ignore and keep waiting.
        if len(result_parse) == 0 or result_parse[0] != expected_cmd:
            log_entry = f"wps_open_capture: ignoring unexpected response: {result_str}"
            handle['log'].append(log_entry)
            if show_log:
                print(log_entry)
            continue

        status = result_parse[1] if len(result_parse) > 1 else None
        if status == "FAILED":
            raise RuntimeError(f"wps_open_capture: {result_str}")
        if status != "SUCCEEDED":
            time.sleep(handle.get('sleep_time', 1))
            continue

        reason_field = result_parse[3] if len(result_parse) > 3 else ""
        if isinstance(reason_field, str) and "reason=yes" in reason_field.lower():
            time.sleep(handle.get('sleep_time', 1) / 2)
            continue

        return


def wps_save_capture(handle, capture_absolute_filename, show_log=False):
    """
    Save the current capture to disk.

    :param dict handle: Connection handle returned by wps_open().
    :param str capture_absolute_filename: Path where to save the capture.
    :param bool show_log: If True, print send/receive log.
    :returns: None
    """    
    s = handle['socket']
    MAX_TO_READ = handle['max_data_from_automation_server']

    # • Save Capture – Wait until status has been reported.
    FTE_CMD="Save Capture;" + str(capture_absolute_filename)
    send_data=FTE_CMD.encode(encoding='UTF-8',errors='strict')
    log_entry = f"wps_save_capture: sending: {send_data}"
    handle['log'].append(log_entry)
    if show_log:
        print(log_entry)
    s.send(send_data)

    _parsed, result_str = _wait_for_command_result(
        handle,
        expected_cmd="SAVE CAPTURE",
        expected_status="SUCCEEDED",
        show_log=show_log,
        context="wps_save_capture",
    )
    log_entry = f"wps_save_capture: {result_str}"
    handle['log'].append(log_entry)
    if show_log:
        print(log_entry)


def wps_close_capture(handle, capture_absolute_filename=None, show_log=False):
    """
    Close the current capture file.

    Command format:
    "Close Capture File;<capture file path>"

    If the capture file path is omitted, any changes to the open file are discarded.
    If provided, the file cannot be overwritten.

    Response format:
    "CLOSE CAPTURE FILE ;<status>;<timestamp>;[<reason>]"
    (A reason is supplied only for FAILED status.)
    """
    s = handle['socket']
    MAX_TO_READ = handle['max_data_from_automation_server']

    FTE_CMD = "Close Capture File"
    if capture_absolute_filename is not None and str(capture_absolute_filename) != "":
        FTE_CMD = f"{FTE_CMD};{capture_absolute_filename}"
    send_data = FTE_CMD.encode(encoding='UTF-8', errors='strict')
    log_entry = f"wps_close_capture: sending: {send_data}"
    handle['log'].append(log_entry)
    if show_log:
        print(log_entry)
    s.send(send_data)

    _parsed, result_str = _wait_for_command_result(
        handle,
        expected_cmd="CLOSE CAPTURE FILE",
        expected_status="SUCCEEDED",
        show_log=show_log,
        context="wps_close_capture",
    )
    log_entry = f"wps_close_capture: {result_str}"
    handle['log'].append(log_entry)
    if show_log:
        print(log_entry)

def wps_export_html(
        handle,
        html_absolute_filename=None,
        show_log=False,
        recv_retry_attempts=None,
        recv_retry_sleep=None,
        *,
        summary=0,
        databytes=1,
        decode=None,
        frames='all',
        frame_range_upper=None,
        frame_range_lower=None,
        layers=None):
    """
    Export capture data as HTML.

    Command format (sent to the analyzer):
    "HTML Export;summary=<summary>;databytes=<bytes>;decode=<decode>;[frames=<frames>;]"
    "[frame range upper=<frame number>;][frame range lower=<frame number>;]"
    "[layers=<layer1>,<layer2>,...;]file=<export path>"

    Notes:
    - This can take considerable time to generate the HTML.
    - If no file is specified, the analyzer will generate a default filename in its log directory.
    - The 'layers' parameter can be a string (single layer) or a list/tuple of strings. By default, all layers are included.

    Parameter details (matches WPS "HTML Export" command behavior):
    - summary:
        - 0: do not include summary (default)
        - 1: include summary
    - databytes:
        - 0: do not include data bytes
        - 1: include data bytes (default)
    - decode:
        - 0: do not include decode
        - 1: include decode
        - None: choose a default based on databytes (defaults to 1 when databytes=1, else 0)
    - frames:
        - 'all': export all frames (default). Any frame range parameters are ignored by the analyzer.
        - 'selected': export only frames within the selected range. If frame ranges are not provided,
          the analyzer defaults lower to 0 and upper to the highest frame.
    - frame_range_lower / frame_range_upper:
        Valid frame numbers are 0 up to the highest frame. Only meaningful when frames='selected'.
    - layers:
        Limit export to specific layers. Provide either:
        - a comma-separated string of layer names (no extra spaces), e.g. "LE BB,LE BIS", or
        - a list/tuple of layer name strings, e.g. ["LE BB", "LE BIS"]
        If omitted/None, all layers are exported.

    :param dict handle: Connection handle returned by wps_open().
    :param str html_absolute_filename: Output HTML file path (optional). If only a filename is
        provided, the analyzer prepends its configured log directory.
    :param bool show_log: If True, print send/receive log.
    :param int recv_retry_attempts: Override handle recv retry attempts for this call.
    :param float recv_retry_sleep: Override handle recv retry sleep for this call.

    :param int summary: 0/1 (see above).
    :param int databytes: 0/1 (see above).
    :param int|None decode: 0/1/None (see above).
    :param str frames: "all" or "selected".
    :param int|None frame_range_upper: Upper frame number when frames="selected".
    :param int|None frame_range_lower: Lower frame number when frames="selected".
    :param str|list|tuple|None layers: Layer filter (see above).

    :returns: None
    :raises ValueError: On invalid argument values.
    :raises WPSTimeoutError: If the command does not complete before handle['max_wait_time'].
    :raises RuntimeError: If the analyzer reports FAILED.
    """ 
    if not isinstance(handle, dict) or "socket" not in handle:
        raise ValueError("Invalid handle provided. Must be a dict returned by wps_open().")
    
    s = handle['socket']
    MAX_TO_READ = handle['max_data_from_automation_server']

    if summary not in (0, 1):
        raise ValueError("summary must be 0 or 1")
    if databytes not in (0, 1):
        raise ValueError("databytes must be 0 or 1")
    if decode is None:
        decode = 1 if databytes == 1 else 0
    if decode not in (0, 1):
        raise ValueError("decode must be 0 or 1")

    if frames is None:
        frames = 'all'
    if frames not in ('all', 'selected'):
        raise ValueError("frames must be 'all' or 'selected'")

    def _format_layers(value):
        if value is None:
            return None
        if isinstance(value, str):
            return value
        if isinstance(value, (list, tuple)):
            parts = []
            for item in value:
                if not isinstance(item, str) or not item:
                    raise ValueError("layers must be a string or a list/tuple of non-empty strings")
                parts.append(item)
            return ",".join(parts)
        raise ValueError("layers must be a string or a list/tuple of strings")

    cmd_parts = [
        "HTML Export",
        f"summary={summary}",
        f"databytes={databytes}",
        f"decode={decode}",
    ]

    # Only include frames if it's non-default, per docs.
    if frames != 'all':
        cmd_parts.append(f"frames={frames}")

    if frame_range_upper is not None:
        cmd_parts.append(f"frame range upper={frame_range_upper}")
    if frame_range_lower is not None:
        cmd_parts.append(f"frame range lower={frame_range_lower}")

    layers_str = _format_layers(layers)
    if layers_str:
        cmd_parts.append(f"layers={layers_str}")

    if html_absolute_filename is not None and str(html_absolute_filename) != "":
        cmd_parts.append(f"file={html_absolute_filename}")

    FTE_CMD = ";".join(cmd_parts)

    send_data = FTE_CMD.encode(encoding='UTF-8', errors='strict')
    log_entry = f"wps_export_html: sending: {send_data}"
    handle['log'].append(log_entry)
    if show_log:
        print(log_entry)
    s.send(send_data)

    # Wait until status has been reported.
    start_time = time.monotonic()
    EXPECTED_COMMAND = "HTML EXPORT"
    while True:
        if time.monotonic() - start_time > handle['max_wait_time']:
            error_msg = (
                f"wps_export_html: Timeout waiting for '{EXPECTED_COMMAND} SUCCEEDED' "
                f"after {handle['max_wait_time']} seconds."
            )
            handle['log'].append(error_msg)
            if show_log:
                print(error_msg)
            raise WPSTimeoutError(error_msg, handle=handle)

        ok, result_parse, result_str = _recv_and_parse(
            handle,
            expected_cmd=EXPECTED_COMMAND,
            show_log=show_log,
            retry_attempts=recv_retry_attempts,
            retry_sleep=recv_retry_sleep,
            decode_errors="replace",
            context="wps_export_html",
        )
        if not ok:
            time.sleep(handle['sleep_time'])
            continue

        status = result_parse[1] if result_parse and len(result_parse) > 1 else None
        if status == "SUCCEEDED":
            return
        if status == "FAILED":
            reason = result_parse[3] if result_parse and len(result_parse) > 3 else result_str
            raise RuntimeError(f"HTML Export failed: {reason}")

        # Unknown/intermediate status; keep waiting.
        time.sleep(handle['sleep_time'])

def wps_export_pcapng(
    handle,
    pcapng_absolute_filename,
    tech='LE',
    mode=0,
    show_log=False,
    recv_retry_attempts=None,
    recv_retry_sleep=None,
):
    """
    Export capture data as PCAPNG.

    :param dict handle: Connection handle returned by wps_open().
    :param str pcapng_absolute_filename: Output PCAPNG file path.
    :param str tech: Technology filter [Classic, LE, 80211, WPAN] (default 'LE').
    :param int mode: Mode parameter (default 0).
    :param bool show_log: If True, print send/receive log.
    :param int recv_retry_attempts: Override handle recv retry attempts for this call.
    :param float recv_retry_sleep: Override handle recv retry sleep for this call.
    :returns: None
    """    
    s = handle['socket']
    MAX_TO_READ = handle['max_data_from_automation_server']
    # Save Capture – Wait until status has been reported.
    FTE_CMD = f"PCAPNG Export;file={pcapng_absolute_filename};tech={tech};mode={mode}"
    send_data = FTE_CMD.encode(encoding='UTF-8', errors='strict')
    log_entry = f"wps_export_pcapng_du: sending: {send_data}"
    handle['log'].append(log_entry)
    if show_log:
        print(log_entry)

    s.send(send_data)

    _parsed, result_str = _wait_for_command_result(
        handle,
        expected_cmd="PCAPNG EXPORT",
        expected_status="SUCCEEDED",
        show_log=show_log,
        context="wps_export_pcapng",
        retry_attempts=recv_retry_attempts,
        retry_sleep=recv_retry_sleep,
        decode_errors="replace",
    )
    log_entry = f"wps_export_pcapng_du: {result_str}"
    handle['log'].append(log_entry)
    if show_log:
        print(log_entry)

def wps_export_spectrum(
    handle,
    spectrum_absolute_filename,
    show_log=False,
    recv_retry_attempts=None,
    recv_retry_sleep=None,
):
    """
    Export spectrum data from the capture.

    :param dict handle: Connection handle returned by wps_open().
    :param str spectrum_absolute_filename: Output spectrum file path.
    :param bool show_log: If True, print send/receive log.
    :param int recv_retry_attempts: Override handle recv retry attempts for this call.
    :param float recv_retry_sleep: Override handle recv retry sleep for this call.
    :returns: None
    """    
    s = handle['socket']
    MAX_TO_READ = handle['max_data_from_automation_server']
    # • Save Capture – Wait until status has been reported.
    FTE_CMD="Spectrum Export;file=" + str(spectrum_absolute_filename)
    send_data=FTE_CMD.encode(encoding='UTF-8',errors='strict')
    log_entry = f"wps_export_spectrum: sending: {send_data}"
    handle['log'].append(log_entry)
    if show_log:
        print(log_entry)
    s.send(send_data)

    _parsed, result_str = _wait_for_command_result(
        handle,
        expected_cmd="SPECTRUM EXPORT",
        expected_status="SUCCEEDED",
        show_log=show_log,
        context="wps_export_spectrum",
        retry_attempts=recv_retry_attempts,
        retry_sleep=recv_retry_sleep,
        decode_errors="replace",
    )
    log_entry = f"wps_export_spectrum: {result_str}"
    handle['log'].append(log_entry)
    if show_log:
        print(log_entry)

def wps_get_available_streams_audio(handle,parameters="No", show_log=False):
    """
    Query available audio streams in the capture.

    :param dict handle: Connection handle returned by wps_open().
    :param str parameters: Parameters string for the plugin (default "No").
    :param bool show_log: If True, print send/receive log.
    :returns: Raw response bytes from WPS.
    :rtype: bytes
    """    
    s = handle['socket']
    MAX_TO_READ = handle['max_data_from_automation_server']

    # • Save Capture – Wait until status has been reported.
    FTE_CMD=f"Plugin Command;Plugin Name=Audio Expert;Command=Get Available Streams;Parameters={parameters}"
    send_data=FTE_CMD.encode(encoding='UTF-8',errors='strict')
    log_entry = f"wps_get_available_streams_audio: sending: {send_data}"
    handle['log'].append(log_entry)
    if show_log:
        print(log_entry)

    s.send(send_data)
    data=_recv_with_retries(handle, MAX_TO_READ, show_log=show_log, context="wps_get_available_streams_audio")
    log_entry = f"wps_get_available_streams_audio: {data}"
    handle['log'].append(log_entry)
    if show_log:
        print(log_entry)

    return data

# This exports audio data from a capture
def wps_export_audio(
    handle,
    audio_absolute_filename,
    audio_streams="1",
    audio_requestTypes="CSV&WAV",
    audio_time="all",
    show_log=False,
    recv_retry_attempts=None,
    recv_retry_sleep=None,
):
    """
    Export audio data from the capture.

    :param dict handle: Connection handle returned by wps_open().
    :param str audio_absolute_filename: Output audio file path.
    :param str audio_streams: Streams to export (default "1").
    :param str audio_requestTypes: Request types (default "CSV&WAV").
    :param str audio_time: Time range (default "all").
    :param bool show_log: If True, print send/receive log.
    :param int recv_retry_attempts: Override handle recv retry attempts for this call.
    :param float recv_retry_sleep: Override handle recv retry sleep for this call.
    :returns: None
    """    
    s = handle['socket']
    MAX_TO_READ = handle['max_data_from_automation_server']

    # • Save Capture – Wait until status has been reported.
    FTE_CMD=f"Plugin Command;Plugin Name=Audio Expert;Command=AES Export;Parameters=streams={audio_streams},requestTypes={audio_requestTypes},time={audio_time},file={audio_absolute_filename}"
    send_data=FTE_CMD.encode(encoding='UTF-8',errors='strict')
    log_entry = f"wps_export_audio: sending: {send_data}"
    handle['log'].append(log_entry)
    if show_log:
        print(log_entry)

    s.send(send_data)

    _parsed, result_str = _wait_for_command_result(
        handle,
        expected_cmd="PLUGIN COMMAND",
        expected_status="SUCCEEDED",
        show_log=show_log,
        context="wps_export_audio",
        retry_attempts=recv_retry_attempts,
        retry_sleep=recv_retry_sleep,
        decode_errors="replace",
    )
    log_entry = f"wps_export_audio: {result_str}"
    handle['log'].append(log_entry)
    if show_log:
        print(log_entry)

# Add a Bookmark
# Example values
# bookmark_text = 'le collect'
# bookmark_frame = 1
def wps_add_bookmark(handle, bookmark_frame, bookmark_text, show_log=False):
    """
    Add a bookmark to the capture.

    :param dict handle: Connection handle returned by wps_open().
    :param int bookmark_frame: Frame index for the bookmark.
    :param str bookmark_text: Text for the bookmark.
    :param bool show_log: If True, print send/receive log.
    :returns: None
    """    
    s = handle['socket']
    MAX_TO_READ = handle['max_data_from_automation_server']

    FTE_CMD=f"Add Bookmark;string={bookmark_text};frame={bookmark_frame}"
    send_data=FTE_CMD.encode(encoding='UTF-8',errors='strict')
    log_entry = f"wps_add_bookmark: sending: {send_data}"
    handle['log'].append(log_entry)
    if show_log:
        print(log_entry)

    s.send(send_data)

    _parsed, result_str = _wait_for_command_result(
        handle,
        expected_cmd="ADD BOOKMARK",
        expected_status="SUCCEEDED",
        show_log=show_log,
        context="wps_add_bookmark",
    )
    log_entry = f"wps_add_bookmark: {result_str}"
    handle['log'].append(log_entry)
    if show_log:
        print(log_entry)

# Set Resolving List
def wps_set_resolving_list(handle, address_list=None, show_log=False):
    """
    Set the resolving list for BR/EDR device address resolution.

    Command format:
    "Set Resolving List;<address list>"

    The address list can be:
    - A comma-separated list of BD_ADDR values (e.g., "0x001122334455,0xAABBCCDDEEFF")
    - An empty list to clear the resolving list.

    :param dict handle: Connection handle returned by wps_open().
    :param list|tuple|str|None address_list: BD_ADDR list or comma-separated string. Use None/""/[]
        to clear the list.
    :param bool show_log: If True, print send/receive log.
    :returns: Reason string from the analyzer response.
    :raises ValueError: On invalid handle or address list values.
    :raises WPSTimeoutError: If the command does not complete before handle['max_wait_time'].
    """
    if not isinstance(handle, dict) or "socket" not in handle:
        raise ValueError("Invalid handle provided. Must be a dict returned by wps_open().")

    def _normalize_addresses(value):
        if value is None:
            return []
        if isinstance(value, str):
            if value.strip() == "":
                return []
            parts = [part.strip() for part in value.split(",") if part.strip() != ""]
            return parts
        if isinstance(value, (list, tuple)):
            return list(value)
        raise ValueError("address_list must be a list, tuple, comma-separated string, or None.")

    addresses = _normalize_addresses(address_list)
    addr_pattern = re.compile(r"^0x[0-9A-Fa-f]{12}$")
    for addr in addresses:
        if not isinstance(addr, str) or not addr_pattern.match(addr):
            raise ValueError("Each BD_ADDR must be a hex string like '0x001122334455'.")

    address_field = ",".join(addresses)
    FTE_CMD = f"Set Resolving List;{address_field}"
    send_data = FTE_CMD.encode(encoding='UTF-8', errors='strict')
    log_entry = f"wps_set_resolving_list: sending: {send_data}"
    handle['log'].append(log_entry)
    if show_log:
        print(log_entry)

    handle['socket'].send(send_data)

    start_time = time.monotonic()
    expected_cmd = "SET RESOLVING LIST"
    max_wait = handle.get('max_wait_time', 60)

    while True:
        if time.monotonic() - start_time > max_wait:
            error_msg = (
                f"wps_set_resolving_list: Timeout waiting for '{expected_cmd}' "
                f"after {max_wait} seconds."
            )
            handle['log'].append(error_msg)
            if show_log:
                print(error_msg)
            raise WPSTimeoutError(error_msg, handle=handle)

        _, result_parse, result_str = _recv_and_parse(handle, show_log=show_log)

        if result_parse is None:
            continue

        if len(result_parse) == 0 or result_parse[0] != expected_cmd:
            log_entry = f"wps_set_resolving_list: ignoring unexpected response: {result_str}"
            handle['log'].append(log_entry)
            if show_log:
                print(log_entry)
            continue

        status = result_parse[1] if len(result_parse) > 1 else None
        reason = result_parse[3] if len(result_parse) > 3 else ""
        log_entry = f"wps_set_resolving_list: {result_str}"
        handle['log'].append(log_entry)
        if show_log:
            print(log_entry)

        if status in ("SUCCEEDED", "FAILED"):
            return reason

        time.sleep(handle.get('sleep_time', 1))

def wps_wireless_devices(handle, action, action_parameters=None, show_log=False):
    """
    Send a Wireless Devices command and return the response reason.

    Command format:
    "Wireless Devices;<action>;<action parameters>"

    Valid actions and parameters:
    - browse: type=<bluetooth|wifi>
    - detail: type=<bluetooth|wifi>;address=<device address>
    - select: type=<bluetooth|wifi>;address=<device address|all>;select=<yes|no>;favorite=<yes|no>
    - add: address=<device address>;type=<bluetooth|wifi>;lerandom=<yes|no>;irk=<device IRK>;
        select=<yes|no>;favorite=<yes|no>
    - nickname: address=<device address>;type=<bluetooth|wifi>;nickname="<nickname>"
    - delete: address=<device address>;type=<bluetooth|wifi>

    :param dict handle: Connection handle returned by wps_open().
    :param str action: Wireless Devices action (browse, detail, select, add, nickname, delete).
    :param dict|list|tuple|str|None action_parameters: Parameters to append after the action.
        When a dict is provided, parameters are formatted as key=value pairs joined by ";".
        When a list/tuple is provided, entries may be "key=value" strings or (key, value) pairs.
    :param bool show_log: If True, print send/receive log.
    :returns: Reason string from the analyzer response, or "" if not supplied.
    :raises ValueError: On invalid handle, action, or parameters.
    :raises WPSTimeoutError: If the command does not complete before handle['max_wait_time'].
    """
    if not isinstance(handle, dict) or "socket" not in handle:
        raise ValueError("Invalid handle provided. Must be a dict returned by wps_open().")
    if not isinstance(action, str) or not action.strip():
        raise ValueError("action must be a non-empty string.")

    def _format_params(params):
        if params is None:
            return ""
        if isinstance(params, str):
            return params.strip()
        if isinstance(params, dict):
            return ";".join(f"{key}={value}" for key, value in params.items())
        if isinstance(params, (list, tuple)):
            formatted = []
            for item in params:
                if isinstance(item, str):
                    formatted.append(item)
                elif isinstance(item, (list, tuple)) and len(item) == 2:
                    formatted.append(f"{item[0]}={item[1]}")
                else:
                    raise ValueError(
                        "action_parameters list entries must be 'key=value' strings or (key, value) pairs."
                    )
            return ";".join(formatted)
        raise ValueError("action_parameters must be a dict, list/tuple, string, or None.")

    param_text = _format_params(action_parameters)
    if action.strip().lower() == "select" and action_parameters is not None:
        address_pattern = re.compile(r"^[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5}$")
        if isinstance(action_parameters, dict):
            address_value = action_parameters.get("address")
            select_value = action_parameters.get("select")
            favorite_value = action_parameters.get("favorite")
        else:
            address_value = None
            select_value = None
            favorite_value = None
            for entry in param_text.split(";") if param_text else []:
                if "=" not in entry:
                    continue
                key, value = entry.split("=", 1)
                key = key.strip()
                if key == "address":
                    address_value = value
                elif key == "select":
                    select_value = value
                elif key == "favorite":
                    favorite_value = value

        if address_value is not None and address_value != "all" and not address_pattern.match(address_value):
            raise ValueError("select action address must be a device address or 'all'.")
        if select_value is not None and select_value not in {"yes", "no"}:
            raise ValueError("select action select value must be 'yes' or 'no'.")
        if favorite_value is not None and favorite_value not in {"yes", "no"}:
            raise ValueError("select action favorite value must be 'yes' or 'no'.")
    FTE_CMD = f"Wireless Devices;{action.strip()}"
    if param_text:
        FTE_CMD = f"{FTE_CMD};{param_text}"

    send_data = FTE_CMD.encode(encoding='UTF-8', errors='strict')
    log_entry = f"wps_wireless_devices: sending: {send_data}"
    handle['log'].append(log_entry)
    if show_log:
        print(log_entry)

    handle['socket'].send(send_data)

    start_time = time.monotonic()
    expected_cmd = "WIRELESS DEVICES"
    max_wait = handle.get('max_wait_time', 60)

    while True:
        if time.monotonic() - start_time > max_wait:
            error_msg = (
                f"wps_wireless_devices: Timeout waiting for '{expected_cmd}' "
                f"after {max_wait} seconds."
            )
            handle['log'].append(error_msg)
            if show_log:
                print(error_msg)
            raise WPSTimeoutError(error_msg, handle=handle)

        _, result_parse, result_str = _recv_and_parse(handle, show_log=show_log)

        if result_parse is None:
            continue

        if len(result_parse) == 0 or result_parse[0] != expected_cmd:
            log_entry = f"wps_wireless_devices: ignoring unexpected response: {result_str}"
            handle['log'].append(log_entry)
            if show_log:
                print(log_entry)
            continue

        status = result_parse[1] if len(result_parse) > 1 else None
        reason = result_parse[2] if len(result_parse) > 3 else ""
        log_entry = f"wps_wireless_devices: {result_str}"
        handle['log'].append(log_entry)
        if show_log:
            print(log_entry)

        if status in ("SUCCEEDED", "FAILED"):
            return reason

        time.sleep(handle.get('sleep_time', 1))

# This is used to send a general command to the WPS
def wps_send_command(handle, full_command, show_log=False):
    """
    Send a raw FTE command to WPS.

    :param dict handle: Connection handle returned by wps_open().
    :param str full_command: The complete FTE command string.
    :param bool show_log: If True, print send/receive log.
    :returns: None
    """    
    s = handle['socket']
    MAX_TO_READ = handle['max_data_from_automation_server']
    # Start the recording
    FTE_CMD=full_command
    send_data=FTE_CMD.encode(encoding='UTF-8',errors='strict')
    log_entry = f"wps_send_command: sending: {send_data}"
    handle['log'].append(log_entry)
    if show_log:
        print(log_entry)

    s.send(send_data)
    data=_recv_with_retries(handle, MAX_TO_READ, show_log=show_log, context="wps_send_command")
    log_entry = f"wps_send_command: Receiving: {data}"
    handle['log'].append(log_entry)
    if show_log:
        print(log_entry)

def wps_close(handle, show_log=False, recv_retry_attempts=None, recv_retry_sleep=None):
    """
    Close the connection and stop the FTS.

    :param dict handle: Connection handle returned by wps_open().
    :param bool show_log: If True, print send/receive log.
    :param int recv_retry_attempts: Override handle recv retry attempts for this call.
    :param float recv_retry_sleep: Override handle recv retry sleep for this call.
    :returns: None
    """    
    s = handle['socket']
    MAX_TO_READ = handle['max_data_from_automation_server']

    FTE_CMD="Stop FTS"
    send_data=FTE_CMD.encode(encoding='UTF-8',errors='strict')
    log_entry = f"wps_close: sending: {send_data}"
    handle['log'].append(log_entry)
    if show_log:
        print(log_entry)

    s.send(send_data)

    # Best-effort shutdown: don't crash cleanup on recv timeouts.
    start_time = time.monotonic()
    expected_cmd = "STOP FTS"
    max_wait = handle.get('max_wait_time', 60)

    while True:
        if time.monotonic() - start_time > max_wait:
            log_entry = (
                f"wps_close: Timeout waiting for '{expected_cmd} SUCCEEDED' after {max_wait} seconds; closing socket anyway."
            )
            handle['log'].append(log_entry)
            if show_log:
                print(log_entry)
            break

        try:
            data = _recv_with_retries(
                handle,
                MAX_TO_READ,
                retry_attempts=recv_retry_attempts,
                retry_sleep=recv_retry_sleep,
                show_log=show_log,
                context="wps_close",
            )
        except (socket.timeout, TimeoutError):
            continue

        log_entry = f"wps_close: {data}"
        handle['log'].append(log_entry)
        if show_log:
            print(log_entry)

        try:
            result_str = data.decode(errors='replace')
        except Exception:
            break

        result_parse = result_str.split(';')
        if len(result_parse) >= 2 and result_parse[0] == expected_cmd:
            break

    try:
        s.close()
    except OSError:
        pass

# source_node_id is a 64 bit hex number starting with 0x
# session_keys is a list of 128 bit hex numbers starting with 0x
# This runs the FTE_CMD "Update Matter;matterkeys=source_node_id,session_keys"
def wps_update_matter_keys(handle, source_node_id, session_keys=None, show_log=False):
    """
    Update Matter protocol security keys to enable decryption.
    The Matter keys are required for decryption of encrypted Matter protocol traffic.
    This function sends a command to WPS to update the Matter keys to enable
    decryption of encrypted Matter protocol messages in captures.
    
    Parameters:
        handle (dict): Connection handle returned by wps_open().
        source_node_id (str): 64-bit node ID in hex format (must start with '0x').
                              Example: "0x12345678ABCDEF12"
        session_keys (list, optional): List of 128-bit session keys in hex format 
                                      (each must start with '0x').
                                      Example: ["0x1234567890ABCDEF1234567890ABCDEF"]
        show_log (bool): If True, print log messages to stdout. Default is False.
    
    Returns:
        None: Function doesn't return a value but appends to handle['log'].
    
    Example:
        >>> node_id = "0x12345678ABCDEF12"
        >>> keys = ["0x1234567890ABCDEF1234567890ABCDEF", "0xABCDEF1234567890ABCDEF1234567890"]
        >>> wps_update_matter_keys(handle, node_id, keys, show_log=True)
    
    Note: 
        This command must be issued after opening a capture but before analyzing it.

    :param dict handle: Connection handle returned by wps_open().
    :param str source_node_id: 64‑bit node ID in hex (must start with "0x").
    :param list session_keys: List of 128‑bit session keys in hex (each starts with "0x").
    :param bool show_log: If True, print send/receive log.
    :returns: None
    :raises ValueError: On invalid handle, node ID or key formats.        
    """
    # Validate handle
    if not isinstance(handle, dict) or 'socket' not in handle:
        raise ValueError("Invalid handle: must be a dict containing a valid 'socket'.")

    # Validate source_node_id: should be a non-empty string starting with '0x'
    if not isinstance(source_node_id, str) or not source_node_id.startswith("0x"):
        raise ValueError("Invalid source_node_id: must be a hex string starting with '0x'.")

    # Validate session_keys if provided
    if session_keys is not None:
        if not isinstance(session_keys, list):
            raise ValueError("session_keys must be a list of 128-bit hex strings starting with '0x'.")
        for key in session_keys:
            if not isinstance(key, str) or not key.startswith("0x"):
                raise ValueError("Each session key must be a hex string starting with '0x'.")

    # Build the matter keys string; if session_keys are provided, append them comma separated.
    if session_keys:
        matter_keys_str = source_node_id + "," + ",".join(session_keys)
    else:
        matter_keys_str = source_node_id

    # Construct the FTE command
    FTE_CMD = f"Update Matter;matterkeys={matter_keys_str}"
    try:
        send_data = FTE_CMD.encode(encoding='UTF-8', errors='strict')
    except Exception as e:
        raise ValueError(f"Encoding error: {e}")

    # Log and send the command
    log_entry = f"wps_update_matter_keys: sending: {send_data}"
    handle['log'].append(log_entry)
    if show_log:
        print(log_entry)

    sock = handle['socket']
    sock.send(send_data)

    # Receive and log response
    MAX_TO_READ = handle.get('max_data_from_automation_server', 1000)
    data = sock.recv(MAX_TO_READ)
    log_entry = f"wps_update_matter_keys: Received: {data}"
    handle['log'].append(log_entry)
    if show_log:
        print(log_entry)
