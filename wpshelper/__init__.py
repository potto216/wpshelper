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


def _recv_and_parse(handle, expected_cmd=None, expected_status=None, expected_reason=None, show_log=False):
    """Receive data from the socket, decode and split by ';'.

    If expected_cmd / expected_status / expected_reason are provided, this
    helper will return a tuple (ok, result_parse, raw_str) where `ok` is True
    when all provided expectations match, otherwise False.
    """
    s = handle["socket"]
    max_to_read = handle["max_data_from_automation_server"]

    try:
        rcv_data = s.recv(max_to_read)
    except (socket.timeout, TimeoutError) as e:
        log_entry = f"_recv_and_parse: Socket receive timed out: {e}"
        handle["log"].append(log_entry)
        if show_log:
            print(log_entry)
        return False, None, None

    result_str = rcv_data.decode()
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

def wps_open(tcp_ip="127.0.0.1", tcp_port=22901, max_to_read=1000, wps_executable_path=None, personality_key=None, sleep_time=1, max_wait_time=60, show_log=False):
    """
    Open a connection to the WPS automation server and start the FTS.

    :param str tcp_ip: IP address of the automation server.
    :param int tcp_port: Port of the automation server.
    :param int max_to_read: Maximum bytes to read from the socket at once.
    :param str wps_executable_path: Full path to the FTSAutoServer executable.
    :param str personality_key: Personality key for the hardware.
    :param int sleep_time: Seconds to sleep between polling attempts.
    :param int max_wait_time: Max seconds to wait before timing out.
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

    handle={'max_data_from_automation_server':max_to_read, 'tcp_ip':tcp_ip, 'tcp_port':tcp_port, 'sleep_time':sleep_time, 'max_wait_time': max_wait_time}
    handle['log']=[]
    MAX_TO_READ = handle['max_data_from_automation_server']
    handle['wps_executable_path']=wps_executable_path

    try:
        s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        # Use a socket timeout so higher-level timeouts cannot be blocked
        s.settimeout(handle['sleep_time'])
        s.connect((handle['tcp_ip'],handle['tcp_port']))
        handle['socket'] = s
        data=s.recv(handle['max_data_from_automation_server'])
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
    data=s.recv(MAX_TO_READ)
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
    data=s.recv(MAX_TO_READ)
    log_entry = f"wps_stop_record: receiving: {data}"
    handle['log'].append(log_entry)
    if show_log:
        print(log_entry)

def wps_analyze_capture(handle, show_log=False):
    """
    Analyze the capture on the WPS (start, poll until complete, stop).

    :param dict handle: Connection handle returned by wps_open().
    :returns: None
    :raises WPSTimeoutError: If any polling stage times out.
    """    
    s = handle['socket']

    # • Start Analyze
    FTE_CMD="Start Analyze"
    send_data=FTE_CMD.encode(encoding='UTF-8',errors='strict')
    log_entry = f"wps_analyze_capture: sending: {send_data}"
    handle['log'].append(log_entry)
    s.send(send_data)

    ok, result_parse, result_str = _recv_and_parse(handle, "START ANALYZE", "SUCCEEDED", show_log=show_log)
    if not ok:
        log_entry = f"wps_analyze_capture: ERROR failed to start analysis with a parsed value of: {result_parse}"
        handle['log'].append(log_entry)
        raise RuntimeError(f"Failed to start analysis: {result_str}")

    # • Is Analyze Complete
    start_time = time.monotonic()
    is_done_waiting = False
    EXPECTED_COMMAND_AC = "IS ANALYZE COMPLETE"
    EXPECTED_STATUS_AC = "SUCCEEDED"
    EXPECTED_REASON_AC = "Reason=analyze_complete=yes\r\n"
    while not is_done_waiting:
        if time.monotonic() - start_time > handle['max_wait_time']:
            error_msg = f"wps_analyze_capture: Timeout waiting for '{EXPECTED_COMMAND_AC} {EXPECTED_STATUS_AC}' with reason '{EXPECTED_REASON_AC}' after {handle['max_wait_time']} seconds."
            handle['log'].append(error_msg)
            if show_log: print(error_msg)
            raise WPSTimeoutError(error_msg, handle=handle)

        FTE_CMD="IS ANALYZE COMPLETE"
        send_data=FTE_CMD.encode(encoding='UTF-8',errors='strict')
        log_entry = f"wps_analyze_capture: sending: {send_data}"
        handle['log'].append(log_entry)
        s.send(send_data)

        ok, result_parse, result_str = _recv_and_parse(handle, EXPECTED_COMMAND_AC, EXPECTED_STATUS_AC, EXPECTED_REASON_AC, show_log=show_log)
        if ok:
            is_done_waiting=True
        else:
            log_entry = f"wps_analyze_capture: Parse of received: {result_parse}. Not the desired result so still waiting."
            handle['log'].append(log_entry)
            time.sleep(handle['sleep_time'])

    # • Stop Analyze
    FTE_CMD="Stop Analyze"
    send_data=FTE_CMD.encode(encoding='UTF-8',errors='strict')
    log_entry = f"wps_analyze_capture: sending: {send_data}"
    handle['log'].append(log_entry)
    s.send(send_data)
    _ok, _parsed, result_str = _recv_and_parse(handle, show_log=show_log)

    # • Query State
    start_time = time.monotonic()
    is_done_waiting = False
    EXPECTED_COMMAND_QS = "QUERY STATE"
    EXPECTED_STATUS_QS = "SUCCEEDED"
    EXPECTED_REASON_QS1 = "Reason=CAPTURE STOPPED|CurrentState=CAPTURE STOPPED\r\n"
    EXPECTED_REASON_QS2 = "Reason=CAPTURE STOPPED|CurrentState=CAPTURE ACTIVE NO DATA\r\n"
    while not is_done_waiting:
        if time.monotonic() - start_time > handle['max_wait_time']:
            error_msg = f"wps_analyze_capture: Timeout waiting for '{EXPECTED_COMMAND_QS} {EXPECTED_STATUS_QS}' with reason '{EXPECTED_REASON_QS1}' or '{EXPECTED_REASON_QS2}' after {handle['max_wait_time']} seconds."
            handle['log'].append(error_msg)
            if show_log: print(error_msg)
            raise WPSTimeoutError(error_msg, handle=handle)

        FTE_CMD="Query State"
        send_data=FTE_CMD.encode(encoding='UTF-8',errors='strict')
        log_entry = f"wps_analyze_capture: sending: {send_data}"
        s.send(send_data)

        ok, result_parse, result_str = _recv_and_parse(handle, EXPECTED_COMMAND_QS, EXPECTED_STATUS_QS, show_log=show_log)
        if ok and len(result_parse) > 3 and (result_parse[3]==EXPECTED_REASON_QS1 or result_parse[3]==EXPECTED_REASON_QS2):
            is_done_waiting=True
        else:
            log_entry = f"wps_analyze_capture: Parse of received: {result_parse}. Not the desired result so still waiting."
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
            error_msg = f"wps_analyze_capture: Timeout waiting for '{EXPECTED_COMMAND_PC} {EXPECTED_STATUS_PC}' with reason '{EXPECTED_REASON_PC}' after {handle['max_wait_time']} seconds."
            handle['log'].append(error_msg)
            if show_log: print(error_msg)
            raise WPSTimeoutError(error_msg, handle=handle)

        FTE_CMD="Is Processing Complete"
        send_data=FTE_CMD.encode(encoding='UTF-8',errors='strict')
        log_entry = f"wps_analyze_capture: sending: {send_data}"
        handle['log'].append(log_entry)
        s.send(send_data)

        ok, result_parse, result_str = _recv_and_parse(handle, EXPECTED_COMMAND_PC, EXPECTED_STATUS_PC, EXPECTED_REASON_PC, show_log=show_log)
        if ok:
            is_done_waiting=True
        else:
            log_entry = f"wps_analyze_capture: Parse of received: {result_parse}. Not the desired result so still waiting."
            handle['log'].append(log_entry)
            time.sleep(handle['sleep_time'])

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

    # Wait for the final confirmation (not Reason=yes)
    start_time = time.monotonic()
    EXPECTED_COMMAND_OC = "OPEN CAPTURE FILE"
    EXPECTED_STATUS_OC = "SUCCEEDED"
    EXPECTED_REASON_OC_INTERIM = b"Reason=yes"
    final_response_received = False
    while not final_response_received:
        if time.monotonic() - start_time > handle['max_wait_time']:
            error_msg = f"wps_open_capture: Timeout waiting for final confirmation (not '{EXPECTED_REASON_OC_INTERIM}') after {handle['max_wait_time']} seconds."
            handle['log'].append(error_msg)
            if show_log: print(error_msg)
            raise WPSTimeoutError(error_msg, handle=handle)

        data=s.recv(MAX_TO_READ)
        log_entry = f"wps_open_capture: {data}"
        handle['log'].append(log_entry)
        if show_log:
            print(log_entry)

        # Check if it's the interim "yes" response or the final one
        if EXPECTED_REASON_OC_INTERIM in data:
            # Still waiting, reset timer slightly or just continue loop
            time.sleep(handle['sleep_time'] / 2) # Sleep briefly even on interim response
        else:
            # Assume any response not containing "Reason=yes" is the final one
            # Ideally, parse it to confirm "OPEN CAPTURE FILE;SUCCEEDED"
            result_str = data.decode()
            result_parse = result_str.split(';')
            if len(result_parse) > 1 and result_parse[0] == EXPECTED_COMMAND_OC and result_parse[1] == EXPECTED_STATUS_OC:
                final_response_received = True
            else:
                # Log unexpected final response but break loop anyway? Or raise error?
                log_entry = f"wps_open_capture: Received unexpected final response: {result_str}. Assuming completion."
                handle['log'].append(log_entry)
                if show_log: print(log_entry)
                final_response_received = True # Treat as complete to avoid infinite loop


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
    data=s.recv(MAX_TO_READ)
    log_entry = f"wps_save_capture: {data}"
    handle['log'].append(log_entry)
    if show_log:
        print(log_entry)

def wps_export_html(
        handle,
        html_absolute_filename=None,
        show_log=False,
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

        ok, result_parse, result_str = _recv_and_parse(handle, expected_cmd=EXPECTED_COMMAND, show_log=show_log)
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

def wps_export_pcapng(handle, pcapng_absolute_filename, tech='LE', mode=0, show_log=False):
    """
    Export capture data as PCAPNG.

    :param dict handle: Connection handle returned by wps_open().
    :param str pcapng_absolute_filename: Output PCAPNG file path.
    :param str tech: Technology filter (default 'LE').
    :param int mode: Mode parameter (default 0).
    :param bool show_log: If True, print send/receive log.
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
    data = s.recv(MAX_TO_READ)
    log_entry = f"wps_export_pcapng_du: {data}"
    handle['log'].append(log_entry)
    if show_log:
        print(log_entry)

def wps_export_spectrum(handle,spectrum_absolute_filename, show_log=False):
    """
    Export spectrum data from the capture.

    :param dict handle: Connection handle returned by wps_open().
    :param str spectrum_absolute_filename: Output spectrum file path.
    :param bool show_log: If True, print send/receive log.
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
    data=s.recv(MAX_TO_READ)
    log_entry = f"wps_export_spectrum: {data}"
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
    data=s.recv(MAX_TO_READ)
    log_entry = f"wps_get_available_streams_audio: {data}"
    handle['log'].append(log_entry)
    if show_log:
        print(log_entry)

    return data

# This exports audio data from a capture
def wps_export_audio(handle,audio_absolute_filename,audio_streams="1",audio_requestTypes="CSV&WAV",audio_time="all", show_log=False):
    """
    Export audio data from the capture.

    :param dict handle: Connection handle returned by wps_open().
    :param str audio_absolute_filename: Output audio file path.
    :param str audio_streams: Streams to export (default "1").
    :param str audio_requestTypes: Request types (default "CSV&WAV").
    :param str audio_time: Time range (default "all").
    :param bool show_log: If True, print send/receive log.
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
    data=s.recv(MAX_TO_READ)
    log_entry = f"wps_export_audio: {data}"
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
    data=s.recv(MAX_TO_READ)
    log_entry = f"wps_add_bookmark: {data}"
    handle['log'].append(log_entry)
    if show_log:
        print(log_entry)

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
    data=s.recv(MAX_TO_READ)
    log_entry = f"wps_send_command: Receiving: {data}"
    handle['log'].append(log_entry)
    if show_log:
        print(log_entry)

def wps_close(handle, show_log=False):
    """
    Close the connection and stop the FTS.

    :param dict handle: Connection handle returned by wps_open().
    :param bool show_log: If True, print send/receive log.
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
    data=s.recv(MAX_TO_READ)
    log_entry = f"wps_close: {data}"
    handle['log'].append(log_entry)
    if show_log:
        print(log_entry)

    s.close()

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
