import socket
import time
import os
import sys
import platform
from pathlib import Path
import datetime as datetime


def wps_open(tcp_ip="127.0.0.1",tcp_port=22901,max_to_read = 1000,wps_executable_path=None,personality_key=None, show_log=False):
    # connect to the automation server
    handle={'max_data_from_automation_server':max_to_read, 'tcp_ip':tcp_ip, 'tcp_port':tcp_port}
    handle['log']=[]
    MAX_TO_READ = handle['max_data_from_automation_server']
    handle['wps_executable_path']=wps_executable_path

    s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    s.connect((handle['tcp_ip'],handle['tcp_port']))
    handle['socket'] = s
    data=s.recv(handle['max_data_from_automation_server'])
    log_entry = f"wps_open: Trying connection. Receiving: {data}"
    handle['log'].append(log_entry)
    if show_log:
        print(log_entry)
    # Start Wireless Protocol Suite
    FTE_CMD="Start FTS"+";" + str(wps_executable_path) + ";" + personality_key
    send_data=FTE_CMD.encode(encoding='UTF-8',errors='strict')
    log_entry = f"wps_open: s1 sending: {send_data}"
    handle['log'].append(log_entry)
    if show_log:
        print(log_entry)
    s.send(send_data)

    # Wait to hear the start succeeded
    is_done_waiting = False
    EXPECTED_COMMAND="START FTS"
    EXPECTED_STATUS="SUCCEEDED"

    while not is_done_waiting:
        rcv_data=s.recv(MAX_TO_READ)
        result_str=str(rcv_data.decode())
        log_entry = f"wps_open: s1 received: {result_str}"
        handle['log'].append(log_entry)
        if show_log:
            print(log_entry)
        result_parse = result_str.split(";")
        if result_parse[0]==EXPECTED_COMMAND  and result_parse[1]==EXPECTED_STATUS:
            is_done_waiting=True
        else:
            log_entry = f"wps_open: Received data parsed to {result_parse}, which indicates startup is not complete. Still waiting for the command {EXPECTED_COMMAND} with a status of {EXPECTED_STATUS}."
            handle['log'].append(log_entry)
            if show_log:
                print(log_entry)
            time.sleep(1)

    # Wait for FTS to be ready
    is_done_waiting = False
    while not is_done_waiting:
        FTE_CMD="Is Initialized"
        send_data=FTE_CMD.encode(encoding='UTF-8',errors='strict')
        log_entry = f"wps_open: s2 sending: {send_data}"
        handle['log'].append(log_entry)
        if show_log:
            print(log_entry)
        s.send(send_data)

        rcv_data=s.recv(MAX_TO_READ)
        result_str=str(rcv_data.decode())
        log_entry = f"wps_open: s2 received: {result_str}"
        handle['log'].append(log_entry)
        if show_log:
            print(log_entry)
        result_parse = result_str.split(";")
        if result_parse[0]=="IS INITIALIZED"  and result_parse[1]=="SUCCEEDED":
            is_done_waiting=True
        else:
            log_entry = f"wps_open: Parse of received: {result_parse}. Not the desired result so still waiting.."
            handle['log'].append(log_entry)
            if show_log:
                print(log_entry)
            time.sleep(1)
    return handle

def wps_configure(handle, personality_key,capture_technology, show_log=False):
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
    is_done_waiting = False
    while not is_done_waiting:
        rcv_data=s.recv(MAX_TO_READ)
        result_str=str(rcv_data.decode())
        log_entry = f"wps_configure: received: {result_str}"
        handle['log'].append(log_entry)
        if show_log:
            print(log_entry)
        result_parse = result_str.split(";")
        if result_parse[0]=="CONFIG SETTINGS"  and result_parse[1]=="SUCCEEDED":
            is_done_waiting=True
        else:
            log_entry = f"wps_configure: Parse of received: {result_parse}. Not the desired result so still waiting."
            handle['log'].append(log_entry)
            if show_log:
                print(log_entry)
            time.sleep(1)

def wps_start_record(handle, show_log=False):
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

def wps_analyze_capture(handle):
    s = handle['socket']
    MAX_TO_READ = handle['max_data_from_automation_server']

    # • Stop Analyze
    # • Is Analyze Complete – Repeat until status indicating completion has been received (see Is Analyze Complete).
    # • Stop Analyze
    # • Query State – Repeat until successful status with CAPTURE ACTIVE NO DATA or CAPTURE STOPPED reason.
    # • Is Processing Complete – Repeat until status indicating completion has been received (see Is Processing Complete).
    # • Save Capture – Wait until status has been reported.

    FTE_CMD="Start Analyze"
    send_data=FTE_CMD.encode(encoding='UTF-8',errors='strict')
    log_entry = f"wps_analyze_capture: sending: {send_data}"
    handle['log'].append(log_entry)
    s.send(send_data)

    rcv_data=s.recv(MAX_TO_READ)
    result_str=str(rcv_data.decode())
    log_entry = f"wps_analyze_capture: received: {result_str}"
    handle['log'].append(log_entry)
    result_parse = result_str.split(";")
    if result_parse[0]=="START ANALYZE"  and result_parse[1]=="SUCCEEDED":
        pass
    else:
        log_entry = f"wps_analyze_capture: ERROR failed to start analysis with a parsed value of: {result_parse}"
        handle['log'].append(log_entry)

    is_done_waiting = False
    while not is_done_waiting:
        FTE_CMD="IS ANALYZE COMPLETE"
        send_data=FTE_CMD.encode(encoding='UTF-8',errors='strict')
        log_entry = f"wps_analyze_capture: sending: {send_data}"
        handle['log'].append(log_entry)
        s.send(send_data)

        rcv_data=s.recv(MAX_TO_READ)
        result_str=str(rcv_data.decode())
        log_entry = f"wps_analyze_capture: {result_str}"
        handle['log'].append(log_entry)

        result_parse = result_str.split(";")
        if result_parse[0]=="IS ANALYZE COMPLETE" and \
        result_parse[1]=="SUCCEEDED"  and \
        result_parse[3]=="Reason=analyze_complete=yes\r\n":
            is_done_waiting=True
        else:
            log_entry = f"wps_analyze_capture: Parse of received: {result_parse}. Not the desired result so still waiting."
            handle['log'].append(log_entry)
            time.sleep(1)

    # • Stop Analyze
    FTE_CMD="Stop Analyze"
    send_data=FTE_CMD.encode(encoding='UTF-8',errors='strict')
    log_entry = f"wps_analyze_capture: sending: {send_data}"
    handle['log'].append(log_entry)
    s.send(send_data)
    data=s.recv(MAX_TO_READ)
    log_entry = f"wps_analyze_capture: {data}"
    handle['log'].append(log_entry)

    # • Query State – Repeat until successful status with CAPTURE ACTIVE NO DATA or CAPTURE STOPPED reason.
    is_done_waiting = False
    while not is_done_waiting:
        FTE_CMD="Query State"
        send_data=FTE_CMD.encode(encoding='UTF-8',errors='strict')
        log_entry = f"wps_analyze_capture: sending: {send_data}"
        s.send(send_data)
        rcv_data=s.recv(MAX_TO_READ)
        result_str=str(rcv_data.decode())
        log_entry = f"wps_analyze_capture: {result_str}"
        handle['log'].append(log_entry)

        result_parse = result_str.split(";")
        if result_parse[0]=="QUERY STATE" and \
        result_parse[1]=="SUCCEEDED"  and \
        (result_parse[3]=="Reason=CAPTURE STOPPED|CurrentState=CAPTURE STOPPED\r\n" or result_parse[3]=="Reason=CAPTURE STOPPED|CurrentState=CAPTURE ACTIVE NO DATA\r\n"):
            is_done_waiting=True
        else:
            log_entry = f"wps_analyze_capture: Parse of received: {result_parse}. Not the desired result so still waiting."
            handle['log'].append(log_entry)
            time.sleep(1)

    # • Is Processing Complete – Repeat until status indicating completion has been received (see Is Processing Complete).
    is_done_waiting = False
    while not is_done_waiting:
        FTE_CMD="Is Processing Complete"
        send_data=FTE_CMD.encode(encoding='UTF-8',errors='strict')
        log_entry = f"wps_analyze_capture: sending: {send_data}"
        handle['log'].append(log_entry)
        s.send(send_data)
        rcv_data=s.recv(MAX_TO_READ)
        result_str=str(rcv_data.decode())
        log_entry = f"wps_analyze_capture: {result_str}"
        handle['log'].append(log_entry)
        result_parse = result_str.split(";")
        if result_parse[0]=="IS PROCESSING COMPLETE" and \
        result_parse[1]=="SUCCEEDED"  and \
        result_parse[3]=="Reason=TRUE\r\n":
            is_done_waiting=True
        else:
            log_entry = f"wps_analyze_capture: Parse of received: {result_parse}. Not the desired result so still waiting."
            handle['log'].append(log_entry)
            time.sleep(1)

def wps_open_capture(handle, capture_absolute_filename, show_log=False):
    s = handle['socket']
    MAX_TO_READ = handle['max_data_from_automation_server']

    # • Save Capture – Wait until status has been reported.
    FTE_CMD=r"Open Capture File;" + str(capture_absolute_filename) + r";notify=1"
    send_data=FTE_CMD.encode(encoding='UTF-8',errors='strict')
    log_entry = f"wps_open_capture: sending: {send_data}"
    handle['log'].append(log_entry)
    if show_log:
        print(log_entry)
    s.send(send_data)
    data=s.recv(MAX_TO_READ)
    log_entry = f"wps_open_capture: {data}"
    handle['log'].append(log_entry)
    if show_log:
        print(log_entry)
    while b"Reason=yes" in data:
        data=s.recv(MAX_TO_READ)
        log_entry = f"wps_open_capture: {data}"
        handle['log'].append(log_entry)
        if show_log:
            print(log_entry)

def wps_save_capture(handle, capture_absolute_filename, show_log=False):
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

def wps_export_html(handle,html_absolute_filename, show_log=False):
    s = handle['socket']
    MAX_TO_READ = handle['max_data_from_automation_server']
    # • Save Capture – Wait until status has been reported.
    FTE_CMD="HTML Export;summary=0;databytes=1;decode=1;frames=all;file=" + str(html_absolute_filename)
    send_data=FTE_CMD.encode(encoding='UTF-8',errors='strict')
    log_entry = f"wps_export_html: sending: {send_data}"
    handle['log'].append(log_entry)
    if show_log:
        print(log_entry)
    s.send(send_data)
    data=s.recv(MAX_TO_READ)
    log_entry = f"wps_export_html: {data}"
    handle['log'].append(log_entry)
    if show_log:
        print(log_entry)

# export pcapng
def wps_export_pcapng(handle, pcapng_absolute_filename, tech='LE', mode=0, show_log=False):
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

# This exports a spectrum data from a capture
def wps_export_spectrum(handle,spectrum_absolute_filename, show_log=False):
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

# This returns the number of audio streams in a capture
def wps_get_available_streams_audio(handle,parameters="No", show_log=False):
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
    """Update Matter protocol security keys in Wireless Protocol Suite.
    
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
        The Matter keys are required for decryption of encrypted Matter protocol traffic.
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