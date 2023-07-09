import socket
import time
import os
import sys
import platform
from pathlib import Path
import datetime as datetime


def wps_open(tcp_ip="127.0.0.1",tcp_port=22901,max_to_read = 1000,wps_executable_path=None,personality_key=None):
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
    
    # Start Wireless Protocol Suite
    FTE_CMD="Start FTS"+";" + str(wps_executable_path) + ";" + personality_key
    send_data=FTE_CMD.encode(encoding='UTF-8',errors='strict')
    log_entry = f"wps_open: s1 Sending: {send_data}"
    handle['log'].append(log_entry)
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
        result_parse = result_str.split(";")
        if result_parse[0]==EXPECTED_COMMAND  and result_parse[1]==EXPECTED_STATUS:
            is_done_waiting=True
        else:
            log_entry = f"wps_open: Received data parsed to {result_parse}, which indicates startup is not complete. Still waiting for the command {EXPECTED_COMMAND} with a status of {EXPECTED_STATUS}."
            handle['log'].append(log_entry)
            time.sleep(1)
            
    # Wait for FTS to be ready
    is_done_waiting = False
    while not is_done_waiting:
        FTE_CMD="Is Initialized"
        send_data=FTE_CMD.encode(encoding='UTF-8',errors='strict')
        log_entry = f"wps_open: s2 Sending: {send_data}"
        handle['log'].append(log_entry)
        s.send(send_data)
        
        rcv_data=s.recv(MAX_TO_READ)
        result_str=str(rcv_data.decode())
        log_entry = f"wps_open: s2 received: {result_str}"
        handle['log'].append(log_entry)
        result_parse = result_str.split(";")
        if result_parse[0]=="IS INITIALIZED"  and result_parse[1]=="SUCCEEDED":
            is_done_waiting=True
        else:
            log_entry = f"wps_open: Parse of received: {result_parse}. Not the desired result so still waiting.."
            handle['log'].append(log_entry)
            time.sleep(1)
    return handle

def wps_configure(handle, personality_key,capture_technology):
    s = handle['socket']
    MAX_TO_READ = handle['max_data_from_automation_server']
    # Start Wireless Protocol Suite
    if "X240" in personality_key:
        log_entry = "wps_configure: The X240 requires that the capture technology is setup before running this function."
        handle['log'].append(log_entry)
        FTE_CMD="Config Settings;IOParameters;" + personality_key + ";analyze=inquiryprocess-off|pagingnoconn-off|nullsandpolls-off|emptyle-on|anonymousadv-on|meshadv-off|lecrcerrors=on;" 
    else:
        FTE_CMD="Config Settings;IOParameters;" + personality_key + ";analyze=inquiryprocess-off|pagingnoconn-off|nullsandpolls-off|emptyle-on|anonymousadv-on|meshadv-off|lecrcerrors=on;" +  capture_technology  

    send_data=FTE_CMD.encode(encoding='UTF-8',errors='strict')
    log_entry = f"wps_configure: Sending: {send_data}"
    handle['log'].append(log_entry)
    s.send(send_data)

    # Wait to hear the start succeeded
    is_done_waiting = False
    while not is_done_waiting:
        rcv_data=s.recv(MAX_TO_READ)
        result_str=str(rcv_data.decode())
        log_entry = f"wps_configure: received: {result_str}"
        handle['log'].append(log_entry)
        result_parse = result_str.split(";")
        if result_parse[0]=="CONFIG SETTINGS"  and result_parse[1]=="SUCCEEDED":
            is_done_waiting=True
        else:
            log_entry = f"wps_configure: Parse of received: {result_parse}. Not the desired result so still waiting."
            handle['log'].append(log_entry)
            time.sleep(1)
    
def wps_start_record(handle):
    s = handle['socket']
    MAX_TO_READ = handle['max_data_from_automation_server']
    # Start the recording
    FTE_CMD="Start Record"
    send_data=FTE_CMD.encode(encoding='UTF-8',errors='strict')
    log_entry = f"wps_start_record: Sending: {send_data}"
    handle['log'].append(log_entry)
    s.send(send_data)
    data=s.recv(MAX_TO_READ)
    log_entry = f"wps_start_record: Receiving: {data}"
    handle['log'].append(log_entry)
    
def wps_stop_record(handle):
    s = handle['socket']
    MAX_TO_READ = handle['max_data_from_automation_server']
    # Stop Record
    FTE_CMD="Stop Record"
    send_data=FTE_CMD.encode(encoding='UTF-8',errors='strict')
    log_entry = f"wps_stop_record: Sending: {send_data}"
    handle['log'].append(log_entry)
    s.send(send_data)
    data=s.recv(MAX_TO_READ)
    log_entry = f"wps_stop_record: receiving: {data}"
    handle['log'].append(log_entry)
    
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
    log_entry = f"wps_analyze_capture: Sending: {send_data}"
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
        log_entry = f"wps_analyze_capture: Sending: {send_data}"
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
    log_entry = f"wps_analyze_capture: Sending: {send_data}"
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
        log_entry = f"wps_analyze_capture: Sending: {send_data}"
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
        log_entry = f"wps_analyze_capture: Sending: {send_data}"
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
            
def wps_save_capture(handle, capture_absolute_filename):
    s = handle['socket']
    MAX_TO_READ = handle['max_data_from_automation_server']
    
    # • Save Capture – Wait until status has been reported.
    FTE_CMD="Save Capture;" + str(capture_absolute_filename) 
    send_data=FTE_CMD.encode(encoding='UTF-8',errors='strict')
    log_entry = f"wps_save_capture: Sending: {send_data}"
    handle['log'].append(log_entry)
    s.send(send_data)
    data=s.recv(MAX_TO_READ)
    log_entry = f"wps_save_capture: {data}"
    handle['log'].append(log_entry)

def wps_export_html_json(handle,html_absolute_filename):
    s = handle['socket']
    MAX_TO_READ = handle['max_data_from_automation_server']
    # • Save Capture – Wait until status has been reported.
    FTE_CMD="HTML Export;summary=0;databytes=1;decode=1;frames=all;file=" + str(html_absolute_filename) 
    send_data=FTE_CMD.encode(encoding='UTF-8',errors='strict')
    log_entry = f"wps_export_html_json: Sending: {send_data}"
    handle['log'].append(log_entry)
    
    s.send(send_data)
    data=s.recv(MAX_TO_READ)
    log_entry = f"wps_export_html_json: {data}"
    handle['log'].append(log_entry)

def wps_close(handle):
    s = handle['socket']
    MAX_TO_READ = handle['max_data_from_automation_server']
    
    FTE_CMD="Stop FTS"
    send_data=FTE_CMD.encode(encoding='UTF-8',errors='strict')
    log_entry = f"wps_close: Sending: {send_data}"
    handle['log'].append(log_entry)
    s.send(send_data)
    data=s.recv(MAX_TO_READ)
    log_entry = f"wps_close: {data}"
    handle['log'].append(log_entry)

    s.close()