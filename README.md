# cbinterface

cbinterface is a command line tool for interfacing with multiple carbonblack environments to perform analysis and live response functions.

Use `cbinterface` as a library or on the command line as `cbinterface`.

# Install

## Via pip

```bash
pip install cbinterface
```

## Direct from Github

# Querying

You can query processes and sensors. By default, on the command line, `cbinterface` will warn you before printing a lot of results to the screen.

**NOTE**: Use the `-ad` (`--all-details`) option to print all fields on the command line.

## Query Processes

```
$cbinterface query 'parent_name:svchost.exe process_name:rundll32.exe cmdline:AutoRun.inf'
2021-02-10 04:00:10 analysis cbinterface.cli[7211] INFO searching acmecomp environment..
2021-02-10 04:00:10 analysis cbinterface.query[7211] INFO got 27 process results grouped by id.
Print all results? (y/n) [y] y

------------------------- QUERY RESULTS -------------------------

  -------------------------
  Process GUID: 000059af-0000-2e74-01d6-ff16835f6f89
  Process Name: rundll32.exe
  Process PID: 11892
  Process MD5: 80f8e0c26028e83f1ef371d7b44de3df
  Process Path: c:\windows\system32\rundll32.exe
  Process Status: Terminated
  Command Line: rundll32.exe C:\WINDOWS\system32\davclnt.dll,DavSetCookie removedName http://serverName/folder/process/AutoRun.inf
  Parent Name: svchost.exe
  Parent GUID: 000059af-0000-4428-01d6-f96379775e63
  Hostname: computer00601
  Username: DOMAIN\Pete
  Start Time: 2021-02-09 19:05:21.244000
  Last Update Time: 2021-02-09 19:05:21.715000
  Sensor ID: 32958
  Comms IP: 192.168.252.192
  Interface IP: 192.168.252.192
  GUI Link: https://carbonblack.acmecomp/#analyze/000059af-0000-2e74-01d6-ff16835f6f89/1612897752481

  -------------------------
  Process GUID: 00006a99-0000-59ac-01d6-feff3879acfd
  Process Name: rundll32.exe
  Process PID: 22956
  Process MD5: 80f8e0c26028e83f1ef371d7b44de3df
  Process Path: c:\windows\system32\rundll32.exe
  Process Status: Terminated
  Command Line: rundll32.exe C:\WINDOWS\system32\davclnt.dll,DavSetCookie serverName http://example.com/folder/AutoRun.inf
  Parent Name: svchost.exe
  Parent GUID: 00006a99-0000-5448-01d6-fed7b2708931
  Hostname: computer01035
  Username: DOMAIN\Sara
  Start Time: 2021-02-09 16:18:37.162000
  Last Update Time: 2021-02-09 16:18:37.887000
  Sensor ID: 47299
  Comms IP: 185.220.101.14
  Interface IP: 192.168.1.89
  GUI Link: https://carbonblack.acmecomp/#analyze/00006a99-0000-59ac-01d6-feff3879acfd/1612887600302

<cut>
```

### Get Facet Data

Use the `--facets` option to get facet data on the command line.

`cbinterface query 'parent_name:svchost.exe process_name:rundll32.exe cmdline:AutoRun.inf' --facets`

Example:

```
$ cbinterface query 'parent_name:svchost.exe process_name:rundll32.exe cmdline:AutoRun.inf'  --facets 
2021-02-10 03:53:21 analysis cbinterface.cli[5789] INFO searching acmecompany environment..
2021-02-10 03:53:21 analysis cbinterface.query[5789] INFO got 27 process results grouped by id.
2021-02-10 03:53:21 analysis cbinterface.cli[5789] INFO getting facet data...

------------------------- FACET HISTOGRAMS -------------------------

			process_md5 results: 1
			--------------------------
                  80f8e0c26028e83f1ef371d7b44de3df:    27 100.0% ■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■


			hostname results: 6
			--------------------------
                                    computer012303:    10  37.0% ■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■
                                    computer012550:    10  37.0% ■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■
                                    computer012367:     3  11.1% ■■■■■■■■■■■■■■■
                                    computer012345:     2   7.4% ■■■■■■■■■■
                                    computer006070:     1   3.7% ■■■■■
                                    computer012307:     1   3.7% ■■■■■


			group results: 1
			--------------------------
                        corporate windows desktops:    27 100.0% ■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■


			path_full results: 1
			--------------------------
                  c:\windows\system32\rundll32.exe:    27 100.0% ■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■


			parent_name results: 1
			--------------------------
                                       svchost.exe:    27 100.0% ■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■


			process_name results: 1
			--------------------------
                                      rundll32.exe:    27 100.0% ■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■


			host_type results: 1
			--------------------------
                                       workstation:    27 100.0% ■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■


			username_full results: 6
			--------------------------
                                DOMAIN\Fred:    10  37.0% ■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■
                                DOMAIN\Bart:    10  37.0% ■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■
                              DOMAIN\Kilter:     3  11.1% ■■■■■■■■■■■■■■■
                             DOMAIN\Sashnal:     2   7.4% ■■■■■■■■■■
                               DOMAIN\Hippo:     1   3.7% ■■■■■
                               DOMAIN\EvilG:     1   3.7% ■■■■■

Print all results? (y/n) [y] n
```

## Query Sensors

```
$ cbinterface sensor-query hostname:computer012550
2021-02-10 04:12:43 analysis cbinterface.cli[9812] INFO searching acmecomp environment for sensor query: hostname:computer012550...
2021-02-10 04:12:43 analysis cbinterface.sensor[9812] INFO got 1 sensor results.

------------------------- SENSOR RESULTS -------------------------

Sensor object - https://carbonblack.acmecomp/#/host/30182
-------------------------------------------------------------------------------
	cb_build_version_string: 006.001.009.81012
	computer_sid: S-1-5-21-3617190964-3928019601-2880162275
	computer_dns_name: computer012550.zone.acmecomp
	computer_name: computer012550
	os_environment_display_string: Windows 10 Enterprise, 64-bit
	physical_memory_size: 8317603840
	systemvolume_free_size: 178565648384
	systemvolume_total_size: 254356221952

	status: Online
	is_isolating: False
	sensor_id: 30182
	last_checkin_time: 2021-02-10 04:11:39.846926-05:00
	next_checkin_time: 2021-02-10 04:12:40.846005-05:00
	sensor_health_message: Very high event loss
	sensor_health_status: 80
	network_interfaces:
		NetworkAdapter(macaddr='4c:1d:96:78:fc:21', ipaddr='172.19.8.185')
```

# Process Inspection

Use the process inspection interface to carve and parse process events. You can use any combination of optional arguments together *and* these arugments are also applied to processes that recursively walked with the `-w` (`--walk-tree`) option.

**NOTE**: If you do not supply any optional arguments, the following inspection arguments are applied by default:

    -i, --proc-info       show process information
    -t, --process-tree    print the process tree with this process as the root.
    -a, --process-ancestry
                            print the the process ancestry
    -c, --show-children   print process children event details
    -nc, --netconns       print network connections
    -fm, --filemods       print file modifications
    -rm, --regmods        print registry modifications
    -ml, --modloads       print modloads
    -cp, --crossprocs     print crossprocs

All process inspection arguments:

```
$ cbinterface inspect -h
usage: cbinterface inspect [-h] [-i] [-w] [-t] [-a] [-c] [-nc] [-fm] [-rm] [-ml] [-cp]
                           [-rpe] [--json] [--segment-limit SEGMENT_LIMIT]
                           guid_with_optional_segment

positional arguments:
guid_with_optional_segment
                        the process GUID/segment to inspect. Segment is
                        optional.

optional arguments:
-h, --help            show this help message and exit
-i, --proc-info       show binary and process information
-w, --walk-tree       Recursively walk, print, and inspect the process tree.
                        Specified arguments (ex. filemods) applied at every
                        process in tree. WARNING: can pull large datasets.
-t, --process-tree    print the process tree with this process as the root.
-a, --process-ancestry
                        print the the process ancestry
-c, --show-children   only print process children event details
-nc, --netconns       print network connections
-fm, --filemods       print file modifications
-rm, --regmods        print registry modifications
-ml, --modloads       print modloads
-cp, --crossprocs     print crossprocs
-rpe, --raw-print-events
                        do not format Cb events onto a single line. Print them
                        the way Cb does by default.
--json                Combine all results into json document and print the
                        result.
--segment-limit SEGMENT_LIMIT
                        stop processing events into json after this many
                        process segments
```

## Single Segment Specification

You can specify that a single process segment is inspected by passing a process with the process.current_segment set to an existing process.
This can be accomplished on the command line by passing the segment with the process GUID, like so:

`cbinterface inspect 00006a99-0000-59ac-01d6-feff3879acfd/1612887600302`


## All Segment Specification (default)

By default, if a single segment is not specified (current_segment field not set in the Process object) all segment events are inspected.

# Live Response

`cbinterface` has a robust live response interface for managing live response sessions and commands on sensors.

Command line interface to live response functions:

```
$ cbinterface live-response -h
usage: cbinterface live-response [-h] [-e EXECUTE_COMMAND] [-cr CREATE_REGKEY]
                                 [-sr SET_REGKEY_VALUE]
                                 hostname_or_sensor_id
                                 {put,collect,remediate,rem,destroy} ...

positional arguments:
  hostname_or_sensor_id
                        the hostname or sensor_id to go live with.
  {put,collect,remediate,rem,destroy}
    put                 put a file on the sensor
    collect             collect artifacts from hosts
    remediate (rem, destroy)
                        remdiation (delete/kill) actions

optional arguments:
  -h, --help            show this help message and exit
  -e EXECUTE_COMMAND, --execute-command EXECUTE_COMMAND
                        Execute this command on the sensor. NOTE: waits for
                        output.
  -cr CREATE_REGKEY, --create-regkey CREATE_REGKEY
                        Create this regkey.
  -sr SET_REGKEY_VALUE, --set-regkey-value SET_REGKEY_VALUE
                        Set this regkey value.
```

## LR Collection

Command line interface to LR collections:

```
$ cbinterface live-response collect -h
usage: cbinterface live-response [-h] [-e EXECUTE_COMMAND] [-cr CREATE_REGKEY]
                                 [-sr SET_REGKEY_VALUE]
                                 hostname_or_sensor_id
                                 {put,collect,remediate,rem,destroy} ...

positional arguments:
  hostname_or_sensor_id
                        the hostname or sensor_id to go live with.
  {put,collect,remediate,rem,destroy}
    put                 put a file on the sensor
    collect             collect artifacts from hosts
    remediate (rem, destroy)
                        remdiation (delete/kill) actions

optional arguments:
  -h, --help            show this help message and exit
  -e EXECUTE_COMMAND, --execute-command EXECUTE_COMMAND
                        Execute this command on the sensor. NOTE: waits for
                        output.
  -cr CREATE_REGKEY, --create-regkey CREATE_REGKEY
                        Create this regkey.
  -sr SET_REGKEY_VALUE, --set-regkey-value SET_REGKEY_VALUE
                        Set this regkey value.
```

## LR Remediation

Command line interface to LR remediations:

```
$ cbinterface live-response remediate -h
usage: cbinterface live-response [-h] [-e EXECUTE_COMMAND] [-cr CREATE_REGKEY]
                                      [-sr SET_REGKEY_VALUE]
                                      hostname_or_sensor_id
                                      {put,collect,remediate,rem,destroy} ...

positional arguments:
  hostname_or_sensor_id
                        the hostname or sensor_id to go live with.
  {put,collect,remediate,rem,destroy}
    put                 put a file on the sensor
    collect             collect artifacts from hosts
    remediate (rem, destroy)
                        remdiation (delete/kill) actions

optional arguments:
  -h, --help            show this help message and exit
  -e EXECUTE_COMMAND, --execute-command EXECUTE_COMMAND
                        Execute this command on the sensor. NOTE: waits for
                        output.
  -cr CREATE_REGKEY, --create-regkey CREATE_REGKEY
                        Create this regkey.
  -sr SET_REGKEY_VALUE, --set-regkey-value SET_REGKEY_VALUE
                        Set this regkey value.
```

# Sessions

`cbinterface` used a custom live response session manager: 

`from cbinterface2.sessions import CustomLiveResponseSessionManager`

This custom session manager allows for much more flexible with the management of live response commands.

Also, if needed, there is a command line interface for interacting directly with CbServer sessions:

```
cbi session -gcr 13288:3 -h
usage: cbi session [-h] [-lss LIST_SENSOR_SESSIONS]
                   [-gsc GET_SESSION_COMMAND_LIST] [-a] [-g GET_SESSION]
                   [-c CLOSE_SESSION] [-gcr GET_COMMAND_RESULT]
                   [-f GET_FILE_CONTENT]

optional arguments:
  -h, --help            show this help message and exit
  -lss LIST_SENSOR_SESSIONS, --list-sensor-sessions LIST_SENSOR_SESSIONS
                        list all CbLR sessions associated to this sensor ID.
  -gsc GET_SESSION_COMMAND_LIST, --get-session-command-list GET_SESSION_COMMAND_LIST
                        list commands associated to this session
  -a, --list-all-sessions
                        list all CbLR sessions.
  -g GET_SESSION, --get-session GET_SESSION
                        get live response session by id.
  -c CLOSE_SESSION, --close-session CLOSE_SESSION
                        close live response session by id.
  -gcr GET_COMMAND_RESULT, --get-command-result GET_COMMAND_RESULT
                        get any results for this command.
  -f GET_FILE_CONTENT, --get-file-content GET_FILE_CONTENT
                        byte stream any file content to stdout. (use a pipe)
```

## Check Session & Command Result

The following demonstrates correalting a session ID to commmand ID and checking the command result.

Check the session:

```
$cbinterface session -g 13290 
{
  "address": "54.82.99.78",
  "check_in_timeout": 1200,
  "create_time": 1612951662.403915,
  "current_working_directory": "C:\\Windows\\CarbonBlack",
  "drives": [
    "C:\\"
  ],
  "group_id": 7,
  "hostname": "FT7R15",
  "id": 13290,
  "os_version": "",
  "sensor_id": 31851,
  "sensor_wait_timeout": 120,
  "session_timeout": 300,
  "status": "active",
  "storage_size": "17194",
  "storage_ttl": 7.0,
  "supported_commands": [
    "delete file",
    "put file",
    "reg delete key",
    "directory list",
    "reg create key",
    "get file",
    "reg enum key",
    "reg query value",
    "kill",
    "create process",
    "process list",
    "reg delete value",
    "reg set value",
    "create directory",
    "memdump"
  ]
}
```

Get session commands:

```
$ cbinterface session -gsc 13290
[
  {
    "completion": 1612952045.935913,
    "create_time": 1612951689.034951,
    "id": 1,
    "name": "memdump",
    "object": "c:\\windows\\temp\\cblr.hGjtWgEj9Ku1.tmp",
    "result_code": 0,
    "result_desc": "",
    "result_type": "WinHresult",
    "sensor_id": 31851,
    "session_id": 13290,
    "status": "complete",
    "username": "smcfeely"
  }
]
```

Check the specific session command:

```
$ cbinterface session -gcr 13290:1
{
  "complete": true,
  "completion": 1612952045.935913,
  "compressing": false,
  "create_time": 1612951689.034951,
  "dumping": false,
  "id": 1,
  "name": "memdump",
  "object": "c:\\windows\\temp\\cblr.hGjtWgEj9Ku1.tmp",
  "percentdone": 0,
  "result_code": 0,
  "result_desc": "",
  "result_type": "WinHresult",
  "return_code": 0,
  "sensor_id": 31851,
  "session_id": 13290,
  "status": "complete",
  "username": "smcfeely"
}
```
