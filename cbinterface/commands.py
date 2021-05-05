"""All things LR sessions commands and command management."""

import os
import json
import time
import logging
from datetime import timedelta
from typing import Union
from concurrent.futures import Future

from cbapi.live_response_api import CbLRSessionBase

LOGGER = logging.getLogger("cbinterface.command")

# the cbinterface directory
BASE_DIR = os.path.dirname(os.path.abspath(__file__))


class BaseSessionCommand:
    """For storing and managing session commands.

    Session Commands are 'jobs' with concurrent.futures.
    """

    def __init__(self, description, placeholders={}, post_completion_command=None):
        self.description = description
        self.future = None
        self.session_id = None
        # store a copy of session data
        self.session_data = {}
        self._sensor_id = None
        self._exception = None
        self._result = None
        self._hostname = None
        self.placeholders = placeholders
        self.post_completion_command = post_completion_command

    def fill_placeholders(self, string_item: str, placeholders={}):
        # fill common placeholders
        placeholders = placeholders if placeholders else self.placeholders
        placeholders["HOSTNAME"] = placeholders.get("HOSTNAME", self.hostname)
        placeholders["SENSOR_ID"] = placeholders.get("SENSOR_ID", self.sensor_id)
        placeholders["DEVICE_ID"] = placeholders.get("DEVICE_ID", self.sensor_id)
        placeholders["WORK_DIR"] = placeholders.get("WORK_DIR", "C:\\Program Files")
        string_item = string_item.format(**placeholders)
        return string_item

    @property
    def hostname(self):
        # NOTE: Appears this is set to None for psc. So, custom
        # session manager sets it right before job submission.
        return self.session_data.get("hostname") or self._hostname

    @property
    def sensor_id(self):
        return self.session_data.get("sensor_id") or self._sensor_id

    @property
    def initiatied(self):
        """True if future exists."""
        if isinstance(self.future, Future):
            return True
        return False

    @property
    def done(self):
        if self.future and self.future.done():
            return True
        return False

    @property
    def exception(self):
        if self.done:
            self._exception = self.future.exception()
        return self._exception

    @property
    def has_result(self):
        if self.done and self.exception is None:
            return True
        return False

    @property
    def result(self):
        if self.has_result:
            return self.future.result()
        return None

    @property
    def status(self):
        if not self.initiatied:
            return "not submitted"
        if self.done:
            if self.exception:
                return "error"
            if self.has_result:
                return "complete"
        return "pending"

    def run(self):
        """The function to implement the live response command logic."""
        raise NotImplemented()

    def process_result(self):
        """Implement logic to process any results."""
        pass

    def execute_post_completion(self):
        if not self.post_completion_command:
            return None
        if self.status != "complete":
            return False
        self.post_completion_command = self.fill_placeholders(self.post_completion_command)
        if self.post_completion_command.startswith("tools/"):
            self.post_completion_command = f"{BASE_DIR}/{self.post_completion_command}"
        LOGGER.info(f"executing post completion command: {self.post_completion_command}")
        import shlex, subprocess

        try:
            args = shlex.split(self.post_completion_command)
            return subprocess.run(args=args)
        except Exception as e:
            LOGGER.error(f"caught exception executing post completion command: {e}")
            return False

    def __str__(self):
        txt = f"LrSessionCommand: {self.description}"
        if self.hostname:
            txt += f" - device:{self.hostname}"
        if self.session_id:
            txt += f" - session:{self.session_id}"
        txt += f" - status:{self.status}"
        return txt


###############################
# General or Generic Commands #
###############################
class PutFile(BaseSessionCommand):
    """Get process listing via Live Response."""

    def __init__(self, local_filepath, sensor_write_filepath, **kwargs):
        super().__init__(description="Put file on device", **kwargs)
        self.local_filepath = local_filepath
        self.sensor_write_filepath = sensor_write_filepath

    def run(self, session: CbLRSessionBase):
        self.sensor_write_filepath = self.fill_placeholders(self.sensor_write_filepath)
        try:
            with open(self.local_filepath, "rb") as fp:
                data = fp.read()
            return session.put_file(data, self.sensor_write_filepath)
        except Exception as e:
            LOGGER.error(f"couldn't put file: {e}")
            return False

    def process_result(self):
        if not self.result:
            return False
        # it worked if execution makes it here
        LOGGER.info(f"put '{self.sensor_write_filepath}' on {self.hostname} via session {self.session_id}")
        if self.post_completion_command:
            self.execute_post_completion()
        return True


class LogicalDrives(BaseSessionCommand):
    """List logical drives on this sensor."""

    def __init__(self):
        super().__init__(description="List logical drives")

    def run(self, session: CbLRSessionBase):
        return session.session_data.get("drives", [])

    def process_result(self):
        print(f"\n + Logical Drives on {self.hostname}: ")
        for drive in self.result:
            print(f"    {drive}")


class CreateRegKey(BaseSessionCommand):
    """Create a registry key on the remote machine."""

    def __init__(self, regkey):
        super().__init__(description=f"Create A Registry Key @ '{regkey}'")
        self.regkey = regkey

    def run(self, session: CbLRSessionBase):
        return session.create_registry_key(self.regkey)

    def process_result(self):
        LOGGER.info(f"Created'{self.regkey}' on {self.hostname}")


class SetRegKeyValue(BaseSessionCommand):
    """Set a registry key value on the remote machine."""

    def __init__(self, regkey, value):
        super().__init__(description=f"Set RegKey '{regkey}' value '{value}'")
        self.regkey = regkey
        self.value = value

    def run(self, session: CbLRSessionBase):
        return session.set_registry_value(self.regkey, self.value)

    def process_result(self):
        LOGGER.info(f"Set '{self.regkey}' value='{self.value}' on {self.hostname}")


class ExecuteCommand(BaseSessionCommand):
    """Create a new process on the remote machine with the specified command string.

    Args:
        command (str): Command string used for the create process operation.
        wait_for_output (bool): True to block on output from the new process (execute in foreground).
            This will also set wait_for_completion (below).
        remote_output_file_name (str): The remote output file name used for process output.
        working_directory (str): The working directory of the create process operation.
        wait_timeout (int): Timeout used for this command.
        wait_for_completion (bool): True to wait until the process is completed before returning.
        print_results (bool): Print results to console if True.
        write_results_path: Path to write the results. Default is to write nothing.

    Returns:
        str: The output of the process.
    """

    def __init__(
        self,
        command: str,
        wait_for_output=True,
        remote_output_file_name=None,
        working_directory=None,
        wait_timeout=60,
        wait_for_completion=True,
        print_results=True,
        write_results_path=False,
        **kwargs,
    ):
        super().__init__(description=f"Execute {command}", **kwargs)
        self._command_string = command
        self.wait_for_output = wait_for_output
        self.remote_output_file_name = remote_output_file_name
        self.working_directory = working_directory
        self.wait_timeout = wait_timeout
        self.wait_for_completion = wait_for_completion
        self.print_results = print_results
        self.write_results_path = write_results_path
        self.start_time = None
        self.elapsed_time = None

    def run(self, session: CbLRSessionBase):
        self._command_string = self.fill_placeholders(self._command_string)
        self.start_time = time.time()
        session.create_process(
            self._command_string,
            wait_for_output=self.wait_for_output,
            remote_output_file_name=self.remote_output_file_name,
            working_directory=self.working_directory,
            wait_timeout=self.wait_timeout,
            wait_for_completion=self.wait_for_completion,
        )
        self.elapsed_time = timedelta(seconds=(time.time() - self.start_time))

    def process_result(self):
        LOGGER.debug(f"{self} took {self.elapsed_time} to return.")
        if self.post_completion_command:
            self.execute_post_completion()
        if not self.result:
            if self.wait_for_output:
                LOGGER.warning("Expected output, but did not receive results.")
                return False
            LOGGER.info(f"successfully executed '{self._command_string}'. no results returned.")
            return True
        if self.print_results:
            print("\n-------------------------")
            print(self.result.decode("utf-8"))
            print("\n-------------------------")
            print()
        if self.write_results_path:
            self.write_results_path = self.fill_placeholders(self.write_results_path)
            if os.path.exists(self.write_results_path):
                LOGGER.info(f"overriting existing file: {self.write_results_path}")
            with open(self.write_results_path, "wb") as fp:
                fp.write(self.result)
        return True


#######################
# Collection Commands #
#######################
class ProcessListing(BaseSessionCommand):
    """Get process listing via Live Response."""

    def __init__(self):
        super().__init__(description="process listing")

    def run(self, session: CbLRSessionBase):
        return session.list_processes()

    def process_result(self):
        # just print the results as json
        print(json.dumps(self.result, indent=2, sort_keys=True))


class ListDirectory(BaseSessionCommand):
    """List the contents of a directory."""

    def __init__(self, dir_path: str):
        super().__init__(description=f"List Directory @ {dir_path}")
        self.dir_path = dir_path

    def run(self, session: CbLRSessionBase):
        return session.list_directory(self.dir_path)

    def process_result(self):
        results = self.result
        if not results:
            LOGGER.info("no results.")
            return
        print(json.dumps(results, indent=2, sort_keys=True))


class WalkDirectory(BaseSessionCommand):
    """Perform a full directory walk with recursion into subdirectories."""

    def __init__(self, dir_path: str, followlinks=False):
        super().__init__(description=f"Walk Directory @ {dir_path}")
        self.dir_path = dir_path
        self.followlinks = followlinks

    def run(self, session: CbLRSessionBase):
        return session.walk(self.dir_path, followlinks=self.followlinks)

    def process_result(self):
        if not self.result:
            LOGGER.warning("no results.")
            return
        print(f"Recursive top-down directory listing for '{self.dir_path}':")
        for name, subdir_names, filenames in self.result:
            print(f" + Directory: {name}")
            for subdir in subdir_names:
                print(f"    SubDirectory: {subdir}")
            for fn in filenames:
                print(f"    File: {fn}")


class ListRegKeyValues(BaseSessionCommand):
    """List all registry values from the specified registry key."""

    def __init__(self, regkeypath: str, return_json=False):
        super().__init__(description=f"List Registry Keys and Values @ {regkeypath}")
        self.regkeypath = regkeypath
        self.return_json = return_json

    def run(self, session: CbLRSessionBase):
        return session.list_registry_keys(self.regkeypath)
        # return session.list_registry_keys_and_values(self.regkeypath)

    def process_result(self):
        results = self.result
        if not results:
            LOGGER.info("no results.")
            return None
        if self.return_json:
            return json.dumps(results, indent=2, sort_keys=True)
        print(f"\nRegistryKey Listing: {self.regkeypath}")
        for result in results:
            print("\n\t-------------------------")
            print(f"\tName: {result['value_name']}")
            print(f"\tType: {result['value_type']}")
            print(f"\tData: {result['value_data']}")
        print()


class RegKeyValue(BaseSessionCommand):
    """Get the associated value of the specified registry key."""

    # TODO: add write_results option and make print_results an option

    def __init__(self, regkeyvalue: str):
        super().__init__(description=f"Get Registry Key Value @ {regkeyvalue}")
        self.regkeyvalue = regkeyvalue

    def run(self, session: CbLRSessionBase):
        return session.get_registry_value(self.regkeyvalue)

    def process_result(self):
        # print(json.dumps(self.result, indent=2, sort_keys=True))
        print("\n\t-------------------------")
        print(f"\tName: {self.result['value_name']}")
        print(f"\tType: {self.result['value_type']}")
        print(f"\tData: {self.result['value_data']}")
        print()


class GetSystemMemoryDump(BaseSessionCommand):
    """Perform a memory dump operation on the sensor.

    NOTE: Not a fan of Cb's implementation.
    """

    def __init__(self, local_filename: str = "", compress=True):
        super().__init__(description=f"Dump System Memory")
        self.local_filename = local_filename
        self.compress = compress
        self._memdump_id = None
        self._cb = None

    def run(self, session: CbLRSessionBase):
        # store a pointer to the CbR object for later
        self._cb = session._cb
        if not self.local_filename:
            self.local_filename = f"{self.sensor_id}_{self.hostname}.cb.memdump"
        if self.compress:
            self.local_filename += ".zip"
        dump_object = session.start_memdump(compress=self.compress)
        self._memdump_id = dump_object.memdump_id
        dump_object.wait()
        dump_object.get(local_filename)
        dump_object.delete()

    def process_result(self):
        from cbinterface.response.sessions import get_command_result

        # should only make it here if an error was not raise
        # check to see if the command has success status with server
        # and if the local file exists
        memdump_cmd = get_command_result(self._cb, self.session_id, self._memdump_id)
        if memdump["status"] != "complete":
            LOGGER.error(f"problem completing memory dump: command status: {memdump['status']}")
            return False
        if os.path.exits(self.local_filename):
            LOGGER.info(f" +  wrote: {self.local_filename}")
            return True
        else:
            LOGGER.error(f"Memory dump completed but failed to get a local copy of the memory dump.")
            return False


class GetFile(BaseSessionCommand):
    """Object that retrieves a file via Live Response."""

    def __init__(self, file_path, output_filename: Union[str, bool] = None, **kwargs):
        """
        Initialize the GetFile command.

        Args:
            file_path (str): The file path to be fetched.
            output_filename: optional path to write the file content.
        Returns:
            True on success, False on failure.
        """
        super().__init__(description=f"getFile @ '{file_path}'", **kwargs)
        self._file_path = file_path

        self.output_filename = output_filename

    def run(self, session: CbLRSessionBase):
        """
        Execute the file transfer.
        Args:
            session (CbLRSessionBase): The Live Response session being used.
        Returns:
            File content
        """
        if "{WILDMATCH}" in self._file_path:
            # split on "{WILDMATCH}" and search for the first match to collect
            from cbinterface.helpers import get_os_independent_filepath

            file_path_parts = [self.fill_placeholders(fpp) for fpp in self._file_path.split("{WILDMATCH}")]
            dir_path = get_os_independent_filepath(file_path_parts[0]).parent
            dir_path = f"{dir_path}\\" if "\\" in str(dir_path) else f"{dir_path}/"

            LOGGER.info(f"attempting to find item at '{dir_path}' like {file_path_parts}")
            for item in session.list_directory(dir_path):
                if item["attributes"] == "DIRECTORY":
                    continue
                if [part for part in file_path_parts if part in item["filename"]]:
                    LOGGER.info(f"found potential match: {item['filename']}")
                    self._file_path = f"{dir_path}{item['filename']}"
                    break

        self._file_path = self.fill_placeholders(self._file_path)
        return session.get_raw_file(self._file_path)

    def process_result(self):
        """Write the results to a local file."""
        from cbinterface.helpers import get_os_independent_filepath

        if self.output_filename is None:
            filepath = get_os_independent_filepath(self._file_path)
            hostname_part = f"{self.hostname}_" if self.hostname else ""
            self.output_filename = f"{self.sensor_id}_{hostname_part}{filepath.name}"
        else:
            self.output_filename = self.fill_placeholders(self.output_filename)

        try:
            if os.path.exists(self.output_filename):
                LOGGER.debug(f"{self.output_filename} already exists. appending epoch time")
                _now = str(time.time())
                _now = _now[: _now.rfind(".")]
                self.output_filename = f"{_now}_{self.output_filename}"
            with open(self.output_filename, "wb") as fp:
                content_handle = self.result
                fp.write(content_handle.read())
                content_handle.close()
            if os.path.exists(self.output_filename):
                LOGGER.info(f"wrote: {self.output_filename}")
            if self.post_completion_command:
                self.execute_post_completion()
            return True
        except Exception as e:
            LOGGER.error(f"problem getting file content: {e}")
            return False


########################
# Remediaiton Commands #
########################
class DeleteFile(BaseSessionCommand):
    """Object that deletes a file via Live Response."""

    def __init__(self, file_path):
        """
        Delete the specified file name on the remote machine.
        Args:
            filename (str): Name of the file to be deleted.
        """
        super().__init__(description=f"Delete File @ '{file_path}'")
        self._file_path = file_path

    def run(self, session: CbLRSessionBase):
        return session.delete_file(self._file_path)

    def process_result(self):
        LOGGER.info(f"deleted '{self._file_path}' on {self.hostname} via session {self.session_id}")
        return True


class KillProcessByID(BaseSessionCommand):
    """
    Terminate a process by process id.
    Args:
        pid (int): Process ID to be terminated.
    Returns:
        bool: True if success, False if failure.
    """

    def __init__(self, pid):
        super().__init__(description=f"Kill Process with ID={pid}")
        self.pid = pid

    def run(self, session: CbLRSessionBase):
        return session.kill_process(self.pid)

    def process_result(self):
        if self.result is True:
            LOGGER.info(f"Killed process id {self.pid} on {self.hostname} via session {self.session_id}")
            return True
        else:
            LOGGER.error(f"failed to kill process id {self.pid} on {self.hostname} via session {self.session_id}")
            return self.result


class DeleteRegistryKeyValue(BaseSessionCommand):
    """Delete a registry value on the remote machine."""

    def __init__(self, regkeyvalue):
        super().__init__(description=f"Delete Registry Key:Value @ '{regkeyvalue}'")
        self.regkeyvalue = regkeyvalue

    def run(self, session: CbLRSessionBase):
        return session.delete_registry_value(self.regkeyvalue)

    def process_result(self):
        LOGGER.info(f"Deleted '{self.regkeyvalue}' on {self.hostname}")


class DeleteRegistryKey(BaseSessionCommand):
    """Delete a registry key and all it's values."""

    def __init__(self, regkey):
        super().__init__(description=f"Delete Registry Key @ '{regkey}'")
        self.regkey = regkey

    def run(self, session: CbLRSessionBase):
        return session.delete_registry_key(self.regkey)

    def process_result(self):
        LOGGER.info(f"Deleted '{self.regkey}' on {self.hostname}")


class KillProcessByName(BaseSessionCommand):
    """
    Terminate a process by process name.
    Args:
        process_name (str): Process name(s) to be terminated.
    Returns:
        bool: True if success, False if failure.
    """

    def __init__(self, process_name):
        super().__init__(description=f"Kill Processes with name like '{process_name}'")
        self.pname = process_name
        self.nested_commands = {}

    def run(self, session: CbLRSessionBase):
        from cbinterface.helpers import get_os_independent_filepath

        for process in session.list_processes():
            filepath = get_os_independent_filepath(process["path"])
            if self.pname.lower() in filepath.name.lower():
                LOGGER.info(f"found process to kill: {process['path']} - pid={process['pid']}")
                self.nested_commands[process["pid"]] = session.kill_process(process["pid"])

        return True

    def process_result(self):
        if self.result:
            for pid, killed in self.nested_commands.items():
                if killed:
                    LOGGER.info(f"successfully killed: pid={pid}")
                else:
                    LOGGER.warning(f"failed to kill: pid={pid}")


""" Not used: left as an example of recursive command."""


class RecursiveKillProcessByName(BaseSessionCommand):
    """Recursivly terminate a process by process name.

    First, list processes and find matching process names. Next,
    Create a local CustomLiveResponseSessionManager and create
    commands (managed via threads) to kill the matching processes by PID.
    """

    def __init__(self, process_name):
        super().__init__(description=f"Kill Processes with name like '{process_name}'")
        self.pname = process_name
        self.local_session_manager = None

    def run(self, session: CbLRSessionBase):
        from cbinterface.helpers import get_os_independent_filepath
        from cbinterface.response.sessions import CustomLiveResponseSessionManager

        self.local_session_manager = CustomLiveResponseSessionManager(session._cb)
        for process in session.list_processes():
            filepath = get_os_independent_filepath(process["path"])
            if self.pname in filepath.name:
                LOGGER.info(f"found process to kill: {process['path']} - pid={process['pid']}")
                cmd = KillProcessByID(process["pid"])
                self.local_session_manager.submit_command(cmd, self.sensor_id)

        return True

    def process_result(self):
        if self.result:
            self.local_session_manager.process_completed_commands()
