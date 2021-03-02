"""All things LR sessions commands and command management."""

import os
import json
import logging

from typing import Union
from concurrent.futures import Future

from cbapi.response.cblr import LiveResponseSession

LOGGER = logging.getLogger("cbinterface.command")


class BaseSessionCommand:
    """For storing and managing session commands.

    Session Commands are 'jobs' with concurrent.futures.
    """

    def __init__(self, description):
        self.description = description
        self.future = None
        self.session_id = None
        # store a copy of session data
        self.session_data = {}
        self.sensor_id = None
        self._exception = None
        self._result = None

    @property
    def hostname(self):
        return self.session_data.get("hostname", "")

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

    def __str__(self):
        txt = f"LrSessionCommand: {self.description}"
        if self.hostname:
            txt += f" - sensor:{self.hostname} - session:{self.session_id}"
        txt += f" - status:{self.status}"
        return txt


###############################
# General or Generic Commands #
###############################
class PutFile(BaseSessionCommand):
    """Get process listing via Live Response."""

    def __init__(self, local_filepath, sensor_write_filepath):
        super().__init__(description="Put file on sensor")
        self.local_filepath = local_filepath
        self.sensor_write_filepath = sensor_write_filepath

    def run(self, session: LiveResponseSession):
        try:
            with open(self.local_filepath, "rb") as fp:
                data = fp.read()
            return session.put_file(data, self.sensor_write_filepath)
        except Exception as e:
            LOGGER.error(f"couldn't put file: {e}")

    def process_result(self):
        # it worked if execution makes it here
        LOGGER.info(f"put '{self._file_path}' on {self.hostname} via session {self.session_id}")
        return True


class LogicalDrives(BaseSessionCommand):
    """List logical drives on this sensor."""

    def __init__(self):
        super().__init__(description="List logical drives")

    def run(self, session: LiveResponseSession):
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

    def run(self, session: LiveResponseSession):
        return session.create_registry_key(self.regkey)

    def process_result(self):
        LOGGER.info(f"Created'{self.regkey}' on {self.hostname}")


class SetRegKeyValue(BaseSessionCommand):
    """Set a registry key value on the remote machine."""

    def __init__(self, regkey, value):
        super().__init__(description=f"Set RegKey '{regkey}' value '{value}'")
        self.regkey = regkey
        self.value = value

    def run(self, session: LiveResponseSession):
        return session.set_registry_value(self.regkey, self.value)

    def process_result(self):
        LOGGER.info(f"Set '{self.regkey}' value='{self.value}' on {self.hostname}")


class ExecuteCommand(BaseSessionCommand):
    """Create a new process on the remote machine with the specified command string."""

    def __init__(self, command: str, wait_timeout=60, wait_for_output=True):
        super().__init__(description=f"Execute {command}")
        self._command_string = command
        self.wait_timeout = wait_timeout
        self.wait_for_output = wait_for_output

    def run(self, session: LiveResponseSession):
        session.create_process(
            self._command_string, wait_timeout=self.wait_timeout, wait_for_output=self.wait_for_output
        )

    def process_result(self):
        if not self.result:
            logging.info("no results.")
            return
        print("\n-------------------------")
        print(self.result.decode("utf-8"))
        print("\n-------------------------")
        print()


#######################
# Collection Commands #
#######################
class ProcessListing(BaseSessionCommand):
    """Get process listing via Live Response."""

    def __init__(self):
        super().__init__(description="process listing")

    def run(self, session: LiveResponseSession):
        return session.list_processes()

    def process_result(self):
        # just print the results as json
        print(json.dumps(self.result, indent=2, sort_keys=True))


class ListDirectory(BaseSessionCommand):
    """List the contents of a directory."""

    def __init__(self, dir_path: str):
        super().__init__(description=f"List Directory @ {dir_path}")
        self.dir_path = dir_path

    def run(self, session: LiveResponseSession):
        return session.list_directory(self.dir_path)

    def process_result(self):
        results = self.result
        if not results:
            logging.info("no results.")
            return
        print(json.dumps(results, indent=2, sort_keys=True))


class WalkDirectory(BaseSessionCommand):
    """Perform a full directory walk with recursion into subdirectories."""

    def __init__(self, dir_path: str, followlinks=False):
        super().__init__(description=f"Walk Directory @ {dir_path}")
        self.dir_path = dir_path
        self.followlinks = followlinks

    def run(self, session: LiveResponseSession):
        return session.walk(self.dir_path, followlinks=self.followlinks)

    def process_result(self):
        if not self.result:
            logging.warning("no results.")
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

    def run(self, session: LiveResponseSession):
        return session.list_registry_keys(self.regkeypath)
        # return session.list_registry_keys_and_values(self.regkeypath)

    def process_result(self):
        results = self.result
        if not results:
            logging.info("no results.")
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

    def __init__(self, regkeyvalue: str):
        super().__init__(description=f"Get Registry Key Value @ {regkeyvalue}")
        self.regkeyvalue = regkeyvalue

    def run(self, session: LiveResponseSession):
        return session.get_registry_value(self.regkeyvalue)

    def process_result(self):
        # print(json.dumps(self.result, indent=2, sort_keys=True))
        print("\n\t-------------------------")
        print(f"\tName: {self.result['value_name']}")
        print(f"\tType: {self.result['value_type']}")
        print(f"\tData: {self.result['value_data']}")
        print()


class GetSystemMemoryDump(BaseSessionCommand):
    """Perform a memory dump operation on the sensor."""

    def __init__(self, local_filename: str = "", compress=True):
        super().__init__(description=f"Dump System Memory")
        self.local_filename = local_filename
        self.compress = compress
        self._memdump_id = None
        self._cb = None

    def run(self, session: LiveResponseSession):
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

    def __init__(self, file_path, output_filename: Union[str, bool] = None):
        """
        Initialize the GetFile command.

        Args:
            file_path (str): The file path to be fetched.
            output_filename: optional path to write the file content.
        Returns:
            True on success, False on failure.
        """
        super().__init__(description=f"getFile @ '{file_path}'")
        self._file_path = file_path

        self.output_filename = output_filename

    def run(self, session: LiveResponseSession):
        """
        Execute the file transfer.
        Args:
            session (CbLRSessionBase): The Live Response session being used.
        Returns:
            File content
        """
        return session.get_raw_file(self._file_path)

    def process_result(self):
        """Write the results to a local file."""
        from cbinterface.helpers import get_os_independant_filepath

        if self.output_filename is None:
            filepath = get_os_independant_filepath(self._file_path)
            self.output_filename = f"{self.sensor_id}_{filepath.name}"

        try:
            with open(self.output_filename, "wb") as fp:
                content_handle = self.result
                fp.write(content_handle.read())
                content_handle.close()
            if os.path.exists(self.output_filename):
                LOGGER.info(f"wrote: {self.output_filename}")
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

    def run(self, session: LiveResponseSession):
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

    def run(self, session: LiveResponseSession):
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

    def run(self, session: LiveResponseSession):
        return session.delete_registry_value(self.regkeyvalue)

    def process_result(self):
        LOGGER.info(f"Deleted '{self.regkeyvalue}' on {self.hostname}")


class DeleteRegistryKey(BaseSessionCommand):
    """Delete a registry key and all it's values."""

    def __init__(self, regkey):
        super().__init__(description=f"Delete Registry Key @ '{regkey}'")
        self.regkey = regkey

    def run(self, session: LiveResponseSession):
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

    def run(self, session: LiveResponseSession):
        from cbinterface.helpers import get_os_independant_filepath

        for process in session.list_processes():
            filepath = get_os_independant_filepath(process["path"])
            if self.pname in filepath.name:
                logging.info(f"found process to kill: {process['path']} - pid={process['pid']}")
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

    def run(self, session: LiveResponseSession):
        from cbinterface.helpers import get_os_independant_filepath
        from cbinterface.response.sessions import CustomLiveResponseSessionManager

        self.local_session_manager = CustomLiveResponseSessionManager(session._cb)
        for process in session.list_processes():
            filepath = get_os_independant_filepath(process["path"])
            if self.pname in filepath.name:
                logging.info(f"found process to kill: {process['path']} - pid={process['pid']}")
                cmd = KillProcessByID(process["pid"])
                self.local_session_manager.submit_command(cmd, self.sensor_id)

        return True

    def process_result(self):
        if self.result:
            self.local_session_manager.process_completed_commands()
