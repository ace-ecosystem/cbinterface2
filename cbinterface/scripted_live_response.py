"""Functionality that supports live response "scripts".

In IDR, people like to call things like this playbooks. So, playbooks,
and also remediation scripts to allow for mass remediations.

TODO: Implemented collection scripts for mass collections.
"""

import os
import logging

from configparser import ConfigParser
from typing import Union, List

from cbapi.psc import Device
from cbapi.psc.devices_query import DeviceSearchQuery
from cbapi.live_response_api import CbLRManagerBase

from cbinterface.helpers import get_os_independent_filepath, input_with_timeout

# XXX Make playbooks support all commands?

from cbinterface.commands import (
    PutFile,  # Playbook
    ProcessListing,
    GetFile,  # Playbook
    ListRegKeyValues,
    RegKeyValue,
    ExecuteCommand,  # Playbook
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

# GLOBALS #
LOGGER = logging.getLogger("cbinterface.scripted_live_response")

IGNORED_SECTIONS = ["overview"]

REQUIRED_CMD_KEYS = ["operation"]
REQUIRED_OP_KEY_MAP = {
    "RUN": ["command"],
    "UPLOAD": ["path"],
    "DOWNLOAD": ["file_path", "client_file_path"],
}
""" # remove?
OPTIONAL_CMD_KEYS = ['wait_for_completion', 'get_results']
OPTIONAL_OP_KEY_MAP = {'RUN': ['async_run', 'write_results_path', 'print_results',
                               'common_setup_command', 'common_cleanup_command'],
                       'UPLOAD': ['write_results_path'],
                       'DOWNLOAD': ['client_file_path', 'common_setup_command']
                       } 
"""

# live response scripts - order is important, ordered impacts execution.
SUPPORTED_LR_SCRIPT_KEYS = [
    "pids",
    "process_names",
    "services",
    "scheduled_tasks",
    "registry_values",
    "registry_keys",
    "files",
    "directories",
]

LR_REMEDIATION_MAP = {
    "pids": KillProcessByID,
    "process_names": KillProcessByName,
    "services": "playbook_configs/delete_service.ini",
    "scheduled_tasks": "playbook_configs/delete_scheduled_task.ini",
    "registry_values": DeleteRegistryKeyValue,
    "registry_keys": DeleteRegistryKey,
    "files": DeleteFile,
    "directories": "playbook_configs/delete_directory.ini",
}

# Get the working directory
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Playbook section begins #

PLAYBOOK_TEMPLATE_PATH = os.path.join(BASE_DIR, "templates/playbook.ini")


def write_playbook_template(template_path=PLAYBOOK_TEMPLATE_PATH):
    """Write the example template to the current working dir."""
    from shutil import copyfile

    destination = template_path[template_path.rfind("/") + 1 :]
    copyfile(template_path, destination)
    return destination


def playbook_missing_required_keys(config, KEYS):
    """Return True if a playbook is missing required keys."""
    for key in KEYS:
        for section in config.sections():
            if section in IGNORED_SECTIONS:
                return False
            if not config.has_option(section, key):
                LOGGER.error("{} is missing required key: {}".format(section, key))
                return True
    return False


def operation_missing_required_keys(config, section, KEYS):
    """Return True if an operation is missing required keys."""
    for key in KEYS:
        if not config.has_option(section, key):
            LOGGER.error(
                "{} is missing required operation key:{} for operation:{}".format(
                    section, key, config[section]["operation"]
                )
            )
            return True
    return False


def load_playbook(playbook_path):
    """Load playbook config from path."""
    playbook = ConfigParser()
    if not os.path.exists(playbook_path):
        playbook_path = os.path.join(BASE_DIR, playbook_path)
    if not os.path.exists(playbook_path):
        playbook_name = playbook_path[playbook_path.rfind("/") + 1 : playbook_path.rfind(".")]
        LOGGER.error(f"Path to '{playbook_name}' playbook does not exist: {playbook_path}")
        return False
    LOGGER.debug(f"loading playbook path: {playbook_path}")
    try:
        playbook.read(playbook_path)
    except Exception as e:
        LOGGER.error("ConfigParser Error reading '{playbook_path}' : {e}")
        return False
    if playbook_missing_required_keys(playbook, REQUIRED_CMD_KEYS):
        return False
    return playbook


def enforce_argument_placeholders(playbook: ConfigParser, placeholders: dict = {}):
    """Some playbooks require arguments to execute. These arguments are in the form of string format placeholder keys.
    Make sure we have all of the arguments for this playbook. Prompt the user for those arguments if we don't.

    Args:
      playbook: A loaded LR playbook playbook
      placeholders: A dictionary of placeholders we already have (if any)
    Return:
      completed placeholders dict
    """
    LOGGER.debug("Enforcing argument placeholders")
    args_needed = []
    required_args = (
        playbook["overview"]["required_arguments"].split(",")
        if playbook.has_option("overview", "required_arguments")
        else None
    )
    if required_args:
        args_needed = [arg for arg in required_args if arg not in placeholders.keys()]
    for arg in args_needed:
        prompt = f"playbook requires argument {arg}: "
        placeholders[arg] = input_with_timeout(prompt)
    return placeholders


def build_playbook_commands(playbook_path, placeholders={}, separate_cleanup=False):
    """Build the live response commands that define this playbook.

    Args:
        lrsm: A CbLRManagerBase based object (CustomLiveResponseSessionManager)
        devices: iterable of Devices/Sensors (TODO: sensors)
    Returns: List of Cb live response commands.
    """

    # TODO remove cleanup command stuff

    ready_live_response_commands = []

    playbook = load_playbook(playbook_path)
    if not playbook:
        return ready_live_response_commands
    placeholders = enforce_argument_placeholders(playbook, placeholders)

    playbook_name = playbook_path[playbook_path.rfind("/") + 1 : playbook_path.rfind(".")]
    cleanup_commands = []
    playbook_commands = [cmd for cmd in playbook.sections() if cmd not in IGNORED_SECTIONS]
    if separate_cleanup:
        playbook_commands = [
            cmd for cmd in playbook.sections() if cmd not in IGNORED_SECTIONS and not cmd.startswith("cleanup")
        ]
        cleanup_commands = [
            cmd for cmd in playbook.sections() if cmd not in IGNORED_SECTIONS and cmd.startswith("cleanup")
        ]

    # make sure requirements are met first
    for command in playbook_commands:
        op = playbook[command]["operation"].upper()
        if op not in REQUIRED_OP_KEY_MAP:
            LOGGER.error("{op} is not a recognized operation")
            return False
        if operation_missing_required_keys(playbook, command, REQUIRED_OP_KEY_MAP[op]):
            return False

    LOGGER.info(f"building live response commands defined by {playbook_name}")

    for command in playbook_commands:
        op = playbook[command]["operation"].upper()
        post_completion_command = playbook[command].get("post_completion_command", None)

        if op == "RUN":
            command_string = playbook[command]["command"]
            wait_for_output = playbook[command].getboolean("wait_for_output", True)
            remote_output_file_name = playbook[command].get("remote_output_file_name", None)
            working_directory = playbook[command].get("working_directory", None)
            wait_timeout = playbook[command].getint("wait_timeout", 30)
            wait_for_completion = playbook[command].getboolean("wait_for_completion", True)
            print_results = playbook[command].getboolean("print_results", True)
            write_results_path = playbook[command].get("write_results_path", False)

            cmd = ExecuteCommand(
                command_string,
                wait_for_output=wait_for_output,
                remote_output_file_name=remote_output_file_name,
                working_directory=working_directory,
                wait_timeout=wait_timeout,
                wait_for_completion=wait_for_completion,
                print_results=print_results,
                write_results_path=write_results_path,
                placeholders=placeholders,
                post_completion_command=post_completion_command,
            )
            LOGGER.debug(f"built {cmd}")
            ready_live_response_commands.append(cmd)

        elif op == "DOWNLOAD" or op == "PUT":
            file_path = playbook[command]["file_path"]
            client_file_path = playbook[command]["client_file_path"]

            if not os.path.exists(file_path):
                original_fp = file_path
                file_path = os.path.join(BASE_DIR, file_path)
                if not os.path.exists(file_path):
                    LOGGER.error(f"Not found: '{original_fp}' OR '{file_path}'")
                    return False

            file_name = get_os_independent_filepath(file_path).name

            cmd = PutFile(
                file_path,
                sensor_write_filepath=client_file_path,
                placeholders=placeholders,
                post_completion_command=post_completion_command,
            )
            cmd.description = f"Put '{file_name}' on device @ '{client_file_path}'"
            LOGGER.debug(f"built {cmd}")
            ready_live_response_commands.append(cmd)

        elif op == "UPLOAD" or op == "GET":
            path = playbook[command]["path"]
            write_results_path = playbook[command].get("write_results_path", None)
            cmd = GetFile(
                path,
                output_filename=write_results_path,
                placeholders=placeholders,
                post_completion_command=post_completion_command,
            )
            LOGGER.debug(f"built {cmd}")
            ready_live_response_commands.append(cmd)

    if separate_cleanup:
        ready_live_response_cleanup_commands = []
        unique_cleanup_commands = []
        for command in cleanup_commands:
            op = playbook[command]["operation"].upper()

            if op == "RUN":
                command_string = playbook[command]["command"]
                if command_string in unique_cleanup_commands:
                    continue
                unique_cleanup_commands.append(command_string)
                wait_for_output = playbook[command].getboolean("wait_for_output", True)
                remote_output_file_name = playbook[command].get("remote_output_file_name", None)
                working_directory = playbook[command].getboolean("working_directory", None)
                wait_timeout = playbook[command].getint("wait_timeout", 30)
                wait_for_completion = playbook[command].getboolean("wait_for_completion", True)
                print_results = playbook[command].getboolean("print_results", True)
                write_results_path = playbook[command].get("write_results_path", False)

                cmd = ExecuteCommand(
                    command_string,
                    wait_for_output=wait_for_output,
                    remote_output_file_name=remote_output_file_name,
                    working_directory=working_directory,
                    wait_timeout=wait_timeout,
                    wait_for_completion=wait_for_completion,
                    print_results=print_results,
                    write_results_path=write_results_path,
                    placeholders=placeholders,
                )
                LOGGER.debug(f"built {cmd}")
                ready_live_response_commands.append(cmd)

        return ready_live_response_commands, ready_live_response_cleanup_commands

    return ready_live_response_commands


# Remediation section begins #

REMEDIATION_TEMPLATE_PATH = os.path.join(BASE_DIR, "templates/remediate.ini")


def write_remediation_template(template_path=REMEDIATION_TEMPLATE_PATH):
    """Write the example template to the current working dir."""
    from shutil import copyfile

    destination = template_path[template_path.rfind("/") + 1 :]
    copyfile(template_path, destination)
    return destination


def load_live_response_script(remediation_script_path):
    """Load live response script config from path."""
    script = ConfigParser()
    if not os.path.exists(remediation_script_path):
        remediation_script_path = os.path.join(BASE_DIR, remediation_script_path)
    if not os.path.exists(remediation_script_path):
        script_name = remediation_script_path[
            remediation_script_path.rfind("/") + 1 : remediation_script_path.rfind(".")
        ]
        LOGGER.error(f"Path to '{script_name}' script does not exist: {remediation_script_path}")
        return False
    LOGGER.debug(f"loading script path: {remediation_script_path}")
    try:
        script.read(remediation_script_path)
    except Exception as e:
        LOGGER.error("ConfigParser Error reading '{remediation_script_path}' : {e}")
        return False
    return script


def build_remediation_commands(remediation_script_path):
    """Return Live Response Session Commands described by this script."""
    from cbinterface.config import get_playbook_map

    file_paths = []
    process_names = []
    process_ids = []
    scheduled_tasks = []
    services = []
    directories = []
    reg_key_values = []
    reg_keys = []

    script = load_live_response_script(remediation_script_path)
    if not script:
        return False

    cleanup_commands = []
    remediation_commands = []

    for remediation_type in SUPPORTED_LR_SCRIPT_KEYS:
        remediation_function_or_play = LR_REMEDIATION_MAP[remediation_type]

        if script.has_section(remediation_type):
            for remediation_key, remediation_item in script[remediation_type].items():
                if remediation_function_or_play is NotImplemented:
                    LOGGER.warning(f"{remediation_type} remediation is NotImplemented yet.")
                    continue
                elif isinstance(remediation_function_or_play, str) and remediation_function_or_play.startswith(
                    "playbook"
                ):
                    playbook = load_playbook(remediation_function_or_play)
                    if not playbook:
                        continue
                    placeholder_argument_name = playbook.get("overview", "required_arguments", fallback="").split(",")[
                        0
                    ]
                    if not placeholder_argument_name:
                        continue
                    placeholders = {placeholder_argument_name: remediation_item}
                    cmds = build_playbook_commands(remediation_function_or_play, placeholders=placeholders)
                    remediation_commands.extend(cmds)
                else:
                    cmd = remediation_function_or_play(remediation_item)
                    LOGGER.info(f"created {cmd}")
                    remediation_commands.append(cmd)

    return remediation_commands
