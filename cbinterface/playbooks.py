import os
import logging

from configparser import ConfigParser
from typing import Union, List

from cbapi.psc import Device
from cbapi.psc.devices_query import DeviceSearchQuery
from cbapi.live_response_api import CbLRManagerBase

from cbinterface.helpers import get_os_independant_filepath, input_with_timeout

# TODO Make scripts support all commands
from cbinterface.commands import (
    PutFile,
    GetFile,
    ExecuteCommand,
)

# GLOBALS #
LOGGER = logging.getLogger("cbinterface." + __name__)

IGNORED_SECTIONS = ["overview"]

REQUIRED_CMD_KEYS = ["operation"]
REQUIRED_OP_KEY_MAP = {
    "RUN": ["command"],
    "UPLOAD": ["path"],
    "DOWNLOAD": ["file_path"],
}
""" # remove?
OPTIONAL_CMD_KEYS = ['wait_for_completion', 'get_results']
OPTIONAL_OP_KEY_MAP = {'RUN': ['async_run', 'write_results_path', 'print_results',
                               'common_setup_command', 'common_cleanup_command'],
                       'UPLOAD': ['write_results_path'],
                       'DOWNLOAD': ['client_file_path', 'common_setup_command']
                       } 
"""

# Get the working directory
BASE_DIR = os.path.dirname(os.path.abspath(__file__))


def playbook_missing_required_keys(config, KEYS):
    for key in KEYS:
        for section in config.sections():
            if section in IGNORED_SECTIONS:
                return False
            if not config.has_option(section, key):
                LOGGER.error("{} is missing required key: {}".format(section, key))
                return True
    return False


def operation_missing_required_keys(config, section, KEYS):
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
        prompt = f"playbook needs argument {arg}: "
        placeholders[arg] = input_with_timeout(prompt)
    return placeholders


def build_playbook_commands(playbook_path, placeholders={}):
    """Build the live response commands that define this playbook.

    Args:
        lrsm: A CbLRManagerBase based object (CustomLiveResponseSessionManager)
        devices: iterable of Devices/Sensors (TODO: sensors)
    Returns: List of Cb live response commands.
    """

    ready_live_response_commands = []

    playbook = load_playbook(playbook_path)
    placeholders = enforce_argument_placeholders(playbook, placeholders)

    playbook_name = playbook_path[playbook_path.rfind("/") + 1 : playbook_path.rfind(".")]
    playbook_commands = [cmd for cmd in playbook.sections() if cmd not in IGNORED_SECTIONS]

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

        if op == "RUN":
            command_string = playbook[command]["command"]
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
            )
            cmd.placeholders = placeholders
            LOGGER.debug(f"built {cmd}")
            ready_live_response_commands.append(cmd)

        elif op == "DOWNLOAD" or op == "PUT":
            file_path = playbook[command]["file_path"].format(**placeholders)
            client_file_path = playbook[command]["client_file_path"].format(**placeholders)

            if not os.path.exists(file_path):
                original_fp = file_path
                file_path = os.path.join(BASE_DIR, file_path)
                if not os.path.exists(file_path):
                    LOGGER.error("Not found: '{original_fp}' OR '{file_path}'")
                    return False

            file_name = get_os_independant_filepath(file_path).name

            cmd = PutFile(file_path, sensor_write_filepath=client_file_path)
            cmd.description = f"Put '{file_name}' on device @ '{client_file_path}'"
            LOGGER.debug(f"built {cmd}")
            ready_live_response_commands.append(cmd)

        elif op == "UPLOAD" or op == "GET":
            path = playbook[command]["path"].format(**placeholders)
            write_results_path = playbook[command].get("write_results_path", None)
            cmd = GetFile(path, output_filename=write_results_path)
            LOGGER.debug(f"built {cmd}")
            ready_live_response_commands.append(cmd)

    return ready_live_response_commands
