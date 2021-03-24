"""All things LR sessions."""

import io
import os
import time
import logging
import threading

from cbapi.psc import Device
from cbapi.psc.threathunter import CbThreatHunterAPI
from cbapi.psc.cblr import (
    LiveResponseSession,
    LiveResponseSessionManager,
    LiveResponseJobScheduler,
    WorkItem,
    JobWorker,
)
from cbapi.errors import ObjectNotFoundError, TimeoutError

# from cbapi.live_response_api import CbLRManagerBase, WorkItem, poll_status

from typing import List, Union

from cbinterface.commands import BaseSessionCommand
from cbinterface.psc.device import is_device_online

LOGGER = logging.getLogger("cbinterface.psc.session")

CBLR_BASE = "/integrationServices/v3/cblr"


class CustomLiveResponseJobScheduler(LiveResponseJobScheduler):
    def __init__(self, cb, psc_cb, max_workers=10):
        self.psc_cb = psc_cb
        super().__init__(cb, max_workers=10)

    def _spawn_new_workers(self):
        if len(self._job_workers) >= self._max_workers:
            return

        schedule_max = self._max_workers - len(self._job_workers)

        devices = [
            s for s in self.psc_cb.select(Device) if s.id in self._unscheduled_jobs and s.id not in self._job_workers
        ]
        # and is_device_online(s)]

        devices_to_schedule = devices[:schedule_max]
        LOGGER.debug("Spawning new workers to handle these devices: {0}".format(devices_to_schedule))
        for device in devices_to_schedule:
            LOGGER.debug("Spawning new JobWorker for device id {0}".format(device.id))
            self._job_workers[device.id] = JobWorker(self._cb, device.id, self.schedule_queue)
            self._job_workers[device.id].start()


class CustomLiveResponseSessionManager(LiveResponseSessionManager):
    def __init__(self, cb, timeout=30, custom_session_keepalive=False):
        # First, get a CB object with the LR API permissions
        cblr = CbThreatHunterAPI(url=cb.credentials.url, token=cb.credentials.lr_token, org_key=cb.credentials.org_key)
        super().__init__(cblr, timeout=timeout, keepalive_sessions=False)
        # so now self._cb == cblr -- store a reference to the regular cb
        self.psc_cb = cb

        if custom_session_keepalive:
            self._cleanup_thread = threading.Thread(target=self._keep_active_sessions_alive_thread)
            self._cleanup_thread.daemon = True
            self._cleanup_thread.start()

        # for storing initiatied commands
        self.commands = []

    def get_session(self, device: Device):
        """Get or create LR session."""
        session_data = self._cb.post_object(f"{CBLR_BASE}/session/{device.id}", {"sensor_id": device.id}).json()
        session_id = session_data["id"]
        LOGGER.debug(f"got session id={session_id} with status={session_data['status']}")
        self._sessions[device.id] = self.cblr_session_cls(self, session_id, device.id, session_data=session_data)
        return self._sessions[device.id]

    def wait_for_active_session(self, device: Device, timeout=86400):
        """Return active session or None.

        Default timeout is 7 days.
        """
        LOGGER.info(
            f"attempting to get active session on device {device.id} (hostname:{device.name}) for up to {timeout/60} minutes"
        )
        start_time = time.time()
        session = None
        status = None
        while status != "ACTIVE" and time.time() - start_time < timeout:
            if not is_device_online(device):
                LOGGER.debug(f"waiting for device {device.id} to come online...")
                time.sleep(1)
                continue
            session = self.get_session(device)
            status = session.session_data["status"]
            time.sleep(0.5)

        if session and is_session_active(session):
            LOGGER.info(f"got active session {session.session_id}.")
        return session

    def submit_command(self, command: BaseSessionCommand, device: Union[int, Device]):
        """
        Create a new job to be executed as a Live Response.

        Args:
            command (BaseSessionCommand): The job to be scheduled.
            device (Device): Device to execute job on.
        Returns:
            Future: A reference to the running job.
        """
        assert isinstance(command, BaseSessionCommand)

        device_id = device
        if isinstance(device, Device):
            device_id = device.id
            command._hostname = device.name
        LOGGER.debug(f"submitting {command} to {device_id}")

        if self._job_scheduler is None:
            # spawn the scheduler thread
            self._job_scheduler = CustomLiveResponseJobScheduler(self._cb, self.psc_cb)
            self._job_scheduler.start()

        if device_id not in self._sessions:
            device = Device(self._cb, device_id, force_init=True)
            active_session = self.active_session(device)
            if active_session is None:
                self.wait_for_active_session(device)

        work_item = WorkItem(command.run, device_id)
        self._job_scheduler.submit_job(work_item)
        command.future = work_item.future
        command.device_id = device_id
        command.session_id = self._sessions[device_id].session_id
        command.session_data = self._sessions[device_id].session_data
        self.commands.append(command)
        return command

    def yield_completed_commands(self):
        """Wait for commands to complete, process results.

        Monitor commands and sessions.
        """
        LOGGER.info(f"waiting for {len(self.commands)} commands to complete ...")
        while self.commands:
            for cmd in self.commands:
                if not cmd.initiatied:
                    LOGGER.error(f"skipping uninitialized command: {cmd}")
                    self.commands.remove(cmd)
                    continue
                if cmd.exception:
                    LOGGER.error(f"exception for {cmd}: {cmd.exception}")
                    self.commands.remove(cmd)
                    continue
                if not get_session_by_id(self._cb, cmd.session_id):
                    LOGGER.error(f"session {cmd.session_id} is gone. command has gone to the void: {cmd}")
                    self.commands.remove(cmd)
                    continue

                if cmd.has_result:
                    LOGGER.debug(f"yielding {cmd}")
                    yield cmd
                    self.commands.remove(cmd)

                # yield time for completion
                time.sleep(0.7)

    def process_completed_commands(self):
        for cmd in self.yield_completed_commands():
            LOGGER.debug(f"processing => {cmd}")
            cmd.process_result()

    def _keep_active_sessions_alive_thread(self):
        """Used by a thread to ping active sessions so they don't
        close on long running session commands.
        """
        LOGGER.debug("Starting custom Live Response session keepalive and cleanup task")
        while True:
            time.sleep(self._timeout)

            delete_list = []
            with self._session_lock:
                for session in self._sessions.values():
                    if session._refcount == 0:
                        delete_list.append(session.device_id)
                    else:
                        try:
                            if is_session_active(session):
                                LOGGER.info(f"sending keepalive for session {session.session_id}")
                                self._send_keepalive(session.session_id)
                        except ObjectNotFoundError:
                            LOGGER.debug(
                                f"Session {session.session_id} for device {session.device_id} not valid any longer, removing from cache"
                            )
                            delete_list.append(session.device_id)
                        except Exception as e:
                            LOGGER.warning(
                                f"Keepalive on session {session.session_id} (device {session.device_id}) failed with unknown error: {e}"
                            )
                            delete_list.append(session.device_id)

                for device_id in delete_list:
                    self._close_session(self._sessions[device_id].session_id)
                    del self._sessions[device_id]


def all_live_response_sessions(cb: CbThreatHunterAPI) -> List:
    """List all LR sessions still in server memory."""
    return [sesh for sesh in cb.get_object(f"{CBLR_BASE}/session")]


def active_live_response_sessions(cb: CbThreatHunterAPI) -> List:
    """Return active LR sessions."""
    return [sesh for sesh in cb.get_object(f"{CBLR_BASE}/session?active_only=true")]


def device_live_response_sessions(device: Device, active_or_pending=False):
    """Get sessions associated to this device."""
    sessions = [session for session in all_live_response_sessions(device._cb) if session["device_id"] == device.id]
    if active_or_pending:
        return [session for session in sessions if session["status"] == "active" or session["status"] == "pending"]
    return sessions


def device_live_response_sessions_by_device_id(cb: CbThreatHunterAPI, device_id: Union[int, str]):
    """Get sessions associated to this device by device id."""
    if isinstance(device_id, str):
        device_id = int(device_id)
    sessions = [session for session in all_live_response_sessions(cb) if session["device_id"] == device_id]
    return sessions


def get_session_by_id(cb: CbThreatHunterAPI, session_id):
    """Get a LR session object by id."""
    try:
        return cb.get_object(f"{CBLR_BASE}/session/{session_id}")
    except ObjectNotFoundError:
        LOGGER.warning(f"no live resonse session by ID={session_id}")
        return None


def close_session_by_id(cb: CbThreatHunterAPI, session_id):
    """Close a session by ID."""
    return cb.put_object(f"{CBLR_BASE}/session", {"session_id": session_id, "status": "CLOSE"}).json()


def get_session_status(cb: CbThreatHunterAPI, session_id):
    """Return any session status or None."""
    session = get_session_by_id(cb, session_id)
    if session is None:
        return None
    return session["status"]


def is_session_active(session: LiveResponseSession):
    """Return True if session is active."""
    if session.session_data["status"] == "ACTIVE":
        return True
    return False


def get_session_commands(cb: CbThreatHunterAPI, session_id: str):
    """List commands for this session."""
    try:
        return cb.get_object(f"{CBLR_BASE}/session/{session_id}/command")
    except ObjectNotFoundError:
        LOGGER.warning(f"no live resonse session by ID={session_id}")
        return None


def get_command_result(cb: CbThreatHunterAPI, session_id: str, command_id: str):
    """Get results of a LR session command."""
    try:
        return cb.get_object(f"{CBLR_BASE}/session/{session_id}/command/{command_id}")
    except ObjectNotFoundError:
        LOGGER.warning(f"no live resonse session and/or command combination for {session_id}:{command_id}")
        return None


def get_file_content(cb: CbThreatHunterAPI, session_id: str, file_id: str):
    """Get file content stored in LR session and write the file locally."""
    from cbinterface.helpers import get_os_independent_filepath

    try:
        real_session_id, device_id = session_id.split(":", 1)
        filename = f"{real_session_id}_on_{device_id}"
        file_metadata = cb.get_object(f"{CBLR_BASE}/session/{session_id}/file/{file_id}")
        if file_metadata:
            filepath = get_os_independent_filepath(file_metadata["file_name"])
            filename = f"{filename}_{filepath.name}"
        result = cb.session.get(f"{CBLR_BASE}/session/{session_id}/file/{file_id}/content", stream=True)
        if result.status_code != 200:
            LOGGER.error(
                f"got {result.status_code} from server getting file {file_id} content for session {session_id}"
            )
            return
        with open(filename, "wb") as fp:
            for chunk in result.iter_content(io.DEFAULT_BUFFER_SIZE):
                fp.write(chunk)
        if os.path.exists(filename):
            LOGGER.info(f"wrote: {filename}")
        return os.path.exists(filename)
    except ObjectNotFoundError:
        LOGGER.warning(f"no file {file_id} content with session {session_id}")
        return
