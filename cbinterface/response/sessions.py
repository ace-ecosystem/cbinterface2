"""All things LR sessions."""

import io
import os
import time
import logging
import threading

from cbapi.response.cblr import LiveResponseSession, LiveResponseSessionManager
from cbapi.response import CbResponseAPI, Sensor
from cbapi.errors import ObjectNotFoundError, TimeoutError
from cbapi.live_response_api import CbLRManagerBase, LiveResponseJobScheduler, WorkItem, poll_status

from typing import List, Union

from cbinterface.commands import BaseSessionCommand
from cbinterface.response.sensor import is_sensor_online

LOGGER = logging.getLogger("cbinterface.response.session")

CBLR_BASE = "/api/v1/cblr"


class CustomLiveResponseSessionManager(LiveResponseSessionManager):
    def __init__(self, cb, timeout=30, custom_session_keepalive=False):
        super().__init__(cb, timeout=timeout, keepalive_sessions=False)
        # NOTE: keepalives will automatically close any sessions NOT in an active state.
        # So, don't send keepalives to pending sessions or the session will close.
        # For this reason, don't start sessions on sensor until those sensors are online.
        # Still, if a sensor is slow to check in a timing hicup can occur. The result being, a
        # keepalive will close a pending session that would have otherwise have become active.

        if custom_session_keepalive:
            self._cleanup_thread = threading.Thread(target=self._keep_active_sessions_alive_thread)
            self._cleanup_thread.daemon = True
            self._cleanup_thread.start()

        # for storing initiatied commands
        self.commands = []

    def active_session(self, sensor: Sensor):
        """Return any active sessions on this sensor or None."""
        active = sensor_live_response_sessions(sensor, active_or_pending=True)
        if active:
            session_data = active[0]
            session_id = session_data["id"]
            LOGGER.info(f"found existing session id={session_id} in '{session_data['status']}' state")
            self._sessions[sensor.id] = self.cblr_session_cls(self, session_id, sensor.id, session_data=session_data)
            return self._sessions[sensor.id]
        return None

    def get_session(self, sensor: Sensor):
        """Get or create LR session."""
        active_session = self.active_session(sensor)
        if isinstance(active_session, self.cblr_session_cls):
            return active_session

        session_data = self._cb.post_object(f"{CBLR_BASE}/session", {"sensor_id": sensor.id}).json()
        session_id = session_data["id"]
        LOGGER.info(f"created session id={session_id}")
        self._sessions[sensor.id] = self.cblr_session_cls(self, session_id, sensor.id, session_data=session_data)
        return self._sessions[sensor.id]

    def wait_for_active_session(self, sensor: Sensor, timeout=86400):
        """Return active session or None.

        Default timeout is 7 days.
        """
        LOGGER.info(
            f"attempting to get active session on sensor {sensor.id} (hostname:{sensor.hostname}) for up to {timeout/60} minutes"
        )
        start_time = time.time()
        session = None
        status = None
        while status != "active" and time.time() - start_time < timeout:
            if not is_sensor_online(sensor):
                LOGGER.debug(f"waiting for sensor {sensor.id} to come online...")
                time.sleep(1)
                continue
            if status is None:
                session = self.get_session(sensor)
            status = get_session_status(self._cb, session.session_id)
            time.sleep(0.5)

        if session and is_session_active(session):
            LOGGER.info(f"got active session {session.session_id} on sensor {sensor.id}.")
        return session

    def submit_command(self, command: BaseSessionCommand, sensor: Union[int, Sensor]):
        """
        Create a new job to be executed as a Live Response.

        Args:
            command (BaseSessionCommand): The job to be scheduled.
            sensor (Sensor): Sensor to execute job on.
        Returns:
            Future: A reference to the running job.
        """
        assert isinstance(command, BaseSessionCommand)

        sensor_id = sensor
        if isinstance(sensor, Sensor):
            sensor_id = sensor.id

        if self._job_scheduler is None:
            # spawn the scheduler thread
            self._job_scheduler = LiveResponseJobScheduler(self._cb)
            self._job_scheduler.start()

        if sensor_id not in self._sessions:
            sensor = Sensor(self._cb, sensor_id, force_init=True)
            active_session = self.active_session(sensor)
            if active_session is None:
                self.wait_for_active_session(sensor)

        work_item = WorkItem(command.run, sensor_id)
        self._job_scheduler.submit_job(work_item)
        command.future = work_item.future
        command._sensor_id = sensor_id
        command.session_id = self._sessions[sensor_id].session_id
        command.session_data = self._sessions[sensor_id].session_data
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
                        delete_list.append(session.sensor_id)
                    else:
                        try:
                            if is_session_active(session):
                                LOGGER.info(f"sending keepalive for session {session.session_id}")
                                self._send_keepalive(session.session_id)
                        except ObjectNotFoundError:
                            LOGGER.debug(
                                f"Session {session.session_id} for sensor {session.sensor_id} not valid any longer, removing from cache"
                            )
                            delete_list.append(session.sensor_id)
                        except Exception as e:
                            LOGGER.warning(
                                f"Keepalive on session {session.session_id} (sensor {session.sensor_id}) failed with unknown error: {e}"
                            )
                            delete_list.append(session.sensor_id)

                for sensor_id in delete_list:
                    self._close_session(self._sessions[sensor_id].session_id)
                    del self._sessions[sensor_id]


def all_live_response_sessions(cb: CbResponseAPI) -> List:
    """List all LR sessions still in server memory."""
    return [sesh for sesh in cb.get_object(f"{CBLR_BASE}/session")]


def active_live_response_sessions(cb: CbResponseAPI) -> List:
    """Return active LR sessions."""
    return [sesh for sesh in cb.get_object(f"{CBLR_BASE}/session?active_only=true")]


def sensor_live_response_sessions(sensor: Sensor, active_or_pending=False):
    """Get sessions associated to this sensor."""
    sessions = [session for session in all_live_response_sessions(sensor._cb) if session["sensor_id"] == sensor.id]
    if active_or_pending:
        return [session for session in sessions if session["status"] == "active" or session["status"] == "pending"]
    return sessions


def sensor_live_response_sessions_by_sensor_id(cb: CbResponseAPI, sensor_id: Union[int, str]):
    """Get sessions associated to this sensor by sensor id."""
    if isinstance(sensor_id, str):
        sensor_id = int(sensor_id)
    sessions = [session for session in all_live_response_sessions(cb) if session["sensor_id"] == sensor_id]
    return sessions


def get_session_by_id(cb: CbResponseAPI, session_id):
    """Get a LR session object by id."""
    try:
        return cb.get_object(f"{CBLR_BASE}/session/{session_id}")
    except ObjectNotFoundError:
        LOGGER.warning(f"no live resonse session by ID={session_id}")
        return None


def get_session_status(cb: CbResponseAPI, session_id):
    """Return any session status or None."""
    session = get_session_by_id(cb, session_id)
    if session is None:
        return None
    return session["status"]


def is_session_active(session: LiveResponseSession):
    """Return True if session is active."""
    session_data = get_session_by_id(session._cb, session.session_id)
    if session_data is None:
        return None
    if session_data["status"] == "active":
        return True
    return False


def get_session_commands(cb: CbResponseAPI, session_id: str):
    """List commands for this session."""
    try:
        return cb.get_object(f"{CBLR_BASE}/session/{session_id}/command")
    except ObjectNotFoundError:
        LOGGER.warning(f"no live resonse session by ID={session_id}")
        return None


def get_command_result(cb: CbResponseAPI, session_id: str, command_id: str):
    """Get results of a LR session command."""
    try:
        return cb.get_object(f"{CBLR_BASE}/session/{session_id}/command/{command_id}")
    except ObjectNotFoundError:
        LOGGER.warning(f"no live resonse session and/or command combination for {session_id}:{command_id}")
        return None


def get_file_content(cb: CbResponseAPI, session_id: str, file_id: str):
    """Get file content stored in LR session and write the file locally."""
    from cbinterface.helpers import get_os_independent_filepath

    try:
        file_metadata = cb.get_object(f"{CBLR_BASE}/session/{session_id}/file/{file_id}")
        if file_metadata:
            filepath = get_os_independent_filepath(file_metadata["file_name"])
            filename = f"{session_id}_{filepath.name}"
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
