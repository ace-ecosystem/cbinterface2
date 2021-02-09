"""All things LR session and job/command management."""

import time
import logging
import threading

from concurrent.futures import Future

from cbapi.response.cblr import LiveResponseSession, LiveResponseSessionManager
from cbapi.response import CbResponseAPI, Sensor
from cbapi.errors import ObjectNotFoundError, TimeoutError
from cbapi.live_response_api import CbLRManagerBase, LiveResponseJobScheduler, WorkItem,  poll_status

from typing import List, Union

from cbinterface2.sensor import is_sensor_online

CBLR_BASE = "/api/v1/cblr"

class BaseSessionCommand():
    """For storing and managing session commands.

    Session Commands are 'jobs' with concurrent.futures.
    """
    def __init__(self, description):
        self.description = description
        self.future = None
        self.session_id = None
        self.sensor_id = None
        self._exception = None
        self._result = None

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
        """The function to implement the live response command logic.
        """
        raise NotImplemented()

    def process_result(self):
        """Implement logic to process any results."""
        pass

    def __str__(self):
        return f"LrSessionCommand: {self.description} - status: {self.status}"


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

    def get_session(self, sensor: Sensor):
        """Get or create LR session."""
        active = sensor_live_response_sessions(sensor, active_or_pending=True)
        if active:
            session_data = active[0]
            session_id = session_data['id']
            logging.info(f"found existing session id={session_id} in '{session_data['status']}' state")
            self._sessions[sensor.id] = self.cblr_session_cls(self, session_id, sensor.id, session_data=session_data)
            return self._sessions[sensor.id] 

        session_data = self._cb.post_object(f"{CBLR_BASE}/session", {'sensor_id': sensor.id}).json()
        session_id = session_data["id"]
        logging.info(f"created session id={session_id}")
        self._sessions[sensor.id] = self.cblr_session_cls(self, session_id, sensor.id, session_data=session_data)
        return self._sessions[sensor.id]

    def wait_for_active_session(self, sensor: Sensor, timeout=86400):
        """Return active session or None.
        
        Default timeout is 7 days.
        """
        logging.info(f"attempting to get active session on sensor {sensor.id} (hostname:{sensor.hostname}) for up to {timeout/60} minutes")
        start_time = time.time()
        session = None
        status = None
        while status != 'active' and time.time() - start_time < timeout:
            if not is_sensor_online(sensor):
                logging.debug(f"waiting for sensor {sensor.id} to come online...")
                time.sleep(1)
                continue
            if status is None:
                session = self.get_session(sensor)
            status = get_session_status(self._cb, session.session_id)
            time.sleep(0.5)

        if session and is_session_active(session):
            logging.info(f"got active session {session.session_id} on sensor {sensor.id}.")
        return session

    def submit_command(self, command: BaseSessionCommand, sensor: Sensor):
        """
        Create a new job to be executed as a Live Response.

        Args:
            command (BaseSessionCommand): The job to be scheduled.
            sensor (Sensor): Sensor to execute job on.
        Returns:
            Future: A reference to the running job.
        """
        assert isinstance(command, BaseSessionCommand)

        if self._job_scheduler is None:
            # spawn the scheduler thread
            self._job_scheduler = LiveResponseJobScheduler(self._cb)
            self._job_scheduler.start()

        work_item = WorkItem(command.run, sensor)
        self._job_scheduler.submit_job(work_item)
        command.future = work_item.future
        command.sensor_id = sensor.id
        command.session_id = self._sessions[sensor.id].session_id
        self.commands.append(command)
        return command

    def yield_completed_commands(self):
        """Wait for commands to complete, process results.

        Monitor commands and sessions.
        """
        logging.info(f"waiting for {len(self.commands)} commands to complete ...")
        while self.commands:
            for cmd in self.commands:
                if not cmd.initiatied:
                    logging.error(f"Skipping uninitialized command: {cmd}")
                    self.commands.remove(cmd)
                    continue
                if cmd.exception:
                    logging.error(f"command encountered exception: {cmd}")
                    logging.error(f"exception for {cmd}: {cmd.exception}")
                    self.commands.remove(cmd)
                    continue
                if not get_session_by_id(self._cb, cmd.session_id):
                    logging.error(f"session {cmd.session_id} is gone. command has gone to the void: {cmd}")
                    self.commands.remove(cmd)
                    continue

                if cmd.has_result:
                    logging.debug(f"yielding {cmd}")
                    yield cmd
                    self.commands.remove(cmd)

                # yield time for completion
                time.sleep(0.7)

    def process_completed_commands(self):
        for cmd in self.yield_completed_commands():
            logging.info(f"processing => {cmd}")
            cmd.process_result()

    def _keep_active_sessions_alive_thread(self):
        """Used by a thread to ping active sessions so they don't
           close on long running session commands.
        """
        logging.debug("Starting custom Live Response session keepalive and cleanup task")
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
                                logging.info(f"sending keepalive for session {session.session_id}")
                                self._send_keepalive(session.session_id)
                        except ObjectNotFoundError:
                            logging.debug(f"Session {session.session_id} for sensor {session.sensor_id} not valid any longer, removing from cache")
                            delete_list.append(session.sensor_id)
                        except Exception as e:
                            logging.warning(f"Keepalive on session {session.session_id} (sensor {session.sensor_id}) failed with unknown error: {e}")
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
    sessions = [session for session in all_live_response_sessions(sensor._cb) if session['sensor_id'] == sensor.id]
    if active_or_pending:
        return [session for session in sessions if session['status'] == 'active' or session['status'] == 'pending']
    return sessions

def sensor_live_response_sessions_by_sensor_id(cb: CbResponseAPI, sensor_id: Union[int, str]):
    """Get sessions associated to this sensor by sensor id."""
    if isinstance(sensor_id, str):
        sensor_id = int(sensor_id)
    sessions = [session for session in all_live_response_sessions(cb) if session['sensor_id'] == sensor_id]
    return sessions

def get_session_by_id(cb: CbResponseAPI, session_id):
    """Get a LR session object by id."""
    try:
        return cb.get_object(f"{CBLR_BASE}/session/{session_id}")
    except ObjectNotFoundError:
        logging.warning(f"no live resonse session by ID={session_id}")
        return None

def get_session_status(cb: CbResponseAPI, session_id):
    """Return any session status or None."""
    session = get_session_by_id(cb, session_id)
    if session is None:
        return None
    return session['status']

def is_session_active(session: LiveResponseSession):
    """Return True if session is active."""
    session_data = get_session_by_id(session._cb, session.session_id)
    if session_data is None:
        return None
    if session_data['status'] == 'active':
        return True
    return False

def get_session_commands(cb: CbResponseAPI, session_id: str):
    """List commands for this session."""
    try:
        return cb.get_object(f"{CBLR_BASE}/session/{session_id}/command")
    except ObjectNotFoundError:
        logging.warning(f"no live resonse session by ID={session_id}")
        return None

def stream_command_result(cb: CbResponseAPI, session_id: str, command_id: str):
    """Get results of a LR session command."""
    try:
        return cb.session.get(f"{CBLR_BASE}/session/{session_id}/command/{command_id}", stream=True)
    except ObjectNotFoundError:
        logging.warning(f"no live resonse session by ID={session_id}")
        return None

def get_command_result(cb: CbResponseAPI, session_id: str, command_id: str):
    result = stream_command_result(cb, session_id, command_id)
    if result is None:
        return None
    if result.status_code != 200:
        logging.error(f"got {result.status_code} from server getting result of command {command_id} for session {session_id}")
        return None
    content = b''
    for chunk in result.iter_content(io.DEFAULT_BUFFER_SIZE):
        content += chunk
    return content

""" 
# Unused code for removal. 
def wait_for_jobs(jobs: Dict, timeout=300):
    start_time = time.time()
    timeout = start_time + timeout
    work = list(jobs.keys())
    logging.info(f"waiting for {work} job(s) to complete or timeout...")
    while len(work) > 0:
        # iterate over all the futures
        for f in jobs.keys():
            sensor_id = jobs[f]['sensor_id']
            if not f.done():
                continue
            if f.exception() is None:
                print(f"Sensor {sensor_id} has result:")
                yield f
                #pprint(f.result())
                #completed_sensors.append(futures[f])
            else:
                print(f"Sensor {sensor_id} had error:")
                print(f.exception())
            work.remove(f)
        time.sleep(1)
        if time.time() > timeout:
            logging.warning(f"reached timeout waiting for {len(jobs)} to complete.")
            break
"""