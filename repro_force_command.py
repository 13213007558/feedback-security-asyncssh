#!/usr/bin/env python3
"""Demonstrate combined enforcement of certificate force-command and
authorized_keys command= restrictions in AsyncSSH.

Two harmless "command recorder" strings (recorder-alpha / recorder-beta)
are used as forced commands. The server session never executes anything;
it only records which command the executor was asked to run.
"""

import asyncio
import logging
import os
import socket
import tempfile

import asyncssh
from asyncssh.packet import String

RECORDER_ALPHA = 'recorder-alpha'
RECORDER_BETA = 'recorder-beta'
CLIENT_COMMAND = 'client-requested-command'


class LogCapture(logging.Handler):
    """Capture asyncssh server-side request log lines"""

    def __init__(self):
        super().__init__(level=logging.INFO)
        self.lines = []

    def emit(self, record):
        msg = record.getMessage()
        if any(key in msg for key in ('Command:', 'Subsystem:',
                                      'Forced command',
                                      'Session already requested')):
            self.lines.append(msg.strip())


class Recorder(object):
    """What the trusted executor was asked to run, and channel state"""

    def __init__(self):
        self.calls = []
        self.channels = []


class RecorderSession(asyncssh.SSHServerSession):
    """Harmless command recorder -- logs requests, executes nothing"""

    def __init__(self, recorder):
        self._recorder = recorder
        self._chan = None

    def connection_made(self, chan):
        self._chan = chan
        self._recorder.channels.append(chan)

    def shell_requested(self):
        self._recorder.calls.append(('shell', None))
        return True

    def exec_requested(self, command):
        self._recorder.calls.append(('exec', command))
        return True

    def subsystem_requested(self, subsystem):
        self._recorder.calls.append(('subsystem', subsystem))
        return True


class Server(asyncssh.SSHServer):
    """SSH server requiring public key auth against authorized_keys"""

    def __init__(self, recorder):
        self._recorder = recorder

    def begin_auth(self, username):
        return True

    def session_requested(self):
        return RecorderSession(self._recorder)


class ClientSession(asyncssh.SSHClientSession):
    """Minimal client session"""


def make_fixture(tmpdir, cert_command, key_command):
    """Build CA/client keys, certificate, and authorized_keys content"""

    ca_key = asyncssh.generate_private_key('ssh-ed25519')
    client_key = asyncssh.generate_private_key('ssh-ed25519')
    server_key = asyncssh.generate_private_key('ssh-ed25519')

    if cert_command is not None:
        cert = ca_key.generate_user_certificate(
            client_key, 'demo', principals=['demo'],
            force_command=cert_command)
        client_keys = [(client_key, cert)]
        ak_key = ca_key
        ak_options = ['cert-authority']
    else:
        client_keys = [client_key]
        ak_key = client_key
        ak_options = []

    if key_command is not None:
        ak_options.append('command="%s"' % key_command)

    ak_path = os.path.join(tmpdir, 'authorized_keys')
    with open(ak_path, 'w') as ak_file:
        ak_file.write((','.join(ak_options) + ' ' if ak_options else '') +
                      ak_key.export_public_key().decode())

    return client_keys, ak_path, server_key


async def run_scenario(name, cert_command, key_command, request):
    """Run one scenario and print what the executor observed"""

    recorder = Recorder()
    capture = LogCapture()
    logging.getLogger('asyncssh').addHandler(capture)
    asyncssh.set_log_level('INFO')

    print('%s:' % name)
    print('  cert force-command: %r, authorized_keys command: %r' %
          (cert_command, key_command))

    with tempfile.TemporaryDirectory() as tmpdir:
        client_keys, ak_path, server_key = make_fixture(
            tmpdir, cert_command, key_command)

        loop = asyncio.get_event_loop()

        server_options = await asyncssh.SSHServerConnectionOptions.construct(
            None, server_factory=lambda: Server(recorder),
            server_host_keys=[server_key],
            authorized_client_keys=ak_path)

        client_sock, server_sock = socket.socketpair()

        _, server_conn = await loop.create_connection(
            lambda: asyncssh.SSHServerConnection(loop, server_options),
            sock=server_sock)

        try:
            try:
                async with asyncssh.connect(
                        'localhost', sock=client_sock, username='demo',
                        client_keys=client_keys,
                        known_hosts=None, agent_path=None) as conn:
                    if request == 'exec':
                        chan, _ = await conn.create_session(ClientSession,
                                                            CLIENT_COMMAND)
                    elif request == 'shell':
                        chan, _ = await conn.create_session(ClientSession)
                    elif request == 'subsystem':
                        chan, _ = await conn.create_session(
                            ClientSession, subsystem='sftp')

                    if request == 'repeat':
                        chan, _ = await conn.create_session(ClientSession,
                                                            CLIENT_COMMAND)
                        second = await chan._make_request(
                            b'exec', String('second-command'))
                        print('  second exec on same channel accepted: %s'
                              % second)
                    chan.close()
                    await chan.wait_closed()
            except asyncssh.ChannelOpenError as exc:
                print('  session request REJECTED: %s' % exc.reason)
        finally:
            server_conn.close()
            await server_conn.wait_closed()

    started = [chan._session_started for chan in recorder.channels]
    print('  executor calls: %s' % (recorder.calls or 'NONE'))
    print('  server channel(s) marked started: %s' % (started or 'NONE'))
    for line in capture.lines:
        print('  server log: %s' % line)
    print()


async def main():
    print('=== Repro: both sources set, different commands ===')
    await run_scenario('cert=alpha + authorized_keys=beta (exec)',
                       RECORDER_ALPHA, RECORDER_BETA, 'exec')

    print('=== Consistent configuration ===')
    await run_scenario('cert=alpha + authorized_keys=alpha (exec)',
                       RECORDER_ALPHA, RECORDER_ALPHA, 'exec')
    await run_scenario('cert=alpha + authorized_keys=alpha (shell)',
                       RECORDER_ALPHA, RECORDER_ALPHA, 'shell')
    await run_scenario('cert=alpha + authorized_keys=alpha (subsystem)',
                       RECORDER_ALPHA, RECORDER_ALPHA, 'subsystem')

    print('=== Single-source configuration ===')
    await run_scenario('cert=alpha only (exec)',
                       RECORDER_ALPHA, None, 'exec')
    await run_scenario('authorized_keys=beta only (exec)',
                       None, RECORDER_BETA, 'exec')

    print('=== Conflicting configuration: all request types ===')
    await run_scenario('conflict (shell)',
                       RECORDER_ALPHA, RECORDER_BETA, 'shell')
    await run_scenario('conflict (subsystem)',
                       RECORDER_ALPHA, RECORDER_BETA, 'subsystem')

    print('=== Repeated session request on the same channel ===')
    await run_scenario('match, second exec on same channel',
                       RECORDER_ALPHA, RECORDER_ALPHA, 'repeat')


asyncio.run(main())
