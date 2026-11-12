# Copyright (c) 2026 by Ron Frederick <ronf@timeheart.net> and others.
#
# This program and the accompanying materials are made available under
# the terms of the Eclipse Public License v2.0 which accompanies this
# distribution and is available at:
#
#     http://www.eclipse.org/legal/epl-2.0/
#
# This program may also be made available under the following secondary
# licenses when the conditions for such availability set forth in the
# Eclipse Public License v2.0 are satisfied:
#
#    GNU General Public License, Version 2.0, or any later versions of
#    that license
#
# SPDX-License-Identifier: EPL-2.0 OR GPL-2.0-or-later
#
# Contributors:
#     Ron Frederick - initial implementation, API, and documentation

"""Unit tests for the OpenSSH restrict option in authorized_keys"""

import asyncssh

from asyncssh.packet import Boolean, String, UInt32
from asyncssh.public_key import CERT_TYPE_USER

from unittest.mock import patch

from .server import Server, ServerTestCase
from .util import asynctest, make_certificate


class _RestrictClientChannel(asyncssh.SSHClientChannel):
    """Patched SSH client channel which can make an X11 request"""

    async def make_x11_forwarding_request(self):
        """Make a request to enable X11 forwarding"""

        return await self._make_request(b'x11-req', Boolean(False),
                                        String(b'MIT-MAGIC-COOKIE-1'),
                                        String(b'00' * 16), UInt32(0))


class _RestrictServerSession(asyncssh.SSHServerSession):
    """Server session which counts PTY allocation"""

    def __init__(self):
        self._chan = None
        self._command = ''

    def connection_made(self, chan):
        """Handle session open"""

        self._chan = chan

    def pty_requested(self, term_type, term_size, term_modes):
        """Handle pseudo-terminal request, counting PTY creation"""

        # pylint: disable=unused-argument

        _RestrictServer.pty_count += 1
        return True

    def exec_requested(self, command):
        """Handle exec request"""

        self._command = command
        return True

    def shell_requested(self):
        """Handle shell request"""

        return True

    def session_started(self):
        """Handle session start"""

        _RestrictServer.agent_path_seen = bool(self._chan.get_agent_path())

        if self._command == 'sleep':
            return

        self._chan.write('ok\n')
        self._chan.exit(0)
        self._chan.close()


class _RestrictServer(Server):
    """Server for testing the authorized_keys restrict option"""

    pty_count = 0
    listener_count = 0
    connect_count = 0
    agent_path_seen = False

    @classmethod
    def reset_counts(cls):
        """Reset resource creation counts"""

        cls.pty_count = 0
        cls.listener_count = 0
        cls.connect_count = 0
        cls.agent_path_seen = False

    def session_requested(self):
        """Handle a request to create a new session"""

        return _RestrictServerSession()

    def server_requested(self, listen_host, listen_port):
        """Handle a request to create a listener, counting creations"""

        _RestrictServer.listener_count += 1
        return True

    def connection_requested(self, dest_host, dest_port,
                             orig_host, orig_port):
        """Handle a connection request, counting outbound connections"""

        # pylint: disable=unused-argument

        _RestrictServer.connect_count += 1
        return False


def _write_authorized_keys(filename='authorized_keys_restrict'):
    """Write authorized_keys with restricted entries for the tests"""

    with open('ckey.pub') as f:
        ckey = f.read().strip()

    with open('ckey_ecdsa.pub') as f:
        ckey_ecdsa = f.read().strip()

    # Entry 1: only a fixed command is allowed; all capabilities denied
    # Entry 2: additionally allows PTY allocation
    # Entry 3: CA entry which restores only port forwarding
    with open(filename, 'w') as f:
        f.write(f'restrict,command="echo ok" {ckey}\n')
        f.write(f'restrict,pty,command="echo ok" {ckey_ecdsa}\n')
        f.write(f'cert-authority,principals="ckey",'
                f'restrict,port-forwarding {ckey}\n')


class _TestRestrict(ServerTestCase):
    """Unit tests for the authorized_keys restrict option"""

    @classmethod
    async def start_server(cls):
        """Start an SSH server with restricted authorized_keys entries"""

        _write_authorized_keys()

        return await cls.create_server(
            _RestrictServer, authorized_client_keys='authorized_keys_restrict',
            x11_forwarding=True)

    def setUp(self):
        """Reset resource creation counts"""

        _RestrictServer.reset_counts()

    @asynctest
    async def test_restrict_allows_exec(self):
        """Test that a plain command still runs on a restricted key"""

        async with self.connect(username='ckey', client_keys=['ckey'],
                                agent_path=None) as conn:
            result = await conn.run('echo ok')

            self.assertEqual(result.stdout, 'ok\n')
            self.assertEqual(result.exit_status, 0)

    @asynctest
    async def test_restrict_denies_pty(self):
        """Test that restrict denies PTY allocation before creation"""

        async with self.connect(username='ckey', client_keys=['ckey'],
                                agent_path=None) as conn:
            with self.assertRaises(asyncssh.ChannelOpenError):
                await conn.run('echo ok', term_type='ansi')

            self.assertEqual(_RestrictServer.pty_count, 0)

            result = await conn.run('echo ok')
            self.assertEqual(result.stdout, 'ok\n')

    @asynctest
    async def test_restrict_restores_only_pty(self):
        """Test that restrict,pty restores PTY but not port forwarding"""

        async with self.connect(username='ckey', client_keys=['ckey_ecdsa'],
                                agent_path=None) as conn:
            result = await conn.run('echo ok', term_type='ansi')

            self.assertEqual(result.stdout.strip(), 'ok')
            self.assertEqual(_RestrictServer.pty_count, 1)

            with self.assertRaises(asyncssh.ChannelListenError):
                await conn.forward_remote_port('', 0, '', 0)

            self.assertEqual(_RestrictServer.listener_count, 0)

    @asynctest
    async def test_restrict_denies_remote_forwarding(self):
        """Test that restrict denies remote forwarding before listening"""

        async with self.connect(username='ckey', client_keys=['ckey'],
                                agent_path=None) as conn:
            with self.assertRaises(asyncssh.ChannelListenError):
                await conn.forward_remote_port('', 0, '', 0)

            self.assertEqual(_RestrictServer.listener_count, 0)

            result = await conn.run('echo ok')
            self.assertEqual(result.stdout, 'ok\n')

    @asynctest
    async def test_restrict_denies_direct_tcpip(self):
        """Test that restrict denies direct TCP/IP before connecting"""

        async with self.connect(username='ckey', client_keys=['ckey'],
                                agent_path=None) as conn:
            with self.assertRaises(asyncssh.ChannelOpenError):
                await conn.open_connection('127.0.0.1', 7)

            self.assertEqual(_RestrictServer.connect_count, 0)

            result = await conn.run('echo ok')
            self.assertEqual(result.stdout, 'ok\n')

    @asynctest
    async def test_restrict_denies_agent_forwarding(self):
        """Test that restrict denies agent forwarding before listening"""

        listener_count = 0
        agent_req_count = 0

        real_create_listener = asyncssh.connection.create_unix_forward_listener

        async def create_listener(*args):
            """Count agent listener creations"""

            nonlocal listener_count

            listener_count += 1
            return await real_create_listener(*args)

        real_create_agent_listener = \
            asyncssh.connection.SSHServerConnection.create_agent_listener

        async def create_agent_listener(conn):
            """Count agent forwarding requests evaluated by the server"""

            nonlocal agent_req_count

            agent_req_count += 1
            return await real_create_agent_listener(conn)

        with patch('asyncssh.connection.create_unix_forward_listener',
                   create_listener):
            with patch.object(asyncssh.connection.SSHServerConnection,
                              'create_agent_listener', create_agent_listener):
                async with self.connect(username='ckey', client_keys=['ckey'],
                                        agent_path=None,
                                        agent_forwarding='agent') as conn:
                    result = await conn.run('echo ok')

                    self.assertEqual(result.stdout, 'ok\n')
                    self.assertEqual(agent_req_count, 1)
                    self.assertEqual(listener_count, 0)
                    self.assertFalse(_RestrictServer.agent_path_seen)

    @asynctest
    async def test_restrict_denies_x11_forwarding(self):
        """Test that restrict denies X11 forwarding before listening"""

        listener_count = 0

        real_create_listener = asyncssh.connection.create_x11_server_listener

        async def create_listener(*args):
            """Count X11 listener creations"""

            nonlocal listener_count

            listener_count += 1
            return await real_create_listener(*args)

        ckey = asyncssh.read_private_key('ckey')

        # The certificate permits X11 forwarding, so the denial comes
        # from the restrict option on the CA entry alone
        cert = make_certificate('ssh-rsa-cert-v01@openssh.com',
                                CERT_TYPE_USER, ckey, ckey, ['ckey'],
                                extensions={'permit-X11-forwarding': ''})

        with patch('asyncssh.connection.SSHClientChannel',
                   _RestrictClientChannel):
            with patch('asyncssh.connection.create_x11_server_listener',
                       create_listener):
                async with self.connect(username='ckey',
                                        client_keys=[(ckey, cert)],
                                        agent_path=None) as conn:
                    stdin, _, _ = await conn.open_session('sleep')

                    result = \
                        await stdin.channel.make_x11_forwarding_request()

                    self.assertFalse(result)
                    self.assertEqual(listener_count, 0)

                    result = await conn.run('echo ok')
                    self.assertEqual(result.stdout, 'ok\n')

    @asynctest
    async def test_restrict_cert_further_restricts(self):
        """Test that certificate restrictions tighten restored capabilities"""

        ckey = asyncssh.read_private_key('ckey')

        cert_ok = make_certificate('ssh-rsa-cert-v01@openssh.com',
                                   CERT_TYPE_USER, ckey, ckey, ['ckey'],
                                   extensions={'permit-port-forwarding': ''})

        cert_denied = make_certificate('ssh-rsa-cert-v01@openssh.com',
                                       CERT_TYPE_USER, ckey, ckey, ['ckey'])

        # The CA entry restores port forwarding and the certificate
        # permits it, so the listener is created
        async with self.connect(username='ckey',
                                client_keys=[(ckey, cert_ok)],
                                agent_path=None) as conn:
            async with conn.forward_remote_port('', 0, '', 0) as listener:
                self.assertNotEqual(listener.get_port(), 0)

            self.assertEqual(_RestrictServer.listener_count, 1)

            with self.assertRaises(asyncssh.ChannelOpenError):
                await conn.run('echo ok', term_type='ansi')

            self.assertEqual(_RestrictServer.pty_count, 0)

        _RestrictServer.reset_counts()

        # The certificate doesn't permit port forwarding, so the
        # capability restored in the CA entry is denied again
        async with self.connect(username='ckey',
                                client_keys=[(ckey, cert_denied)],
                                agent_path=None) as conn:
            with self.assertRaises(asyncssh.ChannelListenError):
                await conn.forward_remote_port('', 0, '', 0)

            self.assertEqual(_RestrictServer.listener_count, 0)

    @asynctest
    async def test_restrict_admin_further_restricts(self):
        """Test that server settings tighten capabilities restored by key"""

        server = await self.create_server(
            _RestrictServer,
            authorized_client_keys='authorized_keys_restrict',
            allow_pty=False)

        try:
            port = server.sockets[0].getsockname()[1]

            async with self.connect(port=port, username='ckey',
                                    client_keys=['ckey_ecdsa'],
                                    agent_path=None) as conn:
                with self.assertRaises(asyncssh.ChannelOpenError):
                    await conn.run('echo ok', term_type='ansi')

                self.assertEqual(_RestrictServer.pty_count, 0)

                result = await conn.run('echo ok')
                self.assertEqual(result.stdout, 'ok\n')
        finally:
            server.close()
            await server.wait_closed()
