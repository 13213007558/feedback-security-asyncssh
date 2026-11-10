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

"""Tests for the release-verification usage contract in examples/

These tests pin down the split of responsibilities between AsyncSSH's
cryptographic SSHSIG verification and the authorization/policy checks a
release backend must perform itself. In particular, a signature that is
cryptographically valid must still be rejected when its namespace, signer
or declared digest does not match release policy.
"""

import importlib.util
import unittest
from pathlib import Path

import asyncssh

from asyncssh.packet import SSHPacket, String, UInt32
from asyncssh.sshsig import _SSHSIG_MAGIC, _SSHSIG_VERSION


_EXAMPLE_PATH = Path(__file__).resolve().parent.parent / 'examples' / \
    'verify_release.py'

_spec = importlib.util.spec_from_file_location('verify_release_example',
                                               _EXAMPLE_PATH)
verify_release = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(verify_release)

ReleaseVerificationError = verify_release.ReleaseVerificationError

SHORT_MESSAGE = b'release-1.4.2: publish artifact bundle'
NAMESPACE = verify_release.RELEASE_NAMESPACE
PRINCIPAL = 'release-bot'


class _ReleaseTest(unittest.TestCase):
    """Common fixtures: local keys, an allowed-signers table, signatures"""

    def setUp(self):
        super().setUp()

        self.release_ed25519 = asyncssh.generate_private_key(
            'ssh-ed25519', 'release-ed25519')
        self.release_rsa = asyncssh.generate_private_key(
            'ssh-rsa', 'release-rsa')
        self.release_ecdsa = asyncssh.generate_private_key(
            'ecdsa-sha2-nistp256', 'release-ecdsa')
        self.outsider = asyncssh.generate_private_key(
            'ssh-ed25519', 'another-team')

        self.allowed = verify_release.build_allowed_signers(
            PRINCIPAL,
            (self.release_ed25519, self.release_rsa, self.release_ecdsa),
            namespace=NAMESPACE)

    def _sign(self, key, message=SHORT_MESSAGE, namespace=NAMESPACE,
              hash_name='sha512', raw=False):
        return asyncssh.create_sshsig(key, message, namespace=namespace,
                                      hash_name=hash_name, raw=raw)

    def _verify(self, message, sig, allowed=None):
        return verify_release.verify_release_signature(
            message, sig, PRINCIPAL,
            self.allowed if allowed is None else allowed)


class TestHappyPath(_ReleaseTest):
    """Legal controls for every supported public key type"""

    def test_ed25519_control(self):
        """An ed25519 release signature verifies and reports its claims"""

        sig = self._sign(self.release_ed25519)
        claims = self._verify(SHORT_MESSAGE, sig)

        self.assertEqual(claims.key_algorithm, 'ssh-ed25519')
        self.assertEqual(claims.namespace, NAMESPACE)
        self.assertEqual(claims.hash_name, 'sha512')

    def test_rsa_control_with_both_hashes(self):
        """RSA release signatures verify for sha256 and sha512"""

        for hash_name in ('sha256', 'sha512'):
            with self.subTest(hash_name=hash_name):
                sig = self._sign(self.release_rsa, hash_name=hash_name)
                claims = self._verify(SHORT_MESSAGE, sig)
                self.assertEqual(claims.key_algorithm, 'ssh-rsa')
                self.assertEqual(claims.hash_name, hash_name)

    def test_ecdsa_control(self):
        """An ECDSA release signature verifies"""

        sig = self._sign(self.release_ecdsa)
        claims = self._verify(SHORT_MESSAGE, sig)
        self.assertEqual(claims.key_algorithm, 'ecdsa-sha2-nistp256')

    def test_armored_and_raw_inputs_equivalent(self):
        """The verifier accepts both armored and raw SSHSIG blobs"""

        armored = self._sign(self.release_ed25519)
        raw = self._sign(self.release_ed25519, raw=True)

        self._verify(SHORT_MESSAGE, armored)
        self._verify(SHORT_MESSAGE, raw)


class TestPurposeIsolation(_ReleaseTest):
    """A valid signature for another purpose must not be a release approval"""

    def test_other_namespace_rejected_though_cryptographically_valid(self):
        """The 'file' namespace signature verifies but is not a release"""

        sig = self._sign(self.release_ed25519, namespace='file')

        # Prove the negative case is not a broken signature: AsyncSSH's
        # cryptographic verification succeeds when no policy is applied.
        permissive = verify_release.build_allowed_signers(PRINCIPAL, (
            self.release_ed25519,))
        self.assertTrue(asyncssh.validate_sshsig(
            SHORT_MESSAGE, sig, PRINCIPAL, permissive.encode()))

        with self.assertRaisesRegex(ReleaseVerificationError, 'namespace'):
            self._verify(SHORT_MESSAGE, sig)

    def test_namespace_gate_is_load_bearing(self):
        """Removing only the explicit namespace gate must change the result

        With a namespace-less allowed-signers table, the explicit gate in
        verify_release_signature is the sole purpose-isolation control.
        Temporarily disabling it must let the foreign signature through;
        this is the test that fails when that check is deleted.
        """

        sig = self._sign(self.release_ed25519, namespace='git')
        no_ns_signers = verify_release.build_allowed_signers(
            PRINCIPAL, (self.release_ed25519,))

        module = verify_release
        original = module.verify_release_signature

        source = open(_EXAMPLE_PATH).read()
        self.assertIn('claims.namespace != expected_namespace', source)

        def gate_removed(message, sig, principal, allowed_signers, *,
                         expected_namespace=NAMESPACE,
                         allowed_hashes=tuple(module.SUPPORTED_HASHES)):
            claims = module.parse_sshsig_claims(sig)
            if claims.hash_name not in allowed_hashes:
                raise ReleaseVerificationError('bad hash')

            ok = asyncssh.validate_sshsig(
                message, sig, principal, allowed_signers.encode('utf-8'))
            if not ok:
                raise ReleaseVerificationError('not authorized')
            return claims

        module.verify_release_signature = gate_removed
        try:
            # Without the gate the foreign-purpose signature is accepted:
            # the protection demonstrably depends on that check.
            claims = module.verify_release_signature(
                SHORT_MESSAGE, sig, PRINCIPAL, no_ns_signers)
            self.assertEqual(claims.namespace, 'git')
        finally:
            module.verify_release_signature = original

        # With the real implementation, the same inputs are rejected.
        with self.assertRaisesRegex(ReleaseVerificationError, 'namespace'):
            verify_release.verify_release_signature(
                SHORT_MESSAGE, sig, PRINCIPAL, no_ns_signers)

    def test_allowed_signers_namespace_option_is_defense_in_depth(self):
        """AsyncSSH itself rejects a foreign namespace when pinned"""

        sig = self._sign(self.release_ed25519, namespace='file')

        self.assertFalse(asyncssh.validate_sshsig(
            SHORT_MESSAGE, sig, PRINCIPAL, self.allowed.encode()))


class TestSignerAuthorization(_ReleaseTest):
    """The embedded public key is a claim, not a trust anchor"""

    def test_unauthorized_signer_rejected(self):
        """A valid signature from a key outside the table is rejected"""

        sig = self._sign(self.outsider)

        with self.assertRaisesRegex(ReleaseVerificationError,
                                    'cryptographic|authorized'):
            self._verify(SHORT_MESSAGE, sig)

    def test_self_signed_embedded_key_is_not_trusted(self):
        """Anyone can self-sign; only table entries establish trust"""

        sig = self._sign(self.outsider)

        # The embedded key verifies its own signature cryptographically...
        claims = verify_release.parse_sshsig_claims(sig)
        self.assertEqual(claims.namespace, NAMESPACE)

        # ...but an empty allow table has no trusted entry for it.
        with self.assertRaises(ReleaseVerificationError):
            self._verify(SHORT_MESSAGE, sig,
                         allowed='# no trusted signers here\n' +
                         self.allowed)

    def test_wrong_principal_rejected(self):
        """A key trusted for another principal does not authorize this one"""

        sig = self._sign(self.release_ed25519)
        other_principal_signers = verify_release.build_allowed_signers(
            'some-other-bot', (self.release_ed25519,), namespace=NAMESPACE)

        with self.assertRaises(ReleaseVerificationError):
            verify_release.verify_release_signature(
                SHORT_MESSAGE, sig, PRINCIPAL, other_principal_signers)


class TestMessageAndDigest(_ReleaseTest):
    """Message binding and the digest allow-list"""

    def test_message_change_rejected(self):
        """A one-byte message change breaks the cryptographic check"""

        sig = self._sign(self.release_ed25519)

        with self.assertRaises(ReleaseVerificationError):
            self._verify(b'release-1.4.3: publish artifact bundle', sig)

    def test_undeclared_hash_algorithm_rejected(self):
        """A structurally valid blob naming sha1 is refused by policy"""

        raw = self._sign(self.release_ed25519, raw=True)
        mutated = _rewrite_hash_name(raw, b'sha1')

        with self.assertRaisesRegex(ReleaseVerificationError, 'sha1'):
            self._verify(SHORT_MESSAGE, mutated)

    def test_restricting_allowed_hashes_rejects_sha512(self):
        """A tighter policy can downgrade an otherwise legal signature"""

        sig = self._sign(self.release_ed25519, hash_name='sha512')

        with self.assertRaisesRegex(ReleaseVerificationError, 'sha512'):
            verify_release.verify_release_signature(
                SHORT_MESSAGE, sig, PRINCIPAL, self.allowed,
                allowed_hashes=('sha256',))


class TestStructuralRejection(_ReleaseTest):
    """Malformed blobs are rejected before any trust decision"""

    def test_trailing_data_rejected(self):
        """Bytes after the final field fail the end-of-packet check"""

        raw = self._sign(self.release_ed25519, raw=True)

        with self.assertRaisesRegex(ReleaseVerificationError, 'end of packet'):
            self._verify(SHORT_MESSAGE, raw + b'X')

    def test_truncated_field_rejected(self):
        """A cut-off signature field is an incomplete packet"""

        raw = self._sign(self.release_ed25519, raw=True)

        with self.assertRaisesRegex(ReleaseVerificationError,
                                    'Malformed|Incomplete'):
            self._verify(SHORT_MESSAGE, raw[:-8])

    def test_bad_magic_and_version_rejected(self):
        """Wrong magic or version cannot be parsed as SSHSIG"""

        raw = self._sign(self.release_ed25519, raw=True)

        with self.assertRaises(ReleaseVerificationError):
            self._verify(SHORT_MESSAGE, b'XX' + raw[2:])

        bumped_version = _SSHSIG_MAGIC + UInt32(99) + \
            raw[6 + 4:]
        with self.assertRaises(ReleaseVerificationError):
            self._verify(SHORT_MESSAGE, bumped_version)

    def test_armor_problems_rejected(self):
        """Missing header/footer or bad base64 are refused"""

        armored = self._sign(self.release_ed25519)

        with self.assertRaisesRegex(ReleaseVerificationError, 'header'):
            self._verify(SHORT_MESSAGE, armored.replace(
                b'-----BEGIN SSH SIGNATURE-----', b'-----BEGIN OTHER-----'))

        with self.assertRaisesRegex(ReleaseVerificationError, 'footer'):
            self._verify(SHORT_MESSAGE, armored.splitlines()[0] + b'\n')

    def test_corrupt_signature_bytes_rejected(self):
        """Flipping signature bytes keeps structure but breaks crypto"""

        raw = bytearray(self._sign(self.release_ed25519, raw=True))
        raw[-1] ^= 0x01

        with self.assertRaises(ReleaseVerificationError):
            self._verify(SHORT_MESSAGE, bytes(raw))


class TestDemoTable(_ReleaseTest):
    """The runnable example's counterexample table stays correct"""

    def test_demo_accepts_only_the_three_controls(self):
        """Exactly the legal controls pass; every negative case is refused"""

        rows = verify_release.run_demo()

        accepted = [row['case'] for row in rows
                    if row['verdict'] == 'ACCEPTED']
        rejected = [row for row in rows if row['verdict'] == 'REJECTED']

        self.assertEqual(len(accepted), 3)
        self.assertTrue(all('control' in case for case in accepted))
        self.assertEqual(len(rejected), 6)

        # The purpose-isolation row must keep a valid cryptographic
        # signature and be rejected on policy grounds, not on bad bytes.
        isolation = next(row for row in rejected
                         if 'wrong namespace' in row['case'])
        self.assertIn('namespace', isolation['reason'])

        # Structural rows must explain which layer caught them.
        reasons = ' '.join(row['reason'] for row in rejected)
        self.assertIn('end of packet', reasons)
        self.assertIn('Incomplete', reasons)


def _rewrite_hash_name(blob: bytes, new_hash: bytes) -> bytes:
    """Replace the declared hash name in a raw SSHSIG blob"""

    packet = SSHPacket(blob)
    packet.get_bytes(6)
    packet.get_uint32()
    pubdata = packet.get_string()
    namespace = packet.get_string()
    reserved = packet.get_string()
    packet.get_string()
    signature = packet.get_string()

    return _SSHSIG_MAGIC + UInt32(_SSHSIG_VERSION) + String(pubdata) + \
        String(namespace) + String(reserved) + String(new_hash) + \
        String(signature)
