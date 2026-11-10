#!/usr/bin/env python3.10
#
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

"""Release-signing verification example built on AsyncSSH SSHSIG

This example shows how a release backend should verify an armored SSH
signature (see PROTOCOL.sshsig) and, crucially, how to keep *purpose
isolation* and *signer authorization* separate from the raw cryptographic
check.

The split of responsibilities is the whole point of this module:

1. Cryptographic verification (performed by AsyncSSH)

   ``asyncssh.validate_sshsig`` only proves that the public key embedded in
   the signature blob produced the signature over
   ``SSHSIG || namespace || reserved || hash_alg || hash(message)``. It
   parses the blob, rejects structural problems (bad magic/version, trailing
   data, truncated fields, unknown key or hash), recomputes the digest and
   runs the key's ``verify``. It has no notion of which namespace your
   release flow considers valid, and it does not trust the embedded key for
   anything on its own.

2. Authorization (performed by this module, the caller)

   A signature that verifies cryptographically is worthless unless:

   * the namespace carried in the blob is exactly the one the release flow
     pins (here ``"release"``), so a signature legitimately created for
     another business purpose -- ``"file"``, ``"git"``, ... -- cannot be
     replayed as a release approval;
   * the embedded public key matches an entry in the operator-controlled
     allowed-signers table for the expected principal. The key that travels
     inside the signature is *claimed* identity, never a trust anchor:
     anyone can generate a key and self-sign; trust comes only from the
     local allowed-signers table;
   * the declared digest algorithm is one the release policy accepts.

The example is fully self-contained: it generates short-lived local keys,
signs a short release message, and prints a table of positive and negative
cases. Run it directly with::

    python examples/verify_release.py
"""

import binascii
from dataclasses import dataclass
from typing import Dict, Optional, Sequence

import asyncssh

from asyncssh.packet import PacketDecodeError, SSHPacket, String, UInt32
from asyncssh.public_key import decode_ssh_public_key
from asyncssh.sshsig import _SSHSIG_MAGIC, _SSHSIG_VERSION


RELEASE_NAMESPACE = 'release'
SUPPORTED_HASHES = frozenset(('sha256', 'sha512'))


class ReleaseVerificationError(ValueError):
    """A release signature failed cryptographic or policy verification"""


@dataclass(frozen=True)
class SignatureClaims:
    """Policy-relevant fields parsed out of an SSHSIG blob

       These are *claims* made by the signer. They must never be treated as
       trusted until the signature has verified against a key from the local
       allowed-signers table and the claims have matched release policy.
    """

    key_algorithm: str
    namespace: str
    hash_name: str


def _dearmor(sig: bytes) -> bytes:
    """Remove the PEM-style armor of an SSH signature"""

    header = b'-----BEGIN SSH SIGNATURE-----'
    footer = b'-----END SSH SIGNATURE-----'

    if not sig.startswith(header):
        raise ReleaseVerificationError('Missing SSH signature header')

    lines = sig.splitlines()

    if footer not in lines:
        raise ReleaseVerificationError('Missing SSH signature footer')

    payload = b''.join(lines[1:lines.index(footer)])

    try:
        return binascii.a2b_base64(payload)
    except binascii.Error:
        raise ReleaseVerificationError('Malformed base64 signature') from None


def parse_sshsig_claims(sig: bytes) -> SignatureClaims:
    """Parse the policy-relevant claims from an (armored or raw) SSHSIG

       This only decodes the structure; it performs no verification.
    """

    if sig[:1] == b'-':
        sig = _dearmor(sig)

    try:
        packet = SSHPacket(sig)

        if packet.get_bytes(6) != _SSHSIG_MAGIC:
            raise ReleaseVerificationError('Bad SSHSIG magic')

        if packet.get_uint32() != _SSHSIG_VERSION:
            raise ReleaseVerificationError('Unsupported SSHSIG version')

        pubdata = packet.get_string()
        key = decode_ssh_public_key(pubdata)
        namespace = packet.get_string().decode('utf-8')
        packet.get_string()                       # reserved, must be empty
        hash_name = packet.get_string().decode('ascii')
        packet.get_string()                       # the signature itself
        packet.check_end()
    except (PacketDecodeError, UnicodeDecodeError,
            asyncssh.KeyImportError) as exc:
        raise ReleaseVerificationError(
            f'Malformed SSHSIG blob: {exc}') from None

    return SignatureClaims(key.algorithm.decode('ascii'), namespace,
                           hash_name)


def build_allowed_signers(principal: str,
                          trusted_keys: Sequence[asyncssh.SSHKey],
                          namespace: Optional[str] = None) -> str:
    """Render an OpenSSH allowed-signers table for one principal

       When ``namespace`` is supplied it is written into the
       ``namespaces`` option so that AsyncSSH enforces purpose isolation in
       depth, in addition to the explicit check performed by
       :func:`verify_release_signature`.
    """

    options = f'namespaces="{namespace}"' if namespace else ''
    lines = []

    for key in trusted_keys:
        prefix = f'{principal} {options} '.rstrip()
        lines.append(prefix + ' ' +
                     key.convert_to_public().export_public_key().decode())

    return '\n'.join(lines) + '\n'


def verify_release_signature(message: bytes, sig: bytes, principal: str,
                             allowed_signers: str, *,
                             expected_namespace: str = RELEASE_NAMESPACE,
                             allowed_hashes: Sequence[str] = tuple(
                                 SUPPORTED_HASHES)) -> SignatureClaims:
    """Verify a release approval end to end

       :raises ReleaseVerificationError: if the signature is structurally
           invalid, fails the cryptographic check, declares an unsupported
           digest or namespace, or was not produced by a key authorized for
           ``principal``.
    """

    # Parse first so a malformed blob yields a clear policy error instead of
    # a boolean False from the lower layer.
    claims = parse_sshsig_claims(sig)

    # Policy gate 1: digest allow-list. The hash name is attacker-controlled
    # input; only accept algorithms the release policy knows about.
    if claims.hash_name not in allowed_hashes:
        raise ReleaseVerificationError(
            f'Declared hash {claims.hash_name!r} is not an accepted '
            f'release digest {sorted(allowed_hashes)}')

    # Policy gate 2: purpose isolation. A signature valid for another
    # namespace must never count as a release approval, even though its
    # cryptographic signature is perfectly valid.
    if claims.namespace != expected_namespace:
        raise ReleaseVerificationError(
            f'Signature namespace {claims.namespace!r} does not match the '
            f'pinned release namespace {expected_namespace!r}')

    # Gate 3 + cryptographic check in one call: AsyncSSH recomputes the
    # digest and verifies the signature with the *embedded* key, then only
    # returns True when that same key is present in the operator-provided
    # allowed-signers table for this principal (and its namespace option).
    try:
        ok = asyncssh.validate_sshsig(
            message, sig, principal, allowed_signers.encode('utf-8'))
    except ValueError as exc:
        # AsyncSSH rejects structurally-unknown hashes by raising rather
        # than returning False; the earlier allow-list normally catches it.
        raise ReleaseVerificationError(str(exc)) from None

    if not ok:
        raise ReleaseVerificationError(
            'Signature failed cryptographic verification or the signing key '
            'is not authorized for this principal')

    return claims


def _verdict(label: str, fn) -> Dict[str, str]:
    """Run one case and turn the outcome into a table row"""

    try:
        fn()
    except ReleaseVerificationError as exc:
        return {'case': label, 'verdict': 'REJECTED', 'reason': str(exc)}
    else:
        return {'case': label, 'verdict': 'ACCEPTED',
                'reason': 'release policy satisfied'}


def run_demo() -> Sequence[Dict[str, str]]:
    """Generate local keys and exercise the release verifier"""

    short_message = b'release-1.4.2: publish artifact bundle'

    release_key = asyncssh.generate_private_key('ssh-ed25519', 'release-key')
    other_key = asyncssh.generate_private_key('ssh-ed25519', 'other-team')
    rsa_key = asyncssh.generate_private_key('ssh-rsa', 'release-rsa')
    ecdsa_key = asyncssh.generate_private_key(
        'ecdsa-sha2-nistp256', 'release-ecdsa')

    principal = 'release-bot'
    allowed = build_allowed_signers(
        principal, (release_key, rsa_key, ecdsa_key),
        namespace=RELEASE_NAMESPACE)

    release_sig = asyncssh.create_sshsig(
        release_key, short_message, namespace=RELEASE_NAMESPACE)

    # A *cryptographically valid* signature made for a different business
    # purpose. The signature bytes are intact and verify fine; only the
    # namespace differs.
    file_sig = asyncssh.create_sshsig(
        release_key, short_message, namespace='file')

    # Valid cryptographic signature, key outside the approved set.
    outsider_sig = asyncssh.create_sshsig(
        other_key, short_message, namespace=RELEASE_NAMESPACE)

    tampered_message = b'release-9.9.9: publish artifact bundle'

    raw = asyncssh.create_sshsig(release_key, short_message,
                                 namespace=RELEASE_NAMESPACE, raw=True)
    trailing = raw + b'X'
    truncated = raw[:-8]

    def mutate_hash_name(blob: bytes) -> bytes:
        """Rewrite the declared hash name without re-signing"""

        packet = SSHPacket(blob)
        packet.get_bytes(6)
        packet.get_uint32()
        pubdata = packet.get_string()
        namespace = packet.get_string()
        reserved = packet.get_string()
        packet.get_string()                  # old hash name
        signature = packet.get_string()

        return _SSHSIG_MAGIC + UInt32(_SSHSIG_VERSION) + String(pubdata) + \
            String(namespace) + String(reserved) + String(b'sha1') + \
            String(signature)

    bad_hash_sig = mutate_hash_name(raw)

    rows = [
        _verdict('ed25519 release signature (control)', lambda:
                 verify_release_signature(
                     short_message, release_sig, principal, allowed)),
        _verdict('rsa-sha2 release signature (control)', lambda:
                 verify_release_signature(
                     short_message,
                     asyncssh.create_sshsig(
                         rsa_key, short_message,
                         namespace=RELEASE_NAMESPACE),
                     principal, allowed)),
        _verdict('ecdsa release signature (control)', lambda:
                 verify_release_signature(
                     short_message,
                     asyncssh.create_sshsig(
                         ecdsa_key, short_message,
                         namespace=RELEASE_NAMESPACE),
                     principal, allowed)),
        _verdict('valid signature, wrong namespace (purpose isolation)',
                 lambda: verify_release_signature(
                     short_message, file_sig, principal, allowed)),
        _verdict('valid signature, signer not in allowed-signers',
                 lambda: verify_release_signature(
                     short_message, outsider_sig, principal, allowed)),
        _verdict('message altered after signing', lambda:
                 verify_release_signature(
                     tampered_message, release_sig, principal, allowed)),
        _verdict('declared digest sha1 not in policy', lambda:
                 verify_release_signature(
                     short_message, bad_hash_sig, principal, allowed)),
        _verdict('trailing byte appended to blob', lambda:
                 verify_release_signature(
                     short_message, trailing, principal, allowed)),
        _verdict('truncated signature field', lambda:
                 verify_release_signature(
                     short_message, truncated, principal, allowed)),
    ]

    return rows


def main() -> None:
    """Print the positive/negative case table"""

    rows = run_demo()
    width = max(len(row['case']) for row in rows)

    for row in rows:
        print(f"{row['case']:<{width}}  {row['verdict']:<9} "
              f"{row['reason']}")

    accepted = sum(row['verdict'] == 'ACCEPTED' for row in rows)

    if accepted != 3:
        raise SystemExit(
            f'Expected exactly the 3 control signatures to pass, got '
            f'{accepted}')


if __name__ == '__main__':
    main()
