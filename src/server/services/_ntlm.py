"""NTLM tokens for the MSN 2.5 / OSR2 sign-in on LOGSRV selectors 0x0f and 0x10.

CHALLENGE packing, NEGOTIATE parsing and the response crypto come from
`pyspnego`'s `_ntlm_raw` layer. Two parts of it do not fit and are done here:
its high-level acceptor (`spnego.server()`) reads credentials from a static
`NTLM_USER_FILE` while accounts live in the app store, and its `Authenticate`
cannot parse the short token this client sends.

Both selectors carry the opaque SSPI token on a 0x04 variable parameter behind
a 4-byte header:

    [u16 message_type][u16 token_len] then the token in a 256-byte slot

Observed 2026-08-05: on the NEGOTIATE the leading u16 and the token's own NTLM
MessageType both read 1, and on the AUTHENTICATE both read 3. Replies mirror
that, so the field is the message type rather than a format version.

The same capture pins NegotiateFlags = 0x000082a2 — OEM | SEAL | LM_KEY | NTLM
| ALWAYS_SIGN. UNICODE is clear, so text fields are OEM. EXTENDED_SESSION-
SECURITY is clear, so the AUTHENTICATE carries NTLMv1 responses. The client
fills only the LM slot with DESL(LMOWFv1(password), ServerChallenge) and leaves
NtChallengeResponse empty.

The exchange does not end at sign-in. The context it leaves behind encrypts the
LOGSRV selectors that carry account data — see `SecurityContext`.
"""

import hmac
import struct
import zlib
from dataclasses import dataclass

from spnego._ntlm_raw.crypto import (
    compute_response_v1,
    kxkey,
    lmowfv1,
    md4,
    ntowfv1,
    rc4,
    rc4init,
    sealkey,
)
from spnego._ntlm_raw.messages import Challenge, Negotiate, NegotiateFlags

_HEADER = struct.Struct("<HH")

# The client hands us a 256-byte slot with the token at the front. Replies
# mirror the width, because that direction is the only one we have traced.
_SLOT_LEN = 256

# NTLMv1 LM and NT responses are both DESL output.
_RESPONSE_V1_LEN = 24

# AUTHENTICATE layout. The five field descriptors run from offset 12 to 51 in
# every form. A header that stops there carries no flags of its own.
_AUTH_FIELDS_OFFSET = 12
_AUTH_SHORT_HEADER_LEN = 52
_AUTH_LONG_HEADER_LEN = 64
_AUTH_FLAGS_OFFSET = 60

CHALLENGE_LEN = 8

# Width of the token a sealed message carries beside its buffer. Every sealed
# selector length-checks it exactly, before any crypto runs.
SEAL_TOKEN_LEN = 0x10

# The token's leading dword. The three behind it — RandomPad, checksum,
# sequence — are the encrypted part.
_SEAL_VERSION = struct.pack("<I", 1)
_SEAL_TRAILER = struct.Struct("<III")


def unwrap_token(var_data):
    """Split a selector 0x0f variable parameter into (message_type, token)."""
    if len(var_data) < _HEADER.size:
        return None, b""
    message_type, token_len = _HEADER.unpack_from(var_data)
    return message_type, bytes(var_data[_HEADER.size : _HEADER.size + token_len])


def wrap_token(token):
    """Build a selector 0x0f variable parameter around an SSPI token."""
    header = _HEADER.pack(token_message_type(token) or 0, len(token))
    return header + token.ljust(_SLOT_LEN, b"\x00")


def token_message_type(token):
    """Read the NTLM MessageType, or None when the token is not NTLMSSP."""
    if not token.startswith(b"NTLMSSP\x00") or len(token) < 12:
        return None
    return struct.unpack_from("<I", token, 8)[0]


def build_challenge(negotiate_token, server_challenge):
    """Answer a NEGOTIATE with a CHALLENGE. Returns (flags, token).

    The flags echo the client's request. Every one it asks for is one the
    acceptor can hold up: the key derivation and the signing both read off
    these, and nothing here needs a flag dropped.
    """
    flags = Negotiate.unpack(negotiate_token).flags
    return flags, Challenge(flags=flags, server_challenge=server_challenge).pack()


@dataclass(frozen=True)
class Authenticate:
    """The fields of an AUTHENTICATE token this server acts on."""

    flags: int
    user_name: str
    domain_name: str
    workstation: str
    lm_response: bytes
    nt_response: bytes


def parse_authenticate(auth_token, negotiated_flags):
    """Decode an AUTHENTICATE token, or None when it is too short to hold one.

    `pyspnego`'s own `Authenticate` cannot read what the OSR2 client sends. Its
    header stops after WorkstationFields at offset 52, with no
    EncryptedRandomSessionKeyFields, no NegotiateFlags and no MIC — the form
    MS-NLMP marks conditional. `pyspnego` models the 64-byte header only, so it
    reads bytes 60..63 as the flags. In this token those bytes sit inside the LM
    response, the garbage carries the UNICODE bit, and decoding the OEM user
    name as UTF-16 then fails.

    The five field descriptors sit at the same offsets in both forms, so they
    are read here. Flags come off the wire only when the payload starts past the
    long header, and otherwise fall back to what the CHALLENGE negotiated.
    """
    if len(auth_token) < _AUTH_SHORT_HEADER_LEN:
        return None

    fields = [struct.unpack_from("<HHI", auth_token, _AUTH_FIELDS_OFFSET + i * 8) for i in range(5)]
    payload_start = min((off for length, _, off in fields if length), default=len(auth_token))

    flags = negotiated_flags
    if payload_start >= _AUTH_LONG_HEADER_LEN:
        flags = struct.unpack_from("<I", auth_token, _AUTH_FLAGS_OFFSET)[0]

    encoding = "utf-16-le" if flags & NegotiateFlags.unicode else "windows-1252"
    lm, nt, domain, user, workstation = (
        bytes(auth_token[off : off + length]) for length, _, off in fields
    )
    return Authenticate(
        flags=flags,
        user_name=user.decode(encoding, errors="replace"),
        domain_name=domain.decode(encoding, errors="replace"),
        workstation=workstation.decode(encoding, errors="replace"),
        lm_response=lm,
        nt_response=nt,
    )


def password_matches(auth, server_challenge, password):
    """Recompute the NTLMv1 responses from a known password and compare.

    Returns False for an NTLMv2 response. The negotiated flags rule one out,
    so a response of any other length means the exchange drifted from what the
    capture shows and the caller should log the token rather than trust it.
    """
    expected_nt, expected_lm, _ = compute_response_v1(
        auth.flags,
        ntowfv1(password),
        lmowfv1(password),
        server_challenge,
        _client_challenge(auth),
        no_lm_response=False,
    )

    if len(auth.nt_response) == _RESPONSE_V1_LEN:
        return hmac.compare_digest(auth.nt_response, expected_nt)

    if len(auth.lm_response) == _RESPONSE_V1_LEN:
        return hmac.compare_digest(auth.lm_response, expected_lm)

    return False


def _client_challenge(auth):
    """Extended session security hides the client nonce in the LM slot."""
    return auth.lm_response[:8].ljust(8, b"\x00")


class SecurityContext:
    """The sealing state the account-carrying LOGSRV selectors run on.

    `CAuthenticator` (MCM.DLL) keeps the SSPI context alive past sign-in and
    puts it to work on the selectors that carry account data:

      | 0x12 | password change | request: credential blob + token |
      | 0x13 | billing query   | reply:   0x41c account buffer + token |
      | 0x14 | payment method  | request: 0x11c PM buffer + token |

    Those buffers are encrypted, not merely signed. The provider is MSN's own —
    `CAuthenticator` acquires credentials for package "MSN", exported by
    `MSNSSPC.DLL` — and the two function pointers it caches come off the
    SecurityFunctionTable at 0x48 and 0x4c, which that table fills with
    `SealMessage` and `UnsealMessage` rather than the MakeSignature /
    VerifySignature pair at 0x38 / 0x3c. So `FProcessMessage`'s
    ScrambleRequestType selects seal (0) or unseal (1), and neither path looks
    at NTLMSSP_NEGOTIATE_SIGN — only at the RC4 handles, which exist because
    the sign-in asked for confidentiality.

    `SealMessage` @ 0x7d7936ec, per message:

        checksum = CRC32(plaintext)          over each SECBUFFER_DATA
        data     = RC4(handle, plaintext)    in place, same pass
        token    = [1][RandomPad][checksum][seq], the last 12 bytes RC4'd
                   from the same stream, straight after the data

    `UnsealMessage` @ 0x7d793827 mirrors it: decrypt, CRC the plaintext, decrypt
    the token, then compare sequence first and checksum second. The CRC is the
    ordinary reflected CRC-32 — the table at 0x7d7960f0 is the zlib one.

    The two directions run separate RC4 streams off one sealing key: the
    context allocates a send handle and a receive handle and copies the
    freshly keyed state into both. Each pipe runs its own
    NEGOTIATE/AUTHENTICATE pair, so a context covers one pipe and each
    direction starts at sequence 0.
    """

    def __init__(self, flags, session_key):
        self.flags = flags
        self.session_key = session_key
        seal_key = sealkey(flags, session_key, "accept")
        self._out = rc4init(seal_key)
        self._in = rc4init(seal_key)
        self._out_seq = 0
        self._in_seq = 0

    def seal(self, data):
        """Encrypt one outbound message. Returns (ciphertext, 16-byte token)."""
        checksum = zlib.crc32(data) & 0xFFFFFFFF
        ciphertext = rc4(self._out, data)
        # RandomPad rides along encrypted and is never read back — SealMessage
        # does not even initialise it.
        trailer = _SEAL_TRAILER.pack(0, checksum, self._out_seq)
        token = _SEAL_VERSION + rc4(self._out, trailer)
        self._out_seq += 1
        return ciphertext, token

    def unseal(self, ciphertext, token):
        """Decrypt one inbound message. Returns (plaintext, whether it checked out)."""
        plaintext = rc4(self._in, ciphertext)
        _, checksum, seq_num = _SEAL_TRAILER.unpack(rc4(self._in, token[4:SEAL_TOKEN_LEN]))
        intact = seq_num == self._in_seq and checksum == zlib.crc32(plaintext) & 0xFFFFFFFF
        self._in_seq += 1
        return plaintext, intact


def establish(auth, server_challenge, password):
    """Derive the sealing context an accepted AUTHENTICATE leaves behind.

    KEY_EXCH is never negotiated — the short AUTHENTICATE stops after the
    workstation descriptor, so there is no slot for an encrypted session key —
    which makes the exported session key the key exchange key itself.
    """
    lm_hash = lmowfv1(password)
    session_base_key = md4(ntowfv1(password))
    exported_session_key = kxkey(
        auth.flags, session_base_key, lm_hash, auth.lm_response, server_challenge
    )
    return SecurityContext(auth.flags, exported_session_key)
