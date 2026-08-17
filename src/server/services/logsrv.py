"""LOGSRV service handler: login, password change, service discovery."""

import logging
import secrets
import struct

from ..config import (
    LOGSRV_INTERFACE_GUIDS,
    MPC_CLASS_ONEWAY_MASK,
    TAG_END_STATIC,
)
from ..log import TRACE
from ..models import DwordParam, VarParam
from ..mpc import (
    build_discovery_host_block,
    build_discovery_payload,
    build_host_block,
    build_service_packet,
    build_static_reply,
    build_tagged_reply_dword,
    build_tagged_reply_var,
    build_tagged_reply_word,
    parse_request_params,
)
from ..session import Session
from ..store import app_store as _default_store
from . import _ntlm
from ._dispatch import log_unhandled_selector

log = logging.getLogger(__name__)

# LOGSRV wire selectors. Names track MOSCP/SIGNUP handler symbols where known.
LOGSRV_SELECTOR_LOGIN = 0x00  # initial login bootstrap (7 DWORDs)
LOGSRV_SELECTOR_PASSWORD_CHANGE = 0x01  # Tools > Password dialog commit
LOGSRV_SELECTOR_SIGNUP_POST_TRANSFER = 0x02  # SIGNUP step after FTM transfer
LOGSRV_SELECTOR_SIGNUP_QUERY = 0x07  # SIGNUP progressive queries
LOGSRV_SELECTOR_BILLING_QUERY = 0x0A  # billing info fetch
LOGSRV_SELECTOR_PM_COMMIT = 0x0B  # payment-method commit (0x84 var + status)
LOGSRV_SELECTOR_BILLING_COMMIT = 0x0C  # billing commit (0x84 var + status)
LOGSRV_SELECTOR_POST_SIGNUP_QUERY = 0x0D  # post-signup phonebook/server query
LOGSRV_SELECTOR_EXISTING_MEMBER_PHONEBOOK = 0x0E  # existing-member phonebook fetch
# OSR2 / MSN 2.5 login. The NTLM exchange runs over two selectors, one leg each:
# 0x0F carries NEGOTIATE and answers with CHALLENGE, 0x10 carries AUTHENTICATE
# and answers with the sign-in result.
LOGSRV_SELECTOR_NTLM_NEGOTIATE = 0x0F
LOGSRV_SELECTOR_NTLM_AUTHENTICATE = 0x10
LOGSRV_SELECTOR_NTLM_BOOTSTRAP = 0x11  # account record fetch once the context is accepted
# OSR2 replacements for the account selectors, each sealing the account data
# under the pipe's NTLM context. The plaintext originals stay for the RTM
# client, which reaches the same dialogs on 0x0A and 0x0B. Only the address
# commit is shared: BILLADD submits it on 0x0C, in the clear, in both builds.
LOGSRV_SELECTOR_SIGNED_BILLING_QUERY = 0x13
LOGSRV_SELECTOR_SIGNED_PM_COMMIT = 0x14

# The credential blob the client sends as the second send-param of selector
# 0x00. `GUIDE.EXE!VerifyAccountViaLogSrv` @ 0x04304024 builds it out of three
# adjacent stack locals and hands the lot to the marshaller as one 0x58-byte
# field:
#
#     undefined1 blob      [4]    Stack[-0xc4]   never written before the send
#     CHAR       memberId  [65]   Stack[-0xc0]   lstrcpyA(memberId, userId)
#     CHAR       password  [19]   Stack[-0x7f]   lstrcpyA(password, password)
#
# 4 + 65 + 19 = 0x58, and the next local sits at Stack[-0x6c] = blob + 0x58, so
# the three cover the field exactly. Both strings are ASCIIZ and neither is
# transformed — the account is verified against the plain password.
#
# The same layout backs the cached-credentials record in the registry: when the
# dialog passes an empty member id the function copies from `cachedRecord + 4`,
# and clears the cached password at `cachedRecord + 0x45`.
LOGIN_BLOB_LEN = 0x58
LOGIN_BLOB_MEMBER_ID_OFFSET = 0x04
LOGIN_BLOB_MEMBER_ID_LEN = 0x41
LOGIN_BLOB_PASSWORD_OFFSET = 0x45
LOGIN_BLOB_PASSWORD_LEN = 0x13

# First reply dword. `VerifyAccountViaLogSrv` treats 0 and 0x0C as success and
# maps every other value to the message its 0x2F0-titled box shows:
#
#   2, 0x0A  -> 0x2FC  "This member ID is not valid."
#   1        -> 0x309  "The Microsoft Network accounts database is not available"
#   0x0D     -> 0x31E  "This account has been locked."
#   0x16     -> 0x31C  "You are already signed in ... another computer"
#   0x22     -> 0x2C6  "Network busy."
#   0x23     -> 0x2C7  "Software update required." (newer Windows)
#   0x24     -> 0x2C8  "Software update required." (newer MSN)
#   default  -> 0x2F5  "Password not valid. Please type it again."
#
# The catch-all is the password message, so the two credential failures the
# client can name are the two this server reports: 2 for a member id that
# resolves to no account, and an unmapped code for an account whose password
# does not match. 3 is unmapped and sits in the same low band as the rest.
LOGIN_RESULT_OK = 0
LOGIN_RESULT_BAD_MEMBER_ID = 2
LOGIN_RESULT_BAD_PASSWORD = 3

# Selector 0x01 reply for a change the server will not make. Any non-zero value
# raises the same "current password not valid" box, so one code covers a wrong
# current password, a malformed request, and a connection that never signed in.
PASSWORD_CHANGE_REFUSED = 1


class LOGSRVHandler:
    """Handles LOGSRV service requests on a logical pipe."""

    def __init__(self, pipe_idx, svc_name, session=None):
        self.pipe_idx = pipe_idx
        self.svc_name = svc_name
        # Anonymous when the pipe opens before the login lands.
        self.session = session or Session()
        # Set by the AUTHENTICATE this pipe accepts. One RC4 stream per pipe,
        # so the context cannot live on the connection-wide session.
        self.security = None

    def build_discovery_packet(self, server_seq, client_ack):
        """Build the IID->selector discovery block for LOGSRV."""
        payload = build_discovery_payload(LOGSRV_INTERFACE_GUIDS)
        host_block = build_discovery_host_block(payload)
        return build_service_packet(self.pipe_idx, host_block, server_seq, client_ack)

    def handle_request(self, msg_class, selector, request_id, payload, server_seq, client_ack):
        """Dispatch a LOGSRV request. Returns a wire packet or None."""
        if (msg_class & MPC_CLASS_ONEWAY_MASK) == MPC_CLASS_ONEWAY_MASK:
            log.info(
                "oneway_continuation class=0x%02x selector=0x%02x payload_len=%d",
                msg_class,
                selector,
                len(payload),
            )
            return None

        if selector == LOGSRV_SELECTOR_LOGIN:
            reply_payload = _handle_login(payload, self.session)
        elif selector == LOGSRV_SELECTOR_NTLM_NEGOTIATE:
            reply_payload = _handle_ntlm_negotiate(payload, self.session)
        elif selector == LOGSRV_SELECTOR_NTLM_AUTHENTICATE:
            reply_payload, self.security = _handle_ntlm_authenticate(payload, self.session)
        elif selector == LOGSRV_SELECTOR_NTLM_BOOTSTRAP:
            reply_payload = _handle_ntlm_bootstrap(self.session)
        elif selector == LOGSRV_SELECTOR_PASSWORD_CHANGE:
            reply_payload = _handle_password_change(payload, self.session)
        elif selector == LOGSRV_SELECTOR_SIGNUP_POST_TRANSFER:
            reply_payload = _handle_signup_post_transfer(payload)
        elif selector == LOGSRV_SELECTOR_SIGNUP_QUERY:
            reply_payload = _handle_signup_query(payload)
        elif selector == LOGSRV_SELECTOR_BILLING_QUERY:
            reply_payload = _handle_billing_query(self.session)
        elif selector == LOGSRV_SELECTOR_SIGNED_BILLING_QUERY:
            reply_payload = _handle_signed_billing_query(self.session, self.security)
        elif selector == LOGSRV_SELECTOR_PM_COMMIT:
            reply_payload = _handle_pm_commit(payload, self.session)
        elif selector == LOGSRV_SELECTOR_SIGNED_PM_COMMIT:
            reply_payload = _handle_signed_pm_commit(payload, self.session, self.security)
        elif selector == LOGSRV_SELECTOR_BILLING_COMMIT:
            reply_payload = _handle_billing_commit(payload, self.session)
        elif selector == LOGSRV_SELECTOR_POST_SIGNUP_QUERY:
            reply_payload = _handle_post_signup_query(payload)
        elif selector == LOGSRV_SELECTOR_EXISTING_MEMBER_PHONEBOOK:
            reply_payload = _handle_existing_member_phonebook_query(payload)
        else:
            log_unhandled_selector(log, msg_class, selector, request_id, payload)
            return None

        host_block = build_host_block(msg_class, selector, request_id, reply_payload)
        return build_service_packet(self.pipe_idx, host_block, server_seq, client_ack)


def _build_bootstrap_payload(result):
    """Build the LOGSRV login reply: 7 dwords + end-static + 16-byte variable.

    Field 0 is the login result the client branches on. The remaining six dwords
    and the 16-byte variable are read into `PTR_DAT_0430a0a0` slots and the
    account record at `DAT_04308a44 + 0x1de`; zero leaves them all unset.
    """
    payload = bytearray()
    payload.extend(build_tagged_reply_dword(result))
    for _ in range(6):
        payload.extend(build_tagged_reply_dword(0))
    payload.append(TAG_END_STATIC)
    payload.extend(build_tagged_reply_var(0x84, b"\x00" * 16))
    return bytes(payload)


_BOOTSTRAP_PAYLOAD = _build_bootstrap_payload(LOGIN_RESULT_OK)
_BAD_MEMBER_ID_PAYLOAD = _build_bootstrap_payload(LOGIN_RESULT_BAD_MEMBER_ID)
_BAD_PASSWORD_PAYLOAD = _build_bootstrap_payload(LOGIN_RESULT_BAD_PASSWORD)

# NTLM MessageType values the two sign-in selectors carry.
_NTLM_NEGOTIATE = 1
_NTLM_AUTHENTICATE = 3

# The word of the selector 0x10 reply. See `_ntlm_result_reply`.
NTLM_ACCEPTED = 4
NTLM_REFUSED = 0

# Selector 0x0f owes a 0x84 variable whatever happens. An empty one carries no
# token header, which is the only shape distinguishable from a real CHALLENGE
# without inventing a status field.
_NTLM_NO_CHALLENGE_REPLY = build_tagged_reply_var(0x84, b"")


def _build_ntlm_bootstrap_payload():
    """Build the selector 0x11 reply: five dwords, a 16-byte variable, five dwords.

    `GUIDE.EXE!VerifyAccountViaLogSrv` @ 0x04304429 runs this only once
    `StAuthenticate` reports the context accepted — a refused sign-in jumps
    straight to the result check, which is why the selector stayed unseen while
    selector 0x10 answered its word with anything but 4.

    The variable sits sixth because that is where the request's recv
    descriptors put it. `MPCCL!ProcessTaggedServiceReply` @ 0x04604f26 walks
    reply fields and descriptors together, one step each, and a tag that does
    not match the descriptor at that index fails the whole request with
    0x8b0b0008 — so a reply cannot group its statics ahead of its variables the
    way `_build_bootstrap_payload` does. That one only looks grouped because
    its variable is last. End-static consumes no descriptor and can sit
    anywhere; the parser reads it as a flag and completes the request when the
    host block runs out.

    None of the fields carry the login result: that arrives on selector 0x10 as
    the dword `StAuthenticate` hands back. These land in the account record and
    in `PTR_DAT_0430b0bc` slots, and zero leaves them unset the way the RTM
    bootstrap does. Two of them have to stay zero rather than merely may: with
    the Setup `SetupN` value present, a non-zero dword 3 or 4 rewrites the
    result as 0x24 and raises "Software update required."
    """
    payload = bytearray()
    for _ in range(5):
        payload.extend(build_tagged_reply_dword(0))
    payload.extend(build_tagged_reply_var(0x84, b"\x00" * 16))
    for _ in range(5):
        payload.extend(build_tagged_reply_dword(0))
    payload.append(TAG_END_STATIC)
    return bytes(payload)


_NTLM_BOOTSTRAP_PAYLOAD = _build_ntlm_bootstrap_payload()


def _handle_login(request_payload, session):
    """Handle LOGSRV selector 0x00 — the sign-in the client runs before anything else.

    The request is a `0x03` dword (last-update version) plus the `0x04`
    credential blob. A member id and password that match a seeded account sign
    the connection in, and every per-member reply on it reads off that account
    from here on.

    A failure says which half was wrong, because the client has a message for
    each: an unknown member id and a mismatched password raise different boxes.
    """
    send_params, _ = parse_request_params(request_payload)
    blob = next(
        (p.data for p in send_params if isinstance(p, VarParam) and len(p.data) == LOGIN_BLOB_LEN),
        None,
    )
    if blob is None:
        log.warning("login no 0x%02x-byte blob params=%d", LOGIN_BLOB_LEN, len(send_params))
        # A request shaped like this holds no credential the parser recognises,
        # but it may still hold one somewhere else — keep the bytes off INFO.
        log.log(TRACE, "login_request payload=%s", request_payload.hex())
        return _BAD_MEMBER_ID_PAYLOAD

    member_id, password = _decode_login_blob(blob)
    user = _default_store.users.get_user(member_id)
    if user is None:
        log.info(
            "login_reply result=%d reason=unknown_member_id member_id=%r",
            LOGIN_RESULT_BAD_MEMBER_ID,
            member_id,
        )
        return _BAD_MEMBER_ID_PAYLOAD
    if user.password != password:
        log.info(
            "login_reply result=%d reason=wrong_password member_id=%r",
            LOGIN_RESULT_BAD_PASSWORD,
            user.username,
        )
        return _BAD_PASSWORD_PAYLOAD

    session.sign_in(user)
    log.info(
        "login_reply result=0 member_id=%r display_name=%r rights=0x%x",
        user.username,
        user.display_name,
        user.rights,
    )
    return _BOOTSTRAP_PAYLOAD


def _decode_login_blob(blob):
    """Split the credential blob into (member id, password)."""
    return (
        _asciiz(blob, LOGIN_BLOB_MEMBER_ID_OFFSET, LOGIN_BLOB_MEMBER_ID_LEN),
        _asciiz(blob, LOGIN_BLOB_PASSWORD_OFFSET, LOGIN_BLOB_PASSWORD_LEN),
    )


def _asciiz(buf, offset, length):
    """Read a NUL-terminated ASCII field out of a fixed-width slot."""
    return buf[offset : offset + length].split(b"\x00", 1)[0].decode("ascii", errors="replace")


# Minimum success reply for LOGSRV commit selectors (0x0b PM, 0x0c OI).
# Must be a 0x84 variable — a 0x83 dword unblocks WaitForResponse but
# fails the proxy's output_descriptor->m10() type==4 check, which
# surfaces as "Your account information cannot be updated at this time."
# First dword of the buffer is the commit status (0 = silent success,
# 0x1e/0x1f = user message box, anything else = generic error dialog).
# See BILLADD.DLL BillingDlg_ProcessCommitReply @ 0x00434912.
_COMMIT_OK_REPLY = build_tagged_reply_var(0x84, b"\x00" * 4)


def _handle_pm_commit(request_payload, session):
    """LOGSRV selector 0x0b — Payment Options > Payment Method OK.
    BILLADD.DLL BillingDlg_CommitPM @ 0x00434b81 submits a 0x11c PM buffer.

    The submitted buffer is traced rather than stored. Its length matches the
    PM block of the 0x0a reply exactly, but nothing confirms the field offsets
    run the same way in this direction, and writing the account from guessed
    offsets would corrupt it silently. The buffer carries a card number, so the
    bytes stay at TRACE.
    """
    log.info(
        "pm_commit user=%s payload_len=%d",
        session.user.username or "-",
        len(request_payload),
    )
    log.log(TRACE, "pm_commit payload=%s", request_payload.hex())
    log.info("pm_commit_reply status=0")
    return _COMMIT_OK_REPLY


def _handle_billing_commit(request_payload, session):
    """LOGSRV selector 0x0c — Payment Options > Name and Address OK.
    BILLADD.DLL BillingDlg_CommitOI @ 0x00434953 submits a 0x2fc OI
    buffer, fragmented on the wire as class=0xe6/0xe7 one-way
    continuations (filtered out by MPC_CLASS_ONEWAY_MASK).

    Traced, not stored, for the same reason as the PM commit — and here the
    lengths do not even agree: the 0x0a reply's OI block spans 0x008..0x300,
    which is 0x2f8 bytes, four short of what the commit sends.
    """
    log.info(
        "billing_commit user=%s payload_len=%d",
        session.user.username or "-",
        len(request_payload),
    )
    log.log(TRACE, "billing_commit payload=%s", request_payload.hex())
    log.info("billing_commit_reply status=0")
    return _COMMIT_OK_REPLY


ACCOUNT_BUFFER_LEN = 0x41C
PM_BUFFER_LEN = 0x11C


def _handle_billing_query(session):
    """Handle a billing/account info query (selector 0x0A).

    The RTM client opens this when the user clicks Tools > Billing > Payment
    Method. Reply is a single 0x84 variable holding the account buffer.
    """
    log.info("billing_query user=%s", session.user.username or "-")
    buf = _build_account_buffer(session.user.billing)
    _log_account_buffer("billing_query_reply", session.user.billing)
    return build_tagged_reply_var(0x84, buf)


def _handle_signed_billing_query(session, security):
    """LOGSRV selector 0x13 — the OSR2 billing dialog's account fetch.

    `BILLADD.DLL!BillingDlg_FetchWorker` @ 0x7f1245ba sends no parameters and
    takes two variables back, both length-checked before anything is read: the
    0x41c account buffer, then the 16-byte seal token. It hands the pair to
    `CAuthenticator::FProcessMessage(buf, 0x41c, token, 1)`, which unseals them
    in place, and a buffer that fails there is dropped as silently as a wrong
    length.
    """
    log.info("signed_billing_query user=%s", session.user.username or "-")
    buf = _build_account_buffer(session.user.billing)

    if security is None:
        # No AUTHENTICATE landed on this pipe, so there is no key to seal with.
        # The client cannot have reached this selector without one.
        log.warning("signed_billing_query_reply refused reason=no_security_context")
        sealed, token = buf, bytes(_ntlm.SEAL_TOKEN_LEN)
    else:
        sealed, token = security.seal(buf)

    _log_account_buffer("signed_billing_query_reply", session.user.billing)
    return build_tagged_reply_var(0x84, sealed) + build_tagged_reply_var(0x84, token)


def _handle_signed_pm_commit(request_payload, session, security):
    """LOGSRV selector 0x14 — the OSR2 Payment Method commit.

    `BILLADD.DLL` @ 0x7f124c08 seals the 0x11c PM buffer with
    `CAuthenticator::FProcessMessage(buf, 0x11c, token, 0)` and sends the
    ciphertext and the token as consecutive variables. The reply it reads is the
    same 4-byte variable the unsealed commits answer with.

    The buffer is traced rather than stored, for the reason `_handle_pm_commit`
    gives — and it carries a card number, so the plaintext stays at TRACE. The
    seal is checked so a key that drifts shows up in the log rather than as a
    dialog that half works.
    """
    send_params, _ = parse_request_params(request_payload)
    sealed = next(
        (p.data for p in send_params if isinstance(p, VarParam) and len(p.data) == PM_BUFFER_LEN),
        None,
    )
    token = next(
        (
            p.data
            for p in send_params
            if isinstance(p, VarParam) and len(p.data) == _ntlm.SEAL_TOKEN_LEN
        ),
        None,
    )
    if sealed is None or token is None or security is None:
        log.warning(
            "signed_pm_commit malformed params=%d payload_len=%d security=%s",
            len(send_params),
            len(request_payload),
            security is not None,
        )
        log.log(TRACE, "signed_pm_commit payload=%s", request_payload.hex())
        return _COMMIT_OK_REPLY

    buf, intact = security.unseal(sealed, token)
    log.info(
        "signed_pm_commit user=%s payload_len=%d seal_ok=%s",
        session.user.username or "-",
        len(request_payload),
        intact,
    )
    log.log(TRACE, "signed_pm_commit plaintext=%s", buf.hex())
    log.info("signed_pm_commit_reply status=0")
    return _COMMIT_OK_REPLY


def _build_account_buffer(profile):
    """Pack a billing profile into the 0x41c account buffer both queries return.

    Offset 0x000: dword status (0 = success)
    Offset 0x008: OI (Order Information / address) — NUL-terminated strings:
      +0x3b  First name
      +0x69  Last name
      +0x1d0 Country ID (dword)
      +0x1d8 Address line
      +0x201 City
      +0x253 State
      +0x27c ZIP code
      +0x2bd Phone
    Offset 0x300: PM (Payment Method) — 0x11c bytes:
      +0x00  Type dword (1=CHARGE, 2=DEBIT, 3=DIRECTDEBIT)
      +0x19  Card number string
    """
    buf = bytearray(ACCOUNT_BUFFER_LEN)

    # Status = 0 (success)
    struct.pack_into("<I", buf, 0x00, 0)

    # OI: address fields (offsets relative to OI start at byte 8)
    oi = 8
    _put_str(buf, oi + 0x3B, profile.first_name)
    _put_str(buf, oi + 0x69, profile.last_name)
    struct.pack_into("<I", buf, oi + 0x1D0, profile.country_id)
    _put_str(buf, oi + 0x1D8, profile.address)
    _put_str(buf, oi + 0x201, profile.city)
    _put_str(buf, oi + 0x253, profile.state)
    _put_str(buf, oi + 0x27C, profile.zip)
    _put_str(buf, oi + 0x2BD, profile.phone)

    # PM: payment method
    pm = 0x300
    struct.pack_into("<I", buf, pm + 0x00, profile.payment_type)
    _put_str(buf, pm + 0x19, profile.card_number)

    return bytes(buf)


def _log_account_buffer(event, profile):
    masked_card = f"****{profile.card_number[-4:]}" if len(profile.card_number) >= 4 else "****"
    log.info(
        "%s status=0 type=%d first=%r last=%r country=%d city=%r state=%r zip=%r card=%s",
        event,
        profile.payment_type,
        profile.first_name,
        profile.last_name,
        profile.country_id,
        profile.city,
        profile.state,
        profile.zip,
        masked_card,
    )


def _put_str(buf, offset, s):
    """Write a NUL-terminated ASCII string into a buffer at offset."""
    encoded = s.encode("ascii") + b"\x00"
    buf[offset : offset + len(encoded)] = encoded


def _handle_signup_post_transfer(request_payload):
    """Handle LOGSRV selector 0x02 — opened by SIGNUP after the FTM transfer.

    After SIGNUP finishes the FTM download loop for the "LOGSRV" phone-book
    payload, it opens a fresh LOGSRV pipe and calls selector 0x02 with three
    dwords (counter, 0, 0) and one 0x84 recv descriptor.  The reply shape
    isn't RE'd — an empty 0x84 variable is the minimal well-formed payload
    that satisfies the unmarshaller so we can see what the client does next.
    """
    log.info("signup_post_transfer payload_len=%d", len(request_payload))
    log.info("signup_post_transfer_reply var_len=0")
    return build_tagged_reply_var(0x84, b"")


def _handle_post_signup_query(request_payload):
    """Handle LOGSRV selector 0x0d — opened by SIGNUP right after the
    OLREGSRV commit reply comes back.

    Request: three dwords (country_id, 0, 0) + one 0x84 recv descriptor.
    The call runs in parallel with the OLREGSRV one-way continuation
    frames, so it's not the Congrats-gating step — but leaving it
    unanswered makes the client disconnect.  Reply shape isn't RE'd;
    an empty 0x84 variable is the minimal well-formed answer.
    """
    send_params, _ = parse_request_params(request_payload)
    country = (
        send_params[0].value if send_params and isinstance(send_params[0], DwordParam) else None
    )
    log.info("post_signup_query country_id=%s", country if country is not None else "?")
    log.info("post_signup_query_reply var_len=0")
    return build_tagged_reply_var(0x84, b"")


def _handle_existing_member_phonebook_query(request_payload):
    """Handle LOGSRV opcode 0x0e — SIGNUP "I'm already a member → Update
    local phone numbers → Connect" path.

    Request: one send dword (observed=8, semantic unknown) + one 0x83 recv
    descriptor.  The caller SIGNUP.EXE!FUN_004043c1 @ 0x004043c1 opens a
    fresh LOGSRV pipe, issues this opcode, waits, and checks the recv
    dword with CMP/SBB/NEG at 0x004044a7-0x004044ae — returning TRUE iff
    the value is exactly 0.  Any other value leaves the wizard stuck at
    "Starting transfer..." so we must reply with dword=0.
    """
    send_params, _ = parse_request_params(request_payload)
    dw = send_params[0].value if send_params and isinstance(send_params[0], DwordParam) else None
    log.info("existing_member_phonebook dword=%s", dw if dw is not None else "?")
    log.info("existing_member_phonebook_reply dword=0")
    return build_tagged_reply_dword(0)


def _handle_signup_query(request_payload):
    """Handle the SIGNUP.EXE LOGSRV selector 0x07 request.

    Observed on the wire during the "Get the latest product details" flow:
    the request carries no send-side params — just a single recv descriptor
    (0x85) asking for one variable-tagged reply.  The exact reply shape
    hasn't been pinned down from the COM proxy layer yet; returning an
    empty 0x84 variable is the minimal well-formed payload that matches
    the recv descriptor, letting the client's unmarshaller proceed so we
    can observe whatever it does next.
    """
    log.info("signup_query payload_len=%d", len(request_payload))
    log.info("signup_query_reply var_len=0")
    return build_tagged_reply_var(0x84, b"")


def _handle_ntlm_negotiate(request_payload, session):
    """LOGSRV selector 0x0f — first leg of the OSR2 (MSN 2.5) sign-in.

    Replaces the plaintext credential blob of selector 0x00. The client sends
    an NTLM NEGOTIATE and asks for a single 0x84 variable back. The answer is a
    CHALLENGE carrying the nonce that the AUTHENTICATE on selector 0x10 has to
    respond to.
    """
    token = _ntlm_request_token(request_payload)
    if token is None or _ntlm.token_message_type(token) != _NTLM_NEGOTIATE:
        return _NTLM_NO_CHALLENGE_REPLY

    server_challenge = secrets.token_bytes(_ntlm.CHALLENGE_LEN)
    flags, challenge_token = _ntlm.build_challenge(token, server_challenge)
    session.ntlm_challenge = server_challenge
    session.ntlm_flags = flags
    log.info(
        "ntlm_challenge flags=0x%08x server_challenge=%s token_len=%d",
        flags,
        server_challenge.hex(),
        len(challenge_token),
    )
    return build_tagged_reply_var(0x84, _ntlm.wrap_token(challenge_token))


def _handle_ntlm_authenticate(request_payload, session):
    """LOGSRV selector 0x10 — second leg. Validates the AUTHENTICATE and signs in.

    The OSR2 client sends only an LM response, leaving NtChallengeResponse
    empty, and names itself in the Workstation field. It asks for a 0x82 word
    and a 0x83 dword back rather than another token.

    Returns the reply and the signing context an accepted exchange leaves
    behind, which is None on every refusal.
    """
    token = _ntlm_request_token(request_payload)
    if token is None or _ntlm.token_message_type(token) != _NTLM_AUTHENTICATE:
        return _ntlm_result_reply(LOGIN_RESULT_BAD_MEMBER_ID), None

    server_challenge = session.ntlm_challenge
    if server_challenge is None:
        log.warning("ntlm_authenticate arrived with no challenge on this connection")
        return _ntlm_result_reply(LOGIN_RESULT_BAD_MEMBER_ID), None

    auth = _ntlm.parse_authenticate(token, session.ntlm_flags)
    if auth is None:
        log.warning("ntlm_authenticate token too short len=%d", len(token))
        return _ntlm_result_reply(LOGIN_RESULT_BAD_MEMBER_ID), None

    log.info(
        "ntlm_authenticate user=%r domain=%r workstation=%r nt_len=%d lm_len=%d",
        auth.user_name,
        auth.domain_name,
        auth.workstation,
        len(auth.nt_response),
        len(auth.lm_response),
    )

    user = _default_store.users.get_user(auth.user_name)
    if user is None:
        log.info(
            "ntlm_reply result=%d reason=unknown_member_id member_id=%r",
            LOGIN_RESULT_BAD_MEMBER_ID,
            auth.user_name,
        )
        return _ntlm_result_reply(LOGIN_RESULT_BAD_MEMBER_ID), None

    if not _ntlm.password_matches(auth, server_challenge, user.password):
        log.info(
            "ntlm_reply result=%d reason=wrong_password member_id=%r",
            LOGIN_RESULT_BAD_PASSWORD,
            user.username,
        )
        log.log(TRACE, "ntlm_authenticate token=%s", token.hex())
        return _ntlm_result_reply(LOGIN_RESULT_BAD_PASSWORD), None

    session.sign_in(user)
    session.ntlm_challenge = None
    security = _ntlm.establish(auth, server_challenge, user.password)
    log.info(
        "ntlm_reply result=0 member_id=%r display_name=%r rights=0x%x security=established",
        user.username,
        user.display_name,
        user.rights,
    )
    return _ntlm_result_reply(LOGIN_RESULT_OK), security


def _handle_ntlm_bootstrap(session):
    """LOGSRV selector 0x11 — the account record the accepted sign-in reads."""
    log.info("ntlm_bootstrap user=%s", session.user.username or "-")
    log.info("ntlm_bootstrap_reply dwords=5 var_len=16 dwords=5")
    return _NTLM_BOOTSTRAP_PAYLOAD


def _ntlm_request_token(request_payload):
    """Pull the SSPI token out of an NTLM request, or None when it holds none."""
    send_params, recv_descriptors = parse_request_params(request_payload)
    blob = next((p.data for p in send_params if isinstance(p, VarParam)), None)
    if blob is None:
        log.warning("ntlm no variable param params=%d", len(send_params))
        log.log(TRACE, "ntlm_request payload=%s", request_payload.hex())
        return None

    header_type, token = _ntlm.unwrap_token(blob)
    message_type = _ntlm.token_message_type(token)
    log.info(
        "ntlm_request header_type=%s message_type=%s token_len=%d recv=%s",
        header_type,
        message_type,
        len(token),
        [f"0x{d:02x}" for d in recv_descriptors],
    )
    if message_type is None:
        log.warning("ntlm token is not NTLMSSP head=%s", token[:16].hex())
        return None
    return token


def _ntlm_result_reply(result):
    """Build the selector 0x10 reply: a 0x82 word and a 0x83 dword.

    The dword carries the sign-in result, in the vocabulary selector 0x00
    already uses — 0 signs in, 2 raises "This member ID is not valid.", 3
    raises "Password not valid. Please type it again."

    The word continues the message-type run the two legs already number: the
    CHALLENGE this server sends is header type 2, the AUTHENTICATE the client
    sends is 3, and 4 is the acceptance that closes the exchange.
    `CAuthenticator::StAuthenticate` (MCM.DLL @ 0x7f644d2b) presets the field to
    5 and compares it against 4 alone: on 4 it reports success and keeps the
    SSPI context, and on anything else it calls DeleteSecurityContext and
    reports the sign-in refused. The sign-in dialog reads the dword either way,
    so a refused word still signs in — but BILLADD gates its whole fetch on the
    status and dies with "Your account information cannot be downloaded at this
    time" before sending a request.
    """
    return build_static_reply(
        build_tagged_reply_word(NTLM_ACCEPTED if result == LOGIN_RESULT_OK else NTLM_REFUSED),
        build_tagged_reply_dword(result),
    )


def _handle_password_change(request_payload, session):
    """Handle a password change request (selector 0x01).

    The two 17-byte buffers hold the current and the new password. The change
    only commits when the current one matches the account the connection signed
    in as.

    Reply: dword 0 = success, non-zero = "current password not valid"
    (client shows same message for any non-zero value).
    """
    send_params, _ = parse_request_params(request_payload)
    old_pw = new_pw = None
    if len(send_params) > 0 and isinstance(send_params[0], VarParam):
        old_pw = send_params[0].data.split(b"\x00", 1)[0].decode("ascii", errors="replace")
    if len(send_params) > 1 and isinstance(send_params[1], VarParam):
        new_pw = send_params[1].data.split(b"\x00", 1)[0].decode("ascii", errors="replace")

    user = session.user
    if not session.is_authenticated:
        log.warning("password_change_reply status=%d reason=not_signed_in", PASSWORD_CHANGE_REFUSED)
        return build_tagged_reply_dword(PASSWORD_CHANGE_REFUSED)
    if old_pw is None or new_pw is None:
        log.warning(
            "password_change_reply status=%d reason=malformed params=%d",
            PASSWORD_CHANGE_REFUSED,
            len(send_params),
        )
        return build_tagged_reply_dword(PASSWORD_CHANGE_REFUSED)
    if old_pw != user.password:
        log.info(
            "password_change_reply status=%d user=%s reason=wrong_current",
            PASSWORD_CHANGE_REFUSED,
            user.username,
        )
        return build_tagged_reply_dword(PASSWORD_CHANGE_REFUSED)

    _default_store.users.set_password(user.username, new_pw)
    # The session holds a frozen copy, so re-read the account it now points at.
    session.sign_in(_default_store.users.get_user(user.username))
    log.info("password_change_reply status=0 user=%s", user.username)
    return build_tagged_reply_dword(0)


# --- Payload builders used by tests ---


def build_logsrv_bootstrap_payload():
    return _BOOTSTRAP_PAYLOAD


def build_logsrv_service_map_payload():
    return build_discovery_payload(LOGSRV_INTERFACE_GUIDS)
