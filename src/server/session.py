"""Per-connection identity.

One `Session` exists for the life of a client connection. Everything the client
runs — the shell, the billing dialog, the BBS reader, the statement viewer —
rides that single connection through MOSCP.EXE, so one session covers every
service pipe the client opens.

The object is mutable on purpose. A handler captures it when its pipe opens, and
LOGSRV fills it in later on the same connection: the LOGSRV pipe itself is open
before any credential has been checked.
"""

from .store import ANONYMOUS_USER, RIGHTS_AUTHORING


class Session:
    """Who the connection is signed in as."""

    def __init__(self):
        self.user = ANONYMOUS_USER
        # Server nonce and negotiated flags held between the NTLM NEGOTIATE on
        # LOGSRV selector 0x0f and the AUTHENTICATE on 0x10. They sit on the
        # connection rather than the pipe so a client that reopens LOGSRV
        # mid-exchange still matches. The short AUTHENTICATE this client sends
        # carries no flags of its own, so the CHALLENGE's are what verify it.
        self.ntlm_challenge = None
        self.ntlm_flags = 0

    @property
    def is_authenticated(self):
        return self.user is not ANONYMOUS_USER

    @property
    def is_admin(self):
        """Whether the account holds the authoring rights DIRSRV advertises as `x`."""
        return bool(self.user.rights & RIGHTS_AUTHORING)

    def sign_in(self, user):
        self.user = user

    def sign_out(self):
        self.user = ANONYMOUS_USER

    def __repr__(self):
        return f"Session(user={self.user.username!r})"
