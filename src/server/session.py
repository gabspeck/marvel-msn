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
