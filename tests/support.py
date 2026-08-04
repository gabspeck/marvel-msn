"""Shared helpers for tests that need a signed-in connection.

Handlers and reply builders read identity off a `Session`, so a test that
exercises a per-member reply has to hand one over. These wrap the seeded
accounts so a test says which member it is acting as and nothing more.
"""

from server.session import Session
from server.store import app_store

# The two seeded accounts, by username. `ADMIN` holds authoring rights and the
# whole SASRV token list; `SUBSCRIBER` holds neither.
ADMIN = "billg"
ADMIN_PASSWORD = "msn@96"
SUBSCRIBER = "sjobs"
SUBSCRIBER_PASSWORD = "whatsnext"


def seed_user(username=ADMIN):
    """The account record `username` names, straight out of the store."""
    user = app_store.users.get_user(username)
    assert user is not None, f"no seeded account named {username!r}"
    return user


def signed_in(username=ADMIN):
    """A session already signed in as `username`."""
    session = Session()
    session.sign_in(seed_user(username))
    return session


def anonymous():
    """A session that never signed in."""
    return Session()
