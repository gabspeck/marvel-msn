"""Live conference rosters, keyed by room id.

Separate from `conference` because two services read them. CONFSRV owns a
roster — it joins, leaves and pushes to it — while DIRSRV only reports how many
members are in a room, as the node's `p`. Keeping the registry in its own
module lets both import it at module scope: `conference` imports `dirsrv` for
its property serialisation, so `dirsrv` cannot import `conference` back.

State lives for the process. Rooms are authored directory nodes, so the
registry stays bounded, and a retained room keeps its participant ids
monotonic across the last member leaving and a new one arriving.
"""

import threading


class _Room:
    """Live roster for one conference instance, shared by every connection.

    The lock covers the roster and the pushes that report a change to it, so
    every member reads joins, leaves and text in one order. It is always taken
    before a connection's send lock and never after, which is why the CONFSRV
    handler answers from `flush_pending_events` instead of `handle_request`.
    """

    def __init__(self):
        self.lock = threading.RLock()
        self.members = []
        self.next_participant_id = 1


_rooms = {}
_rooms_lock = threading.Lock()


def room_for(room_id):
    """The room's roster, created on first use."""
    with _rooms_lock:
        room = _rooms.get(room_id)
        if room is None:
            room = _Room()
            _rooms[room_id] = room
        return room


def room_population(room_id):
    """How many members are in one room right now.

    Backs the chat node's `p`: MSNFIND's Size cell renders that DWORD as
    "%d people" when `c` is 4, so a room reports occupancy where a file reports
    bytes. Read by `dirsrv._size_value`.

    Never creates the room — a search listing every chat node would otherwise
    register one per result. An unvisited room is 0, which is also the value
    that leaves the cell blank.

    Takes the two locks in sequence rather than nested: the registry lock only
    guards the dict, and holding it while waiting on a room's lock would invert
    the order the push path relies on.
    """
    with _rooms_lock:
        room = _rooms.get(room_id)
    if room is None:
        return 0
    with room.lock:
        return len(room.members)
