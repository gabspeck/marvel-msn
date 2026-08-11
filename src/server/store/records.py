"""Constructors for the records the store holds.

Shared by two callers: `fixtures` builds the seed with them at import, and the
BBS post channel builds a live message node with them at commit time
(`server.services.bbs.commit_post`). They therefore live outside `fixtures` —
a write path must not import the seed module to build a record.
"""

from __future__ import annotations

import datetime
import struct

from ..mos_apps import APP_BBS_SERVICE
from .base import BbsFields, DirectoryNode, NodeContent


def mnid_key(f0, f8):
    """Wire-form node_id (decimal `f0:f8`) and the 8-byte `a` blob.

    Server node_id keys are `"wire_dword_0:wire_dword_1"`, which on the
    client side are `(field_8, field_c)` of the 24-byte `_MosNodeId`
    (GetNthChild @ MOSSHELL 0x7f3fe131 stores `'a'[0]` into the child's
    `field_8` slot and `'a'[1]` into `field_c`; `field_0` is inherited
    from the parent). So if a fixture's wire key is `"X:Y"`, its `'a'`
    payload must equal `(X, Y)`, which is what this helper packs.
    """
    return f"{f0}:{f8}", struct.pack("<II", f0, f8)


def bbs_date_to_unix(s):
    """Parse a `%B %d, %Y %I:%M %p` timestamp into a Unix time_t.

    The string is **local wall-clock time**, i.e. what the client should display,
    matching reference/screenshots/bbs.png whose reader header reads "10:12 AM".

    Converted with the **current** UTC offset, not the offset that was in force
    on that date. Windows 95 has no historical timezone database — it
    applies its single current rule to every timestamp — so a 1995 `_D` is
    rendered by the client with today's offset. Python's `.timestamp()` would
    instead honor the 1995 rule (e.g. Europe/Lisbon ran CEST +0200 until 1996),
    which put the Date column an hour behind the `v`/`w` dialog strings that pass
    through verbatim. Using the current offset makes the column, the dialog and
    the reference agree.

    Assumes the client's timezone matches this host's. Both live on the same
    machine here; a real deployment would format dialog strings from the
    member's profile timezone instead.

    Empty input → 0, which build_bbs_props still emits as `_D` = 0 (never
    omitted — an omitted tag truncates the record).
    """
    if not s:
        return 0
    naive = datetime.datetime.strptime(s, "%B %d, %Y %I:%M %p")
    offset = datetime.datetime.now().astimezone().utcoffset() or datetime.timedelta(0)
    return int((naive - offset).replace(tzinfo=datetime.UTC).timestamp())


def unix_to_wire_filetime(seconds):
    """Unix time_t → Windows FILETIME, the wire form of `w`.

    Zero in stays zero out: it is the "no date" sentinel both directions.
    """
    if not seconds:
        return 0
    return (seconds + 11644473600) * 10_000_000


def bbs_node(
    f0,
    f8,
    name,
    *,
    is_container,
    author="",
    date="",
    parent_subid=0,
    has_children=False,
    body="",
    body_format=BbsFields.body_format,
    delegate=False,
    body_raw=None,
    size_bytes=None,
    attachment_count=0,
    attachment_data=b"",
    download_count=0,
):
    """A BBS tree node (board / conversation / reply).

    `is_container` means **board or folder**, not "has replies" — it drives `b`
    bit 0x01 (CLEAR = container, SET = message), which is bbsnav's conversation
    test. Every message takes is_container=False, whether or not anything
    replies to it; a reply is expressed by `parent_subid` (`_P`), not by tree
    position.

    `has_children` drives `_F` bit 0x1000, the child-count gate read by
    CBbsNavTreeNode_OkToGetChildren (0x7F5F1427). Only the board sets it —
    messages have no tree children, so leaving it False stops the reader
    asking for children that do not exist. The rest of `_F` is fixed: every
    node here is a native MSN bulletin board carrying rich text, which is what
    unlocks the Compose window's formatting and attachment commands. See
    `server.services.bbs._folder_flags`.

    Rides DirectoryNode with app_id=APP_BBS_SERVICE and language=0; the
    BBS-specific tags (`_a/_D/_P/_t/_F`) live in the attached BbsFields, read by
    build_bbs_props and ignored by DIRSRV serialisation. `p` (Size) is the body
    byte count. `name` is the Subject (wire `e`).

    `body` is always plain text. `body_format` names the X-MOS-Format the
    reader is told to stream it as, per message — "RTF" (the default) wraps it
    in an RTF document so the body draws in a proportional font, "TEXT" sends
    it verbatim and lands in the RichEdit's default Courier New.

    Set `delegate` on the board — the node DIRSRV lists inside a category. It
    emits `b` bit 0x04 + `c`/`l`/`i`, so MOSSHELL `HrSetupDelegate` builds the
    inner mnid `{field_0=2, field_8/field_c=mnid_a, field_10=0}` and hands the
    folder to bbsnav, which then reads this same node over svc "BBS". Nodes
    below the board inherit field_0=2 and need no delegate tags.
    """
    key, mnid = mnid_key(f0, f8)
    return DirectoryNode(
        node_id=key,
        is_container=is_container,
        app_id=APP_BBS_SERVICE,
        mnid_a=mnid,
        delegate=delegate,
        content=NodeContent(
            name=name,
            go_word="",
            category="",
            # `tp` is free server text — the client keeps it as an opaque cache
            # slot for the Type column and the General page's item 1011. Only
            # the board is a DIRSRV row, and DSNED names app_id 2 "Bulletin
            # Board Folder" (STRINGTABLE 124, GETPMTE table in docs/DSNED.md
            # §2.1), so use the client's own vocabulary. Messages are never
            # asked for `tp` — it is neither a BBS extra tag nor one of the
            # shared MOS tree tags — and an empty string there stays honest.
            # Blank on the board rendered as "<unknown type>" (string 0xBF).
            type_str="Bulletin Board Folder" if is_container else "",
            price_dword=0,
            rating_dword=0,
            description="",
            language=0,
            topics="",
            people="",
            place="",
            u_value="",
            forum_mgr="",
            vendor_id=0,
            owner=author,
            # The Properties dialog fetches the shared MOS tree tags one at a
            # time (`q,g` then `v,g` …), and build_bbs_props hands those to
            # DIRSRV's serialiser. Mirror the post date into `created`/`modified`
            # so the dialog shows the real timestamp instead of blanks; the
            # listview Date column still comes from `_D`.
            created=date,
            modified=date,
            # `w` for the board's DIRSRV row — the Find results window formats
            # it as a FILETIME and has no blank branch, so mirror `_D` here
            # rather than leaving the Date Modified column on the 1601 epoch.
            modified_filetime=unix_to_wire_filetime(bbs_date_to_unix(date)),
            # A posted message carries its own plain-text length in X-MOS-Size;
            # `body` is empty there because the upload is already encoded.
            size_bytes=len(body) if size_bytes is None else size_bytes,
            bbs=BbsFields(
                author=author,
                date_unix=bbs_date_to_unix(date),
                parent_subid=parent_subid,
                has_children=has_children,
                body=body,
                body_format=body_format,
                body_raw=body_raw,
                attachment_count=attachment_count,
                attachment_data=attachment_data,
                download_count=download_count,
            ),
        ),
    )


# Wall-clock format `bbs_date_to_unix` parses, and the one the Properties
# dialog shows verbatim through `created`/`modified`.
BBS_POST_DATE_FORMAT = "%B %d, %Y %I:%M %p"


def build_bbs_post(
    msg_id,
    board_id,
    *,
    subject,
    author,
    parent_subid,
    body_raw,
    body_format,
    size_bytes,
    attachment_count=0,
    attachment_data=b"",
):
    """A BBS message node built from an article the Compose window just posted.

    `author` comes from the connection's signed-in account. The uploaded article
    carries no author header — the Compose window writes X-MOS-To, Subject,
    References and the X-MOS-* control set (BBSNAV FUN_7F5FBD4E @ 0x7F5FBD4E),
    never a From — so the identity has to come from the session. It goes back
    out as the `From:` header and as the tree's `_a`, and because MOSABP32
    passes a From with no '@' through whole, it is also the key the Member
    Properties sheet resolves on.

    `body_raw` is the uploaded body verbatim — the client encodes it before it
    reaches the wire, so it goes back out untouched under the same
    `body_format`. Dated now, because the article the client sends carries no
    Date header.
    """
    return bbs_node(
        msg_id,
        board_id,
        subject,
        is_container=False,
        author=author,
        date=datetime.datetime.now().strftime(BBS_POST_DATE_FORMAT),
        parent_subid=parent_subid,
        body_raw=body_raw,
        body_format=body_format,
        size_bytes=size_bytes,
        attachment_count=attachment_count,
        attachment_data=attachment_data,
    )


# Name each attachment node carries as its Subject (`e`). The reader never
# shows it — the file name it draws under the icon comes out of the MOSAF
# object's own CONTENTS record inside the body — so it only has to be something
# legible in a log or the Properties dialog.
BBS_ATTACHMENT_NAME = "Attachment %d"


def build_bbs_attachment_nodes(message):
    """The tree nodes behind one message's attachments.

    BBSNAV `FUN_7F5FC919` @ 0x7F5FC919 walks the MOSAF objects it found in the
    body and addresses the k-th one as `(message id + k, board id)`, then reads
    `z` and `_r` off it through `CTreeNavClient::GetProperties`. Each of those
    mnids has to resolve, so a message with N attachments brings N nodes with
    it. They hang off no parent: the board lists messages, not files.
    """
    msg_id, _sep, board_id = message.node_id.partition(":")
    bbs = message.content.bbs
    return [
        bbs_node(
            int(msg_id) + k,
            int(board_id),
            BBS_ATTACHMENT_NAME % k,
            is_container=False,
            author=bbs.author,
            date=message.content.created,
            parent_subid=int(msg_id),
        )
        for k in range(1, bbs.attachment_count + 1)
    ]
