Confirmed contents of MSN nodes
===

The nodes below are confirmed by the 1995 video tutorial of MSN, which features footage of a live MSN client browsing
the US localized nodes.

Address combobox (upper left corner)
---

Shows the hierarchy below when on the MSN Central home page. Order seems alphabetical:

```
The Microsoft Network
|_ Categories (US)
|_ Favorite Places
|_ Member Assistance (US)
|_ Worldwide Categories
|_ Worldwide Member Assistance
```

* This combobox is a tree view, so the five rows are not all siblings. `Worldwide Categories` and
`Worldwide Member Assistance` are the client's two pinned hubs — `GetSpecialMnid(0)` (wire `0:0`) and
`GetSpecialMnid(1)` (wire `1:0`) — and MOSSHELL names them from STRINGTABLE `0x8E`/`0x8F` rather than
from the server's `e` (`docs/MOSSHELL.md` §6.1.1). `Categories (US)` and `Member Assistance (US)` are the
localized children each hub resolves to via `GetLocalizedNode`, which is also where the two HOMEBASE
`LJUMP` buttons land.
  * From the video, it's possible to see that a node can be linked from multiple parents. E.g. Member assistance contains
  a link to MSN Today.

Member assistance (US)
---

* The MSN Member Lobby (directory)
* MSN Beta Center (directory)
* MSN Today
* Member Assistance Kiosk - July 19 (unknown - blue circle with "i" icon)
* First-Time-User Experience (directory)
* Member Guidelines (MOSVIEW)
* MSN Beta News Flash - July 19 (document?)
* Member Guidelines (document?)
* Member Agreement (document?)

Q: what `c` value do these document-type nodes carry?

Categories (US)
---

Most nodes are of type "Category", exceptions noted between parentheses. Children of A&E 

* Arts and Entertainment
  * Books and Writing
  * Movies
  * Art and Design
  * Television and Radio
  * Arts and Entertainment Kiosk
  * Arts Suggestion Box (BBS board)
  * The Big Chip
  * Genres
  * Comedy and Humor
  * The Music Forum
  * Theater and Performance
  * Other Entertaining Places to Visit
  * Coming Attractions
* Business and Finance
* Computers and Software
* Education and Reference
* Home and Family
* Interest, Leisure and Hobbies (Folder)
* People and Communities
* Public Affairs
* Science and Technology
* Special Events
* Sports, Health and Fitness
* The Internet Center
* The MSN Member Lobby (Folder)
* The Microsoft Nework Beta

"Category" and "Folder" are Type-column text, not two node classes. The column
is DSNAV RCDATA 0x81 col 1 (string id 141 "&Type", tag `tp`, width 120), read by
`CDsNavTreeNode::GetDetailsStruct` @ `0x7F581621`. MOSSHELL keeps `tp` as an
opaque cache slot and never inspects it. Neither string exists in DSNAV.NAV or
MOSSHELL.DLL, so both values arrive over the wire. The generic folder glyph on
the two "Folder" rows is the no-`h` default icon, not a second container class.
The client cannot behave differently based on either value.


