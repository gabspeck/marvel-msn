CLAUDE.md
===

* This is an attempt to build a faithful as possible reconstruction of the Marvel protocol used in the original 
incarnation of The Microsoft Network, shipped with Windows 95.

* Client behavior is our guiding light and in absence of source code and specifications, its behavior *is* the protocol.
Therefore, do not suggest workarounds on the client side to fix an issue.

* Do not worry about "legacy" behavior in the server or "backward compatibility". This is a project in development with
no active userbase. Refactor mercilessly when new findings contradict old assumptions

* When updating documentation or inline comments, do not reference the content you're replacing. Simply rewrite it to 
match the latest known facts.

* Avoid narration and verbosity in documents and in-line comments. Keep text information-dense, precise and to the 
point.

* When writing comments, do not state speculation as fact. Be clear about the source of a statement: empiric observation
of wire traffic + user reports of client behavior, live debugging, static analysis, etc.

* If there's a mismatch between expected and actual client behavior, do not apply hacks on the server to force a fix
beyond testing a hypothesis. Take a step back and analyze the problem using decompilation with Ghidra, live debugging
with SoftIce or a combination of both.
