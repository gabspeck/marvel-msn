# CLAUDE.md

## General guidelines 

(taken from https://github.com/forrestchang/andrej-karpathy-skills/blob/main/CLAUDE.md)

## 1. Think Before Coding

**Don't assume. Don't hide confusion. Surface tradeoffs.**

Before implementing:
- State your assumptions explicitly. If uncertain, ask.
- If multiple interpretations exist, present them - don't pick silently.
- If a simpler approach exists, say so. Push back when warranted.
- If something is unclear, stop. Name what's confusing. Ask.

## 2. Simplicity First

**Minimum code that solves the problem. Nothing speculative.**

- No features beyond what was asked.
- No abstractions for single-use code.
- No "flexibility" or "configurability" that wasn't requested.
- No error handling for impossible scenarios.
- If you write 200 lines and it could be 50, rewrite it.

Ask yourself: "Would a senior engineer say this is overcomplicated?" If yes, simplify.

## 3. Surgical Changes

**Touch only what you must. Clean up only your own mess.**

When editing existing code:
- Don't refactor things that aren't broken. At best, suggest it to the user after making the requested changes.
- Match existing style, even if you'd do it differently.
- If you notice unrelated dead code, mention it - don't delete it.

When your changes create orphans:
- Remove imports/variables/functions that YOUR changes made unused.
- Don't remove pre-existing dead code unless asked.

The test: Every changed line should trace directly to the user's request.

## 4. Goal-Driven Execution

**Define success criteria. Loop until verified.**

Transform tasks into verifiable goals:
- "Add validation" → "Write tests for invalid inputs, then make them pass"
- "Fix the bug" → "Write a test that reproduces it, then make it pass"
- "Refactor X" → "Ensure tests pass before and after"

For multi-step tasks, state a brief plan:
```
1. [Step] → verify: [check]
2. [Step] → verify: [check]
3. [Step] → verify: [check]
```

Strong success criteria let you loop independently. Weak criteria ("make it work") require constant clarification.

---

**These guidelines are working if:** fewer unnecessary changes in diffs, fewer rewrites due to overcomplication, and clarifying questions come before implementation rather than after mistakes.


## Project-specific guidelines
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
beyond testing a hypothesis (when you do, revert it after testing it). Take a step back and analyze the problem using 
decompilation with Ghidra, live debugging with SoftIce or a combination of both.
