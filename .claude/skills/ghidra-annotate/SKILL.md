---
name: ghidra-annotate
description: Walk a Ghidra function through the ghidra-headless MCP and annotate it end-to-end — rename auto-generated function/param/local/label names, attach a precise plate comment (goal, params, return), and add line comments on critical sections. Recurses one level into auto-named callees by default. Use when the user asks to annotate/document/clean up a function, after any `decomp_function` that surfaces auto-names the user cares about, or when a `FUN_…` keeps reappearing across sessions.
version: 1.0.0
---

# ghidra-annotate

One invocation = one function fully annotated plus its direct auto-named callees. Codifies the project rule "annotate during analysis, not after" so nothing gets half-done.

## When to use

- User says "annotate this function", "clean up this FUN_", "document this", "name the locals here".
- Right after `decomp_function` exposes a function the user intends to rely on.
- A `FUN_…` / `LAB_…` keeps resurfacing across sessions — annotate it once, for good.
- You just gained understanding of a function during analysis — run this instead of hand-calling ten MCP tools.

Do **not** run this on functions the user hasn't decided to invest in. The skill makes permanent changes to `MSN95.gpr`.

## Prerequisites

- `ghidra-headless` MCP is live. If any `mcp__ghidra-headless__*` tool errors with "no program open", `project_program_open_existing` the binary first.
- `MSN95.gpr` loaded (path in memory: `reference_ghidra_path`).
- Target resolvable by name (e.g. `FUN_7f4049f9`) or address (`0x7f4049f9`).

## Invocation

```
target:<FUN_name|0xADDR> [depth:0|1|2] [dry-run]
```

- `depth:0` — target only.
- `depth:1` (default) — target + direct callees that still match the auto-name regex. Callee cap 16.
- `depth:2` — hard cap; beyond this, refuse and list the rest.
- `dry-run` — run resolution + signal gathering + proposed plate/rename render, but make **no** mutations.

Examples:

```
target:FUN_7f4049f9
target:0x7f4049f9 depth:2
target:FUN_7f5816b6 dry-run
```

## Workflow

Do these per function. One transaction per function — partial progress survives a later failure.

1. Resolve target: `function_at` (address) or `function_by_name`. Abort with the literal input on miss.
2. `transaction_status`. If a foreign transaction is open, **abort** — don't stack. Then `transaction_begin`.
3. `decomp_function` — capture C body + signature.
4. Snapshot existing names: `function_signature_get`, `function_variables`, `symbol_list` (function scope).
5. Gather signals (for naming and comments):
   - For every string literal in the body: `reference_from` at that address → `search_defined_strings` to recover the UTF-16LE text. Memory rule: UI strings are UTF-16LE — don't grep ASCII.
   - Scan decomp text for Win32/CRT API families (`CreateWindowExW`, `WSA*`, `wsprintfW`, `CoCreateInstance`, …).
   - Scan for `PROTOCOL.md` tokens — opcode names, selector values, field identifiers.
   - Note vtable shapes (`ppvObject`, `QueryInterface`, `AddRef`, `Release`).
6. Pick a new name via **Naming priority** (below). If no signal fires, **skip the rename** — a confidently-wrong name is worse than `FUN_…`. Record the gap; the plate will say so.
7. Apply:
   - If the chosen name contains `::`, run the **Placing a function in a class namespace** sub-procedure below instead of a plain rename. Otherwise `function_rename` with the chosen name (only if step 6 yielded a confident choice).
   - `function_signature_set` only when return/param types are plainly readable from signals. Don't guess types.
8. Params: `parameter_replace` or `variable_rename` for each match of the param regex → `decomp_writeback_params`.
9. Locals: `variable_rename` for each match of the local regex → `decomp_writeback_locals`.
10. Labels: `symbol_rename` for every `LAB_*` / `SUB_*` inside the function body (use `symbol_list` scoped to the function).
11. Plate: `comment_set` at the entry address, `type: PLATE`, body from the **Plate template**.
12. Line comments: walk the decomp; for each line matching a **Line-comment trigger**, `comment_set` with `type: PRE` (block header above the line) or `type: EOL` (inline). Never both on the same address.
13. `transaction_commit`.
14. Run the **Verification** checklist. If it fails, don't re-open a transaction — report the specific gap and move on.
15. If `depth >= 1`: `function_callees` → filter to names matching the auto-name regex → skip thunks to resolved imports → recurse steps 1–14. Cap 16 callees; list the rest.
16. Emit one final report:
    - `renamed: N funcs / M vars`
    - `comments: K`
    - `skipped (low confidence): [list]`
    - `remaining auto-names at depth+1: [list]`

## Auto-name patterns

| Kind | Regex |
|---|---|
| Function | `^FUN_[0-9a-fA-F]+$`, `^thunk_FUN_[0-9a-fA-F]+$`, `^SUB_[0-9a-fA-F]+$` |
| Label | `^LAB_[0-9a-fA-F]+$`, `^SUB_[0-9a-fA-F]+$` (when it is a label, not a function) |
| Param | `^param_\d+$`, `^in_[A-Z]{2,4}$` (e.g. `in_EAX`, `in_stack_…`) |
| Local | `^local_[0-9a-fA-F]+$`, `^[pc]?[iu]Var\d+$` (covers `iVar1`, `uVar2`, `puVar3`, `pcVar4`, `cVar5`), `^uStack_[0-9a-fA-F]+$`, `^in_stack_[0-9a-fA-F]+$` |
| Data (detect, **do not** rename) | `^DAT_[0-9a-fA-F]+$`, `^PTR_DAT_[0-9a-fA-F]+$`, `^UNK_[0-9a-fA-F]+$` |

## Plate comment template

Drop any empty section — max 6 lines total. No adjectives, no history, no "this function …".

```
Goal: <one-line imperative — what this function accomplishes>
Params:
  <name> (<type>): <role, units, constraints>
Returns: <type> — <meaning; enumerate error sentinels if any>
Calls: <comma list of notable external/Win32 calls, 0–4 items>
Notes: <one line for a non-obvious invariant or caller contract>
```

Low-confidence target → `Goal: unresolved — needs <what's missing>` and still fill `Params:`/`Returns:` from the signature.

## Line-comment triggers

Emit a comment only when the line is one of:

- Dispatch switch / jump table — label what the discriminant means.
- Error return (`return -1` / `NULL` / `HRESULT`) — name the failure condition.
- Resource acquire/release pair (`CreateX` / `CloseHandle`, `malloc` / `free`, `LockResource` / `UnlockResource`).
- Non-obvious bit math — masks, shifts, packed fields, endian flips — decode the layout.
- Wire-buffer write feeding `send` / `WSASend` / `WriteFile` — annotate offset/field.
- String formatting into a wire buffer (`wsprintfW`, `_snwprintf`).
- Win32 call whose flags/lparam encode non-obvious semantics (`SendMessage` with `WM_USER+N`, `DialogBoxParam` with a resource ID).
- Inline asm or compiler intrinsic (`__outbyte`, `__readcr0`).
- Loop with a non-literal bound (computed from a header field).
- Magic constant that matches a `PROTOCOL.md` token.

Silence otherwise. No comments on trivial assignments, obvious arithmetic, or self-evident calls.

## Naming priority

First signal that yields high confidence wins. Stop looking once one fires.

1. **UTF-16LE string ref** — `search_defined_strings` + `reference_from`. Strongest for MSN95 UI/wire.
2. **Win32/CRT API family dominating the body** — name by the dominant family (e.g. many `WSAAsyncSelect` + `recv` → `<Service>WsaThreadProc`).
3. **PROTOCOL.md token** — grep the repo's `PROTOCOL.md` for opcode/field identifiers seen in the body; align the name with project vocabulary.
4. **vtable / COM shape** — `QueryInterface` / `ppvObject` / known CLSID → `<Interface>::<Method>`.
5. **Single-caller inheritance** — last resort, and only as `<Caller>_<verb>`. Never use this if the caller itself is still `FUN_`.
6. No signal → **skip rename**. Add plate noting the gap. Do not invent.

## Placing a function in a class namespace

Whenever step 6 chose a name of the form `<Class>::<Method>` (COM vtable rule, or any namespaced C++ symbol), do **not** pass the literal `::` name to `function_rename`. That stores the `::` in the symbol name and drops the function in Global — and worse, Ghidra may auto-create a plain `Namespace` with that class name as a side effect, which then blocks a later `class_create`. Instead:

1. Ensure `<Class>` exists as a `GhidraClass`:
   - Try `class_create(name="<Class>")`. Success → done.
   - On `DuplicateNameException` ("A Namespace symbol with name `<Class>` already exists") → a plain `Namespace` exists from a prior (buggy) run. Promote it with `ghidra_eval`:

     ```python
     from ghidra.app.util import NamespaceUtils
     ns_sym = list(currentProgram.getSymbolTable().getSymbols("<Class>"))[0]
     NamespaceUtils.convertNamespaceToClass(ns_sym.getObject())
     ```

     Note the package: `ghidra.app.util.NamespaceUtils`. There is no `ghidra.program.model.symbol.NamespaceUtils` — that import will `ImportError`.
2. `function_rename(addr, "<Method>")` — short name only. Never pass `"<Class>::<Method>"`.
3. `symbol_namespace_move` the function's symbol into `<Class>`.
4. Sanity-check via `symbol_list` scoped to the function's entry: the primary symbol's parent namespace must be `<Class>` and the short name must be `<Method>` with no embedded `::`.

This sub-procedure is idempotent — re-running it on an already-correct symbol is a no-op, and `convertNamespaceToClass` is also a no-op on a namespace that is already a `GhidraClass`.

## Stop conditions

- Depth cap: hard 2, default 1, `depth:0` → target only.
- Callee cap at depth 1: 16. List the rest and stop.
- Skip any function > 2000 decompiled lines — print address + reason, do not annotate.
- Skip thunks that resolve to named imports (already documented by their import name).
- Foreign open transaction → abort, do not stack.
- On any MCP error mid-function: still `transaction_commit` (partial > lost), report the specific failure, continue to the next function.
- `dry-run` → do steps 1–6 and 11–12 as read-only; print what would change; no `_rename` / `_set` / `_writeback_*` calls.

## Verification

After each commit, run every check. If any fails, name the gap in the final report.

1. `decomp_function` again → body contains none of: `FUN_`, `LAB_`, `SUB_`, `param_N`, `local_N`, `i/u/pu/pc/cVar\d`.
2. `comment_get_all` at entry address → `PLATE` present and non-empty.
3. `function_signature_get` → name matches the chosen new name (or still equals original if intentionally skipped).
4. If the chosen name contained `::`: via `symbol_list` at the entry address, the primary symbol's parent namespace is `<Class>` with type `GhidraClass` (not plain `Namespace`) and the short name is `<Method>` with no embedded `::`.
5. `function_variables` → every entry is renamed or listed as a justified skip (e.g. compiler-artifact spill slot).
6. 3-line per-function report:
   `renamed: N funcs / M vars` · `comments: K` · `remaining auto-names: [list]`.

## Don't

- Don't invent names. Skip the rename and say so in the plate.
- Don't rename data labels (`DAT_…`, `PTR_DAT_…`) — out of scope here; mention them in comments instead.
- Don't propagate a param rename to callers from within this skill.
- Don't set types you're not sure about. `function_signature_set` is optional, not mandatory.
- Don't rename locals without `decomp_writeback_locals`, and don't rename params without `decomp_writeback_params` — the decomp view won't reflect the change and the next annotator will redo your work.
- Don't stack transactions. If one is open, abort.
- Don't walk past `depth:2`. The skill refuses.
- Don't ask the user before running each step on the target they specified — they already opted in by invoking the skill. Do ask before widening depth mid-run.
