# TODO

- Deeper RE on the SIGNUP phone-book update function (LOGSRV opcode 0x0e,
  SIGNUP.EXE!FUN_004043c1 @ 0x004043c1). Current stub replies dword=0 which
  makes the wizard tick "Update your list of local phone numbers (done)"
  without any FTM download. Figure out the real contract: what the send
  dword=8 means, whether a non-zero reply triggers an actual phone-book
  fetch (FTM? separate opcode?), and where the client stores / versions
  the phone book so we can serve real updates.

- Implement OSR2 (MSN 2.5) login — LOGSRV selector 0x0f carries an
  NTLMSSP handshake instead of the plaintext 0x00 bootstrap. Current
  stub (`_handle_osr2_bootstrap` in `src/server/services/logsrv.py`)
  logs the Type 1 NEGOTIATE blob and replies with the old 0x00
  payload, which the client silently rejects (returns to login
  prompt, no error). Real fix = server-side NTLM accept loop
  (NEGOTIATE → CHALLENGE → AUTHENTICATE). Prefer `pyspnego` (pure
  Python, `spnego.server` API, supports raw NTLM without SPNEGO
  wrapper); fall back to `impacket.ntlm` if the 1997 client rejects
  modern flag/field combinations. We control account validity so
  the AUTHENTICATE can be rubber-stamped — no real LM/NT hash
  verification needed.

- Align the DIRSRV Categories surface with the connected-client reference
  screenshot. The live client shows a localized `Categories (US)` wrapper,
  a separate top-of-folder shabby bitmap strip, and distinct server-delivered
  per-node icons that are not present in local client assets. Current fixtures
  still stub this as a plain `Categories` container with eight children and
  shared default shabby assets. Follow-up: trace where the country suffix and
  `UNITED STATES:` header come from, confirm which shabby property feeds the
  top strip (`mf` vs `wv`), and replace the one-icon fallback with per-node
  icon ids/assets. The screenshot also implies a richer category set than the
  current stub; visible object count needs reconciliation before fixtures are
  expanded.
