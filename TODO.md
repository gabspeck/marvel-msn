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

- Sub-8bpp DIBs still fault the client. `_picture_chunk_limit` ends the
  first transfer chunk on `bfOffBits`, which keeps
  `MVPR14N!MVPicture_PlainBmpDecodeIncremental @ 0x7E866953` from running
  its 4-byte-short palette build. A 1bpp or 4bpp image has `bfOffBits`
  below the 400 bytes `MVPicture_SelectDecoderByMagic` wants before it
  creates the decoder, so the first decode pass always sees more than
  `bfOffBits` and overflows anyway. `HANDBOOK.M14` `mail.bmp` (4bpp, 382 B)
  and `smokes.bmp` (4bpp, 614 B) will GPF the client if a topic displays
  them. The route out is serving pictures as `lP` segmented hypergraphics
  the way `MVDOC.M14` does — that reaches `Shed_*` over selector `0x1b`
  and never enters the WltPicture branch — which needs an MRB encoder.

