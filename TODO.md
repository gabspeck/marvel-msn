# TODO

- Deeper RE on the SIGNUP phone-book update function (LOGSRV opcode 0x0e,
  SIGNUP.EXE!FUN_004043c1 @ 0x004043c1). Current stub replies dword=0 which
  makes the wizard tick "Update your list of local phone numbers (done)"
  without any FTM download. Figure out the real contract: what the send
  dword=8 means, whether a non-zero reply triggers an actual phone-book
  fetch (FTM? separate opcode?), and where the client stores / versions
  the phone book so we can serve real updates.
