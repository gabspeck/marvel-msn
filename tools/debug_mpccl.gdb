set arch i386
target remote localhost:12345

# Phase 1: Key checkpoints inside InitializeLoginServiceSession
# Using hardware breakpoints (survive DLL loads, limited to 4)

break *0x0460273B
commands
  silent
  printf "=== HIT: 0x0460273B after InitializeServiceInterfaceSelectorState ===\n"
  printf "  EAX=%d (0=early exit, 1=continue)\n", $eax
  info reg eax ecx edx ebx esp ebp esi edi eip
  cont
end

break *0x0460284B
commands
  silent
  printf "=== HIT: 0x0460284B after credential copy, sessionHandle check ===\n"
  info reg eax ecx edx ebx esp ebp esi edi eip
  cont
end

break *0x04602906
commands
  silent
  printf "=== HIT: 0x04602906 convergence before pipe-open prep ===\n"
  info reg eax ecx edx ebx esp ebp esi edi eip
  cont
end

break *0x04602963
commands
  silent
  printf "=== HIT: 0x04602963 after _OpenMOSPipeWithNotifyEx_28 ===\n"
  printf "  AX=0x%04x (FFFF=fail, else=pipe handle)\n", $eax & 0xffff
  info reg eax ecx edx ebx esp ebp esi edi eip
  cont
end

printf "\n4 hardware breakpoints set. Resuming CPU.\n"
printf "Start the MSN login now.\n\n"
cont
