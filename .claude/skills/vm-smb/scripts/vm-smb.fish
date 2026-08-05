#!/usr/bin/env fish
#
# SMB access to the 86Box Windows 95 VM.
#
# Win95 speaks SMB1 over port 139 only. It rejects the generic *SMBSERVER
# called name that smbclient sends when given an IP, so the NetBIOS name is
# mandatory. Server-side `cd` is unsupported; every path is passed whole.
#
# Env overrides: VM_HOST (NetBIOS name), VM_IP (forces -I), VM_SHARE.

set -q VM_HOST; or set VM_HOST 86BOXW95
set -q VM_SHARE; or set VM_SHARE C

set -l opts \
    -N -p 139 \
    --option='client min protocol=NT1' \
    --option='client max protocol=NT1' \
    --option='client lanman auth=yes' \
    --option='client ntlmv2 auth=no'

if set -q VM_IP
    set -a opts -I $VM_IP
end

function usage
    echo "usage: vm-smb.fish <command> [args]"
    echo ""
    echo "  shares                      list shares on the VM"
    echo "  ls [mask]                   list a path; directories need a trailing \\*"
    echo "  get <remote> [local]        download one file"
    echo "  put <local> <remote>        upload one file"
    echo "  pull <remotedir> <localdir> download a directory tree (tar mode)"
    echo "  del <remote>                delete one file"
    echo "  sh <cmds>                   raw smbclient -c passthrough"
    echo ""
    echo "Paths use backslashes and are relative to the share root:"
    echo "  vm-smb.fish ls 'Program Files\\The Microsoft Network\\*'"
    echo "  vm-smb.fish get 'WINDOWS\\WIN.INI' win.ini"
end

# Run one smbclient -c command string against the share.
function smbrun -V opts -V VM_HOST -V VM_SHARE
    smbclient //$VM_HOST/$VM_SHARE $opts -c "$argv[1]" 2>&1 | grep -v 'lpcfg_do_global_parameter'
end

set -l cmd $argv[1]
set -e argv[1]

switch "$cmd"
    case shares
        smbclient -L $VM_HOST $opts 2>&1 | grep -v 'lpcfg_do_global_parameter'

    case ls
        set -l mask '*'
        test (count $argv) -ge 1; and set mask $argv[1]
        smbrun "ls \"$mask\""

    case get
        test (count $argv) -ge 1; or begin
            usage
            exit 2
        end
        set -l local $argv[2]
        test -n "$local"; or set local (basename (string replace -a '\\' / $argv[1]))
        smbrun "get \"$argv[1]\" \"$local\""

    case put
        test (count $argv) -ge 2; or begin
            usage
            exit 2
        end
        smbrun "put \"$argv[1]\" \"$argv[2]\""

    case pull
        test (count $argv) -ge 2; or begin
            usage
            exit 2
        end
        set -l dest $argv[2]
        mkdir -p $dest; or exit 1
        set -l tarball (mktemp -t vm-smb.XXXXXX.tar)
        smbclient //$VM_HOST/$VM_SHARE $opts -Tc $tarball "$argv[1]" 2>&1 \
            | grep -v 'lpcfg_do_global_parameter'
        tar xf $tarball -C $dest; and echo "extracted to $dest"
        rm -f $tarball

    case del
        test (count $argv) -ge 1; or begin
            usage
            exit 2
        end
        smbrun "del \"$argv[1]\""

    case sh
        test (count $argv) -ge 1; or begin
            usage
            exit 2
        end
        smbrun "$argv"

    case '*'
        usage
        exit 2
end
