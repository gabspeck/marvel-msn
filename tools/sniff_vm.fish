#!/usr/bin/env fish
#
# Capture the frames an 86Box guest puts on the host bridge.
#
# Each VM's NIC is a tap port on br0, so the guest shares the bridge with the
# host and the physical LAN. Filtering on the guest MAC isolates one VM and
# keeps every link-layer protocol in the capture — ARP, IPX, NetBEUI and IP
# alike — which matters when the thing under test is server discovery and the
# transport is not yet known.
#
# Usage: tools/sniff_vm.fish <name> [mac]
#
# Writes captures/lan/<name>-<timestamp>.pcap. Ctrl-C to stop, or kill the
# tcpdump child. Known guest MACs come from 86box.cfg (the config stores the
# last three octets; 86Box prepends 00:0c:87 for the AMD PCnet-FAST III).

set -l name $argv[1]
set -l mac $argv[2]

if test -z "$name"
    echo "usage: tools/sniff_vm.fish <name> [mac]" >&2
    exit 1
end

# Windows 95 OSR2 MSN 2.0 VM
test -n "$mac"; or set mac 00:0c:87:b1:e9:39

set -l iface (test -n "$VM_SNIFF_IFACE"; and echo $VM_SNIFF_IFACE; or echo br0)
set -l root (dirname (status filename))/..
set -l dir $root/captures/lan
mkdir -p $dir

set -l out $dir/$name-(date +%Y%m%d-%H%M%S).pcap

echo "iface $iface  mac $mac"
echo "out   $out"
exec sudo tcpdump -i $iface -s 0 -U -n -w $out ether host $mac
