from bcc import BPF
import time
import socket
import struct
import argparse

# Parse command line arguments
parser = argparse.ArgumentParser(description="eBPF/XDP High-Performance Firewall")
parser.add_argument("-i", "--interface", required=True, help="Network interface to attach XDP (e.g., eth0)")
parser.add_argument("-b", "--block", action="append", help="IP address to block", default=[])
args = parser.parse_args()

# Load BPF program
bpf_code = open("xdp_firewall.c").read()
b = BPF(text=bpf_code)
xdp_fn = b.load_func("xdp_router_firewall", BPF.XDP)

# Attach to interface
print(f"Attaching XDP program to {args.interface}...")
b.attach_xdp(args.interface, xdp_fn, 0)

# Add IPs to the BPF Map
drop_ips_map = b.get_table("drop_ips")
for ip in args.block:
    ip_bytes = struct.unpack("I", socket.inet_aton(ip))[0]
    drop_ips_map[bpf_type(ip_bytes)] = bpf_type(0)
    print(f"[+] IP {ip} added to blacklist.")

print("Firewall is active. Press Ctrl+C to stop.")

try:
    while True:
        time.sleep(2)
        # Optional: Print drop statistics
        for k, v in drop_ips_map.items():
            ip_str = socket.inet_ntoa(struct.pack("I", k.value))
            if v.value > 0:
                print(f"[{ip_str}] Packets dropped: {v.value}")
except KeyboardInterrupt:
    print("\nRemoving XDP program...")
    b.remove_xdp(args.interface, 0)
    print("Done.")
