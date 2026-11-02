#include <uapi/linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>

// BPF Map to store blacklisted IPs and their drop counters
BPF_HASH(drop_ips, u32, u64);

int xdp_router_firewall(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    // Bounds checking
    if ((void *)(eth + 1) > data_end) 
        return XDP_PASS;

    // Only inspect IPv4 packets
    if (eth->h_proto != bpf_htons(ETH_P_IP)) 
        return XDP_PASS;

    struct iphdr *ip = data + sizeof(*eth);
    if ((void *)(ip + 1) > data_end) 
        return XDP_PASS;

    u32 src_ip = ip->saddr;
    
    // Check if the source IP is in our blacklist map
    u64 *drop_counter = drop_ips.lookup(&src_ip);
    if (drop_counter) {
        // Atomic increment of the drop counter
        lock_xadd(drop_counter, 1);
        return XDP_DROP;
    }

    return XDP_PASS;
}
