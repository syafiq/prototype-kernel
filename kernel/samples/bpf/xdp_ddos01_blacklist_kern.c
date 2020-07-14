/*  XDP example: DDoS protection via IPv4 blacklist
 *
 *  Copyright(c) 2017 Jesper Dangaard Brouer, Red Hat, Inc.
 *  Copyright(c) 2017 Andy Gospodarek, Broadcom Limited, Inc.
 */
#define KBUILD_MODNAME "foo"
#include <uapi/linux/bpf.h>
#include <uapi/linux/if_ether.h>
#include <uapi/linux/if_packet.h>
#include <uapi/linux/if_vlan.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/in.h>
#include <uapi/linux/tcp.h>
#include <uapi/linux/udp.h>
#include "bpf_helpers.h"

enum {
	DDOS_FILTER_TCP = 0,
	DDOS_FILTER_UDP,
	DDOS_FILTER_MAX,
};

struct vlan_hdr {
	__be16 h_vlan_TCI;
	__be16 h_vlan_encapsulated_proto;
};

typedef struct {
	u32 saddr;
	u32 daddr;
} id_addr;

struct bpf_map_def SEC("maps") blacklist = {
	.type        = BPF_MAP_TYPE_PERCPU_HASH,
	.key_size    = sizeof(u32),
	.value_size  = sizeof(u64), /* Drop counter */
	.max_entries = 100000,
	.map_flags   = BPF_F_NO_PREALLOC,
};

#define XDP_ACTION_MAX (XDP_TX + 1)

/* Counter per XDP "action" verdict */
struct bpf_map_def SEC("maps") verdict_cnt = {
	.type = BPF_MAP_TYPE_PERCPU_ARRAY,
	.key_size = sizeof(u32),
	.value_size = sizeof(long),
	.max_entries = XDP_ACTION_MAX,
};

struct bpf_map_def SEC("maps") port_blacklist = {
	.type        = BPF_MAP_TYPE_PERCPU_ARRAY,
	.key_size    = sizeof(u32),
	.value_size  = sizeof(u32),
	.max_entries = 65536,
};

/* Counter per XDP "action" verdict */

/* TCP Drop counter */
struct bpf_map_def SEC("maps") port_blacklist_drop_count_tcp = {
	.type        = BPF_MAP_TYPE_PERCPU_ARRAY,
	.key_size    = sizeof(u32),
	.value_size  = sizeof(u64),
	.max_entries = 65536,
};

/* UDP Drop counter */
struct bpf_map_def SEC("maps") port_blacklist_drop_count_udp = {
	.type        = BPF_MAP_TYPE_PERCPU_ARRAY,
	.key_size    = sizeof(u32),
	.value_size  = sizeof(u64),
	.max_entries = 65536,
};

/* ts1 */
struct bpf_map_def SEC("maps") ts1 = {
	.type        = BPF_MAP_TYPE_PERCPU_HASH,
	.key_size    = sizeof(u64),
	.value_size  = sizeof(u64), /* time */
	.max_entries = 100000,
	.map_flags   = BPF_F_NO_PREALLOC,
};

/* ts2 */
struct bpf_map_def SEC("maps") ts2 = {
	.type        = BPF_MAP_TYPE_PERCPU_HASH,
	.key_size    = sizeof(u64),
	.value_size  = sizeof(u64), /* time */
	.max_entries = 100000,
	.map_flags   = BPF_F_NO_PREALLOC,
};

/* c */
struct bpf_map_def SEC("maps") counter_c = {
	.type        = BPF_MAP_TYPE_PERCPU_HASH,
	.key_size    = sizeof(u64),
	.value_size  = sizeof(u64), /* int */
	.max_entries = 100000,
	.map_flags   = BPF_F_NO_PREALLOC,
};

/* dc */
struct bpf_map_def SEC("maps") diffcount_dc = {
	.type        = BPF_MAP_TYPE_PERCPU_HASH,
	.key_size    = sizeof(u64),
	.value_size  = sizeof(u64), /* int */
	.max_entries = 100000,
	.map_flags   = BPF_F_NO_PREALLOC,
};

/* mark */
struct bpf_map_def SEC("maps") mark = {
	.type        = BPF_MAP_TYPE_PERCPU_HASH,
	.key_size    = sizeof(u64),
	.value_size  = sizeof(u64), /* int */
	.max_entries = 100000,
	.map_flags   = BPF_F_NO_PREALLOC,
};

static inline struct bpf_map_def *drop_count_by_fproto(int fproto) {

	switch (fproto) {
	case DDOS_FILTER_UDP:
		return &port_blacklist_drop_count_udp;
		break;
	case DDOS_FILTER_TCP:
		return &port_blacklist_drop_count_tcp;
		break;
	}
	return NULL;
}

// TODO: Add map for controlling behavior

//#define DEBUG 1
#ifdef  DEBUG
/* Only use this for debug output. Notice output from bpf_trace_printk()
 * end-up in /sys/kernel/debug/tracing/trace_pipe
 */
#define bpf_debug(fmt, ...)						\
		({							\
			char ____fmt[] = fmt;				\
			bpf_trace_printk(____fmt, sizeof(____fmt),	\
				     ##__VA_ARGS__);			\
		})
#else
#define bpf_debug(fmt, ...) { } while (0)
#endif

/* Keeps stats of XDP_DROP vs XDP_PASS */
static __always_inline
void stats_action_verdict(u32 action)
{
	u64 *value;

	if (action >= XDP_ACTION_MAX)
		return;

	value = bpf_map_lookup_elem(&verdict_cnt, &action);
	if (value)
		*value += 1;
}

/* Parse Ethernet layer 2, extract network layer 3 offset and protocol
 *
 * Returns false on error and non-supported ether-type
 */
static __always_inline
bool parse_eth(struct ethhdr *eth, void *data_end,
	       u16 *eth_proto, u64 *l3_offset)
{
	u16 eth_type;
	u64 offset;

	offset = sizeof(*eth);
	if ((void *)eth + offset > data_end)
		return false;

	eth_type = eth->h_proto;
	bpf_debug("Debug: eth_type:0x%x\n", ntohs(eth_type));

	/* Skip non 802.3 Ethertypes */
	if (unlikely(ntohs(eth_type) < ETH_P_802_3_MIN))
		return false;

	/* Handle VLAN tagged packet */
	if (eth_type == htons(ETH_P_8021Q) || eth_type == htons(ETH_P_8021AD)) {
		struct vlan_hdr *vlan_hdr;

		vlan_hdr = (void *)eth + offset;
		offset += sizeof(*vlan_hdr);
		if ((void *)eth + offset > data_end)
			return false;
		eth_type = vlan_hdr->h_vlan_encapsulated_proto;
	}
	/* Handle double VLAN tagged packet */
	if (eth_type == htons(ETH_P_8021Q) || eth_type == htons(ETH_P_8021AD)) {
		struct vlan_hdr *vlan_hdr;

		vlan_hdr = (void *)eth + offset;
		offset += sizeof(*vlan_hdr);
		if ((void *)eth + offset > data_end)
			return false;
		eth_type = vlan_hdr->h_vlan_encapsulated_proto;
	}

	*eth_proto = ntohs(eth_type);
	*l3_offset = offset;
	return true;
}

u32 parse_port(struct xdp_md *ctx, u8 proto, void *hdr)
{
	void *data_end = (void *)(long)ctx->data_end;
	struct udphdr *udph;
	struct tcphdr *tcph;
	u32 *value;
	u32 *drops;
	u32 dport;
	u32 dport_idx;
	u32 fproto;

	switch (proto) {
	case IPPROTO_UDP:
		udph = hdr;
		if (udph + 1 > data_end) {
			bpf_debug("Invalid UDPv4 packet: L4off:%llu\n",
				  sizeof(struct iphdr) + sizeof(struct udphdr));
			return XDP_ABORTED;
		}
		dport = ntohs(udph->dest);
		fproto = DDOS_FILTER_UDP;
		break;
	case IPPROTO_TCP:
		tcph = hdr;
		if (tcph + 1 > data_end) {
			bpf_debug("Invalid TCPv4 packet: L4off:%llu\n",
				  sizeof(struct iphdr) + sizeof(struct tcphdr));
			return XDP_ABORTED;
		}
		dport = ntohs(tcph->dest);
		fproto = DDOS_FILTER_TCP;
		break;
	default:
		return XDP_PASS;
	}

	dport_idx = dport;
	value = bpf_map_lookup_elem(&port_blacklist, &dport_idx);

	if (value) {
		if (*value & (1 << fproto)) {
			struct bpf_map_def *drop_counter = drop_count_by_fproto(fproto);
			if (drop_counter) {
				drops = bpf_map_lookup_elem(drop_counter , &dport_idx);
				if (drops)
					*drops += 1; /* Keep a counter for drop matches */
			}
			return XDP_DROP;
		}
	}
	return XDP_PASS;
}


SEC("parsing ip4")
static __always_inline
u32 parse_ipv4(struct xdp_md *ctx, u64 l3_offset)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data     = (void *)(long)ctx->data;
	struct iphdr *iph = data + l3_offset;
	u64 *value;
	/* ts1 */
	u64 *ts1_get;
	u64 *ts2_get;
	u64 *c_get;
	u64 *dc_get;
	u64 ts1_val;
	u64 ts2_val; 
	u64 c_val;
	u64 dc_val; 
	u64 mark_val;
	u64 one = 1;
	u64 zero = 0;
	u64 t_now;
	u64 calc_temp = 0;
	u64 TT1 = 10;
	u64 TT2 = 100;
	u64 TF1 = 300;
	id_addr ida;

	u32 ip_src; /* type need to match map */

	/* Hint: +1 is sizeof(struct iphdr) */
	if (iph + 1 > data_end) {
		bpf_debug("Invalid IPv4 packet: L3off:%llu\n", l3_offset);
		return XDP_ABORTED;
	}
	/* Extract key */
	ip_src = iph->saddr;
	ida.saddr = iph->saddr;
	ida.daddr = iph->daddr;
	//ip_src = ntohl(ip_src); // ntohl does not work for some reason!?!

	ts1_get = bpf_map_lookup_elem(&ts1, &ida);
	ts2_get = bpf_map_lookup_elem(&ts2, &ida);
	c_get = bpf_map_lookup_elem(&counter_c, &ida);
	t_now = bpf_ktime_get_ns();

	if (ts1_get && ts2_get && c_get) { //record found
		if ((&t_now-ts2_get) > TT1) { // TT1
			ts1_val = bpf_map_update_elem(&ts1, &ida, &t_now, BPF_EXIST);
			c_val = bpf_map_update_elem(&counter_c, &ida, &zero, BPF_EXIST);
			dc_val = bpf_map_update_elem(&diffcount_dc, &ida, &zero, BPF_EXIST);
			mark_val = bpf_map_update_elem(&mark, &ida, &one, BPF_EXIST);
		}
	} else { //record not found
		ts1_val = bpf_map_update_elem(&ts1, &ida, &t_now, BPF_ANY);
		ts2_val = bpf_map_update_elem(&ts2, &ida, &t_now, BPF_ANY);
		c_val = bpf_map_update_elem(&counter_c, &ida, &zero, BPF_ANY);
		dc_val = bpf_map_update_elem(&diffcount_dc, &ida, &zero, BPF_ANY);
		mark_val = bpf_map_update_elem(&mark, &ida, &zero, BPF_ANY);
	}

	c_get = bpf_map_lookup_elem(&counter_c, &ida);
	dc_get = bpf_map_lookup_elem(&diffcount_dc, &ida);
	__sync_fetch_and_add(&c_get, &one);
	__sync_fetch_and_add(&dc_get, &one);
	ts2_val = bpf_map_update_elem(&ts2, &ida, &t_now, BPF_EXIST);

	if ((&ts2_get-&ts1_get) > TT2) { // TT2
		calc_temp = (u64) &c_get/(&ts2_get-&ts1_get);
		calc_temp &= 0xF; // FIXME : not sure of it solves the issue
		if (calc_temp > TF1) { // TF1
			return XDP_DROP;
			// Send overload warning
		}
	}

	bpf_debug("Valid IPv4 packet: raw saddr:0x%x\n", ip_src);

	value = bpf_map_lookup_elem(&blacklist, &ip_src);

	if (value) {
		/* Don't need __sync_fetch_and_add(); as percpu map */
		*value += 1; /* Keep a counter for drop matches */
		return XDP_DROP;
	}

	return parse_port(ctx, iph->protocol, iph + 1);
}

static __always_inline
u32 handle_eth_protocol(struct xdp_md *ctx, u16 eth_proto, u64 l3_offset)
{
	switch (eth_proto) {
	case ETH_P_IP:
		return parse_ipv4(ctx, l3_offset);
		break;
	case ETH_P_IPV6: /* Not handler for IPv6 yet*/
	case ETH_P_ARP:  /* Let OS handle ARP */
		/* Fall-through */
	default:
		bpf_debug("Not handling eth_proto:0x%x\n", eth_proto);
		return XDP_PASS;
	}
	return XDP_PASS;
}

SEC("xdp_prog")
int  xdp_program(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data     = (void *)(long)ctx->data;
	struct ethhdr *eth = data;
	u16 eth_proto = 0;
	u64 l3_offset = 0;
	u32 action;

	if (!(parse_eth(eth, data_end, &eth_proto, &l3_offset))) {
		bpf_debug("Cannot parse L2: L3off:%llu proto:0x%x\n",
			  l3_offset, eth_proto);
		return XDP_PASS; /* Skip */
	}
	bpf_debug("Reached L3: L3off:%llu proto:0x%x\n", l3_offset, eth_proto);

	action = handle_eth_protocol(ctx, eth_proto, l3_offset);
	stats_action_verdict(action);
	return action;
}

char _license[] SEC("license") = "GPL";
