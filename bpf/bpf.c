#include <vmlinux.h>

#include <libbpf/src/bpf_core_read.h>
#include <libbpf/src/bpf_helpers.h>
#include <libbpf/src/bpf_tracing.h>

enum nf_counter_type {
  NF_COUNTER_KEY_IP_FRAGMENTS_SEEN_TOTAL,
  NF_COUNTER_KEY_IP_FRAGMENTS_TOO_EARLY,
  __NF_COUNTER_KEY_LEN,
};

// Ensure counter type enum is added to BTF.
volatile const enum nf_counter_type _ = 0;

struct nf_counter_key {
  uint32_t type;
  uint8_t  ip_version;
  int      ifindex;
};

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
  __type(key, struct nf_counter_key);
  __type(value, uint64_t);
  __uint(max_entries, 16);
} nf_counters SEC(".maps");

/*
 * Increment the counter for the given key by 1.
 */
static __always_inline void
increment_counter(struct nf_counter_key *key) {
  uint64_t *value;
  uint64_t  increment = 1;

  value = bpf_map_lookup_elem(&nf_counters, key);
  if (value) {
    *value += increment;
  } else {
    bpf_map_update_elem(&nf_counters, key, &increment, BPF_ANY);
  }
}

/*
 * Construct base counter key with information that does not change. The
 * counter type must be set before using the key.
 */
static __always_inline void
set_nf_counter_key_labels(struct nf_counter_key *key, struct sk_buff *skb) {
  unsigned char *skb_head;
  __u16          skb_l3_off;
  struct iphdr  *iph;

  skb_head   = BPF_CORE_READ(skb, head);
  skb_l3_off = BPF_CORE_READ(skb, network_header);
  iph        = (struct iphdr *)(skb_head + skb_l3_off);

  key->ip_version = BPF_CORE_READ_BITFIELD_PROBED(iph, version);
  key->ifindex    = BPF_CORE_READ(skb, skb_iif);
}

/*
 * Count IP packet fragments per IP version and interface index.
 */
SEC("fentry/inet_frag_queue_insert")
int
BPF_PROG(fentry_inet_frag_queue_insert,
         struct inet_frag_queue *q,
         struct sk_buff         *skb,
         int                     offset) {
  struct nf_counter_key counter_key;

  set_nf_counter_key_labels(&counter_key, skb);

  counter_key.type = NF_COUNTER_KEY_IP_FRAGMENTS_SEEN_TOTAL;
  increment_counter(&counter_key);

  if (offset == 0)
    goto out;

  if (!(q->flags & INET_FRAG_FIRST_IN)) {
    counter_key.type = NF_COUNTER_KEY_IP_FRAGMENTS_TOO_EARLY;
    increment_counter(&counter_key);
  }

out:
  return 0;
}

char __license[] SEC("license") = "GPL";
