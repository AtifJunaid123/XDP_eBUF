#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <linux/types.h>
#include <bpf/bpf_helpers.h>
#include <linux/bpf.h>
#include <sys/socket.h>

SEC("xdp_drop")

int xdp_drop_prog(struct xdp_md *ctx) {
  // return XDP_DROP;

  void *data_end = (void *)(long)ctx->data_end;
  void *data = (void *)(long)ctx->data;

  struct ethhdr *eth = data;
  __u16 h_proto;

  if (data + sizeof(struct ethhdr) > data_end) {
    return XDP_DROP;
  }
  h_proto = eth->h_proto;

  if (h_proto == htons(ETH_P_IPV6))
    return XDP_DROP;

  return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
