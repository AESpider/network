/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define MAGIC 0xAB

/* Structure for the covert channel using the IP ID field */
struct covert_message
{
  __u32 src_ip; /* network order */
  __u32 data;   /* hidden data stored in the IP ID field */
};

/* Ring buffer to transmit messages to userspace */
struct
{
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 256 * 1024); /* Size in bytes */
} covert_messages SEC(".maps");

SEC("xdp")
int xdp_prog(struct xdp_md *ctx)
{
  void *data_end = (void *)(long)ctx->data_end;
  void *data = (void *)(long)ctx->data;
  struct ethhdr *eth = data;
  struct iphdr *ip;
  __u16 ip_id;
  __u8 marker;

  /* Bounds checking */
  if (eth + 1 > data_end)
    return XDP_PASS;

  /* Check if IPv4 */
  if (eth->h_proto != bpf_htons(ETH_P_IP))
    return XDP_PASS;

  /* Parse IP header */
  ip = data + sizeof(struct ethhdr);
  if (ip + 1 > data_end)
    return XDP_PASS;

  /* Check ICMP protocol */
  if (ip->protocol != IPPROTO_ICMP)
    return XDP_PASS;

  /* Extract IP ID field */
  ip_id = bpf_ntohs(ip->id);
  marker = (ip_id >> 8) & 0xFF;

  /* Check marker */
  if (marker == MAGIC)
  {
    struct covert_message *msg;

    /* Reserve space in ring buffer */
    msg = bpf_ringbuf_reserve(&covert_messages, sizeof(*msg), 0);
    if (!msg)
      return XDP_PASS;

    /* Store IP in network order */
    msg->src_ip = ip->saddr;
    msg->data = ip_id & 0xFF;

    bpf_printk("IP ID: 0x%x, marker: 0x%x, Data: 0x%x",
               ip_id, marker, ip_id & 0xFF);

    /* Submit message to userspace */
    bpf_ringbuf_submit(msg, 0);
  }

  return XDP_PASS;
}

char _license[] SEC("license") = "GPL";