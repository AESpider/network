/* SPDX-License-Identifier: GPL-2.0 */
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>

static volatile int exiting = 0;

struct covert_message
{
  __u32 src_ip;
  __u32 data;
};

static void sig_handler(int sig)
{
  exiting = 1;
}

/* Ring buffer callback */
static int handle_event(void *ctx, void *data, size_t sz)
{
  const struct covert_message *msg = data;
  struct in_addr src;
  char src_str[INET_ADDRSTRLEN];

  src.s_addr = msg->src_ip;

  inet_ntop(AF_INET, &src, src_str, sizeof(src_str));

  printf("[Detected] %s | Data: 0x%02x", src_str, msg->data);

  /* Print ASCII if printable */
  if (msg->data >= 32 && msg->data < 127)
    printf(" ('%c')", msg->data);

  printf("\n");
  return 0;
}

int main(int argc, char **argv)
{
  struct bpf_object *obj;
  struct bpf_program *prog;
  struct bpf_link *link = NULL;
  struct ring_buffer *rb = NULL;
  int ifindex, map_fd;

  if (argc != 2)
  {
    fprintf(stderr, "Usage: %s <interface>\n", argv[0]);
    return EXIT_FAILURE;
  }

  /* Bump RLIMIT_MEMLOCK to create BPF maps */
  struct rlimit rlim_new = {
      .rlim_cur = RLIM_INFINITY,
      .rlim_max = RLIM_INFINITY,
  };

  if (setrlimit(RLIMIT_MEMLOCK, &rlim_new))
  {
    fprintf(stderr, "Failed to increase RLIMIT_MEMLOCK\n");
    return EXIT_FAILURE;
  }

  /* Get interface index */
  ifindex = if_nametoindex(argv[1]);
  if (!ifindex)
  {
    fprintf(stderr, "Interface '%s' not found\n", argv[1]);
    return EXIT_FAILURE;
  }

  /* Open and load BPF object */
  obj = bpf_object__open_file("covert_channel_kern.o", NULL);
  if (libbpf_get_error(obj))
  {
    fprintf(stderr, "Failed to open BPF object\n");
    return EXIT_FAILURE;
  }

  if (bpf_object__load(obj))
  {
    fprintf(stderr, "Failed to load BPF object\n");
    goto cleanup;
  }

  /* Find and attach XDP program */
  prog = bpf_object__find_program_by_name(obj, "xdp_prog");
  if (!prog)
  {
    fprintf(stderr, "Failed to find xdp_prog\n");
    goto cleanup;
  }

  link = bpf_program__attach_xdp(prog, ifindex);
  if (libbpf_get_error(link))
  {
    fprintf(stderr, "Failed to attach XDP program\n");
    link = NULL;
    goto cleanup;
  }

  /* Setup ring buffer */
  map_fd = bpf_object__find_map_fd_by_name(obj, "covert_messages");
  if (map_fd < 0)
  {
    fprintf(stderr, "Failed to find ring buffer map\n");
    goto cleanup;
  }

  rb = ring_buffer__new(map_fd, handle_event, NULL, NULL);
  if (!rb)
  {
    fprintf(stderr, "Failed to create ring buffer\n");
    goto cleanup;
  }

  printf("XDP loaded on %s\n", argv[1]);
  printf("Listening for covert messages (marker: 0xAB)...\n");
  printf("Press Ctrl+C to exit\n\n");

  /* Setup signal handlers */
  signal(SIGINT, sig_handler);
  signal(SIGTERM, sig_handler);

  /* Poll ring buffer */
  while (!exiting)
  {
    int err = ring_buffer__poll(rb, 100);
    if (err == -EINTR)
    {
      break;
    }
    if (err < 0)
    {
      fprintf(stderr, "Error polling ring buffer: %d\n", err);
      break;
    }
  }

  printf("\nDetaching...\n");

cleanup:
  ring_buffer__free(rb);
  bpf_link__destroy(link);
  bpf_object__close(obj);
  return EXIT_SUCCESS;
}