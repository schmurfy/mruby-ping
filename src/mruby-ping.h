
#include "mruby.h"
#include "mruby/data.h"
#include "mruby/array.h"
#include "mruby/string.h"
#include "mruby/hash.h"

// #include <stdio.h>
// #include <stdlib.h>
// #include <unistd.h>
#include <string.h>
#include <netdb.h>
#include <errno.h>

#include <sys/socket.h>
#include <arpa/inet.h>
#include <net/if.h>

struct target_address {
  in_addr_t in_addr;
  in_addr_t in_addr_src;
  uint32_t  rtable;
  uint16_t  uid;

//#ifdef SO_BINDTODEVICE
  char      device[IFNAMSIZ];
//#endif
};

// shared
void ping_set_targets_common(mrb_state *mrb, mrb_value arr, const uint16_t *targets_count, struct target_address *targets);

// init
void mruby_ping_init_icmp(mrb_state *);
void mruby_ping_init_arp(mrb_state *);
