
#include "mruby-ping.h"

#include <pcap.h>
#include <libnet.h>
#include <math.h>


#define ERR(MSG) { mrb_raise(mrb, E_RUNTIME_ERROR, MSG); return self; }
#define ERRF(MSG, FORMAT, ARGS...) { mrb_raisef(mrb, E_RUNTIME_ERROR, FORMAT, ## ARGS); return self; }


static pcap_t *pcap;


// internal state
struct arp_state {
  libnet_t *ctx;
  
  struct target_address *targets;
  uint16_t targets_count;
};

static void arp_state_free(mrb_state *mrb, void *ptr)
{
  mrb_free(mrb, ptr);
}

static struct mrb_data_type arp_ping_state_type = { "ARPPinger", arp_state_free };






// internals

static uint8_t broadcast_mac_addr[8] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

#define ERRLN(FORMAT, ARGS...) { printf(FORMAT, ## ARGS); libnet_clear_packet(pnet); return -1; }

static int arp_send(
  libnet_t    *pnet,
  int          opcode,
  uint8_t     *source_hardware,
  in_addr_t    source_address,
  uint8_t     *target_hardware,
  in_addr_t    target_address)
{
  int retval = -1;
  
  if( source_hardware == NULL ){
    source_hardware = (uint8_t *) libnet_get_hwaddr(pnet);
    if( source_hardware == NULL )
      ERRLN("error obtaining source hardware address : %s\n", libnet_geterror( pnet ));
  }
  
  if( source_address == 0 ){
    source_address = libnet_get_ipaddr4(pnet);
    if( source_address == 0 )
      ERRLN("error obtaining source address : %s\n", libnet_geterror( pnet ));
  }
  
  if( target_hardware == NULL ){
    target_hardware = broadcast_mac_addr;
  }
  
  if( libnet_autobuild_arp( opcode, source_hardware, (uint8_t *)&source_address, target_hardware, (uint8_t *)&target_address, pnet ) == -1 )
    ERRLN("error building arp packet : %s\n", libnet_geterror(pnet));
  
  if( libnet_build_ethernet( target_hardware, source_hardware, ETHERTYPE_ARP, NULL, 0, pnet, 0 ) == -1 )
    ERRLN("error building ethernet packet : %s\n", libnet_geterror( pnet ));
  

  retval = libnet_write( pnet );
  if( retval == -1 )
    ERRLN( "error sending packet : %s\n", libnet_geterror( pnet ) );
  
  libnet_clear_packet( pnet );

  return retval;
}


#define PROMISC 1

struct pcap_loop_args {
  mrb_value *ret;
  mrb_state *mrb;
  libnet_t  *ctx;
};

//
// return 1 if the two mac targets are identical
//
static int same_ether(const uint8_t *mac1, const uint8_t *mac2)
{
  return  (mac1[0] == mac2[0]) && 
          (mac1[1] == mac2[1]) &&
          (mac1[2] == mac2[2]) &&
          (mac1[3] == mac2[3]) &&
          (mac1[4] == mac2[4]) &&
          (mac1[5] == mac2[5]);
}

static void pcap_packet_handler(uint8_t *args_ptr, const struct pcap_pkthdr *h, const uint8_t *bytes)
{
  uint32_t                     ip;
  uint8_t                     *ether_src;
  struct libnet_ethernet_hdr  *heth;
  struct libnet_arp_hdr       *harp;
  struct pcap_loop_args       *args = (struct pcap_loop_args *)args_ptr;
  struct libnet_ether_addr    *myaddr;
  char                        *host;
  mrb_value                   key;
  
  heth = (void*) bytes;
  harp = (void*)((char*)heth + LIBNET_ETH_H);
  
  ether_src = (uint8_t*)harp + LIBNET_ARP_H;
  
  myaddr = libnet_get_hwaddr(args->ctx);
  
  // check packet type and source (ignore packet from us)
  if( (ntohs(heth->ether_type) == ETHERTYPE_ARP) && (ntohs(harp->ar_op) == ARPOP_REPLY) ){
    // printf("arp from %02x:%02x:%02x:%02x:%02x:%02x\n",
    //     ether_src[0], ether_src[1], ether_src[2], ether_src[3], ether_src[4], ether_src[5]
    //   );
    
    if( !same_ether(ether_src, myaddr->ether_addr_octet) ){
      // printf("ip: %s, target: %s ? %d\n", inet_ntoa( *((struct in_addr *) &ip) ), target_address, strcmp( inet_ntoa( *((struct in_addr *) &ip) ), target_address) );
      // memcpy(&ip, (char*)harp + LIBNET_ARP_H + (harp->ar_hln * 2) + harp->ar_pln, 4);
      memcpy(&ip, (char*)harp + LIBNET_ARP_H + harp->ar_hln, 4);
      host = inet_ntoa( *((struct in_addr *) &ip));
      
      key = mrb_str_new_cstr(args->mrb, host);
      mrb_hash_set(args->mrb, *args->ret, key, mrb_true_value());
    }
    
  }
  
}

#define PCAP_FILTER "arp"

static mrb_value receive_replies(mrb_state *mrb, mrb_value self, const struct arp_state *st, mrb_int timeout)
{
  char errbuff[PCAP_ERRBUF_SIZE];
  const char *ifname;
  mrb_value ret_value;
  struct pcap_loop_args loop_args;
  struct bpf_program arp_p;
  struct timeval sent_at, received_at;
  double elapsed;
  
  gettimeofday(&sent_at, NULL);
  
  ifname = libnet_getdevice(st->ctx);
  
  pcap = pcap_open_live(ifname, 100, PROMISC, timeout, errbuff);
  if( pcap == NULL )
    ERRF("pcap_open_live failed: %s\n", errbuff);
  
  // if( strlen(errbuff) > 0 ) WARN("warning: %s\n", errbuff);
  
  /* compile pcap filter */
  if( pcap_compile(pcap, &arp_p, PCAP_FILTER, 0, 0) == -1 )
    ERRF("pcap_compile(): %s\n", pcap_geterr(pcap));
  
  if( pcap_setfilter(pcap, &arp_p) == -1 )
    ERRF("pcap_setfilter(): %s\n", pcap_geterr(pcap));
  
  // if( get_hw_addr(ifname, hwaddr) != 0 )
  //   ERR("Unable to get MAC address for %s\n", ifname);
  
  loop_args.ctx = st->ctx;
  loop_args.mrb = mrb;
  loop_args.ret = &ret_value;
  
  ret_value = mrb_hash_new_capa(mrb, st->targets_count);
  
  while(1){
    if( pcap_dispatch(pcap, 200, pcap_packet_handler, (uint8_t *)&loop_args) == -1 ){
      ERRF("pcap_loop(): %s\n", pcap_geterr(pcap));
    }
    
    gettimeofday(&received_at, NULL);
    elapsed = ((received_at.tv_sec - sent_at.tv_sec) * 1000 + floor((received_at.tv_usec - sent_at.tv_usec) / 1000));
    if( elapsed >= timeout )
      break;
    
  }
  
  pcap_close(pcap);
  
  return ret_value;
}




// public api

static mrb_value ping_initialize(mrb_state *mrb, mrb_value self)
{
  struct arp_state *st = mrb_malloc(mrb, sizeof(struct arp_state));
  char error_buffer[LIBNET_ERRBUF_SIZE];
  mrb_value ifname_r;
  const char *ifname;
  
  mrb_get_args(mrb, "S", &ifname_r);
  
  ifname = mrb_string_value_cstr(mrb, &ifname_r);
  
  st->ctx = libnet_init(LIBNET_LINK, ifname, error_buffer);
  if( st->ctx == NULL )
    ERRF("Failed to initialize libnet: %s", error_buffer);
  
  st->targets = NULL;
  
  DATA_PTR(self)  = (void*)st;
  DATA_TYPE(self) = &arp_ping_state_type;

  
  return self;
}

static mrb_value ping_set_targets(mrb_state *mrb, mrb_value self)
{
  mrb_value arr;
  struct arp_state *st = DATA_PTR(self);
  
  mrb_get_args(mrb, "A", &arr);
  
  if( st->targets != NULL ){
    mrb_free(mrb, st->targets);
  }
  
  st->targets_count = RARRAY_LEN(arr);
  st->targets = mrb_malloc(mrb, sizeof(struct target_address) * st->targets_count );
  
  ping_set_targets_common(mrb, arr, &st->targets_count, st->targets);
  
  return self;
}


static mrb_value ping_send_pings(mrb_state *mrb, mrb_value self)
{
  int i;
  mrb_int timeout;
  struct arp_state *st = DATA_PTR(self);
  
  mrb_get_args(mrb, "i", &timeout);
  
  // send all arp requests
  for(i = 0; i< st->targets_count; i++){
    arp_send(st->ctx, ARPOP_REQUEST, NULL, 0, NULL, st->targets[i].in_addr);
  }
  
  // and collect the replies
  
  return receive_replies(mrb, self, st, timeout);
}


void mruby_ping_init_arp(mrb_state *mrb)
{
  struct RClass *class = mrb_define_class(mrb, "ARPPinger", NULL);
  
  int ai = mrb_gc_arena_save(mrb);
  
  mrb_define_method(mrb, class, "initialize", ping_initialize,  ARGS_REQ(1));
  mrb_define_method(mrb, class, "set_targets", ping_set_targets,  ARGS_REQ(1));
  mrb_define_method(mrb, class, "send_pings", ping_send_pings,  ARGS_REQ(1));
    
  mrb_gc_arena_restore(mrb, ai);
}


