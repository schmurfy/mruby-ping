#include "mruby-ping.h"



struct state {
  int icmp_sock;
  int raw_sock;
  in_addr_t *addresses;
  uint16_t addresses_count;
};


static uint16_t in_cksum(uint16_t *addr, int len)
{
  int nleft = len;
  int sum = 0;
  uint16_t *w = addr;
  uint16_t answer = 0;

  while (nleft > 1) {
    sum += *w++;
    nleft -= 2;
  }

  if (nleft == 1) {
    *(uint8_t *) (&answer) = *(uint8_t *) w;
    sum += answer;
  }
  
  sum = (sum >> 16) + (sum & 0xFFFF);
  sum += (sum >> 16);
  answer = ~sum;
  return (answer);
}




static void ping_state_free(mrb_state *mrb, void *ptr)
{
  struct state *st = (struct state *)ptr;
  mrb_free(mrb, st);
}

static struct mrb_data_type ping_state_type = { "Pinger", ping_state_free };


static mrb_value ping_initialize(mrb_state *mrb, mrb_value self)
{
  struct state *st = mrb_malloc(mrb, sizeof(struct state));
  
  if ((st->raw_sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0) {
    mrb_raise(mrb, E_RUNTIME_ERROR, "cannot create raw socket, are you root ?");
    return mrb_nil_value();
  }
  
  if ((st->icmp_sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) < 0) {
    mrb_raise(mrb, E_RUNTIME_ERROR, "cannot create icmp socket, are you root ?");
    return mrb_nil_value();
  }
  
  st->addresses = NULL;
  
  DATA_PTR(self)  = (void*)st;
  DATA_TYPE(self) = &ping_state_type;
  
  return self;
}


static mrb_value ping_set_targets(mrb_state *mrb, mrb_value self)
{
  int i;
  mrb_value arr, obj;
  struct state *st = DATA_PTR(self);
  
  mrb_get_args(mrb, "A", &arr);
  
  if( st->addresses != NULL ){
    mrb_free(mrb, st->addresses);
  }
  
  st->addresses_count = RARRAY_LEN(arr);
  st->addresses = mrb_malloc(mrb, sizeof(in_addr_t) * st->addresses_count );
  
  for(i = 0; i< st->addresses_count; i++){
    obj = mrb_ary_ref(mrb, arr, i);
    if( !mrb_string_p(obj) )
      mrb_raisef(mrb, E_TYPE_ERROR, "can't convert %s into String", mrb_obj_classname(mrb, obj));
    
    st->addresses[i] = inet_addr( mrb_str_to_cstr(mrb, obj) );
  }
  
  return self;
}


static void fill_timeout(struct timeval *tv, uint64_t duration)
{
  tv->tv_sec = 0;
  while( duration >= 1000000 ){
    duration -= 1000000;
    tv->tv_sec += 1;
  }
  
  tv->tv_usec = duration;
}

static mrb_value ping_send_pings(mrb_state *mrb, mrb_value self)
{
  struct state *st = DATA_PTR(self);
  mrb_int timeout;
  int i, pos = 0;
  int sending_socket = st->icmp_sock;
  struct timeval sent_at, received_at;
  
  
  // struct ip ip;
  struct icmp icmp;
  // int sd, pos = 0;
  // const int on = 1;
  struct sockaddr_in dst_addr;
  uint8_t packet[sizeof(struct ip) + sizeof(struct icmp)];
  size_t packet_size;
    
  mrb_get_args(mrb, "i", &timeout);
  
  if( timeout <= 0 )
    mrb_raisef(mrb, E_TYPE_ERROR, "timeout should be positive and non null: %d", timeout);
  
  packet_size = sizeof(icmp);
  // packet = (uint8_t *)mrb_malloc(mrb, packet_size);
  
  gettimeofday(&sent_at, NULL);
  
  // send each icmp echo request
  for(i = 0; i< st->addresses_count; i++){
    // prepare destination address
    bzero(&dst_addr, sizeof(dst_addr));
    dst_addr.sin_family = AF_INET;
    dst_addr.sin_addr.s_addr = st->addresses[i];
    
    
    icmp.icmp_type = ICMP_ECHO;
    icmp.icmp_code = 0;
    icmp.icmp_id = 1000;
    icmp.icmp_seq = 0;
    icmp.icmp_cksum = 0;
    icmp.icmp_cksum = in_cksum((uint16_t *)&icmp, sizeof(icmp));
    memcpy(packet + pos, &icmp, sizeof(icmp));
    
    if (sendto(sending_socket, packet, packet_size, 0, (struct sockaddr *)&dst_addr, sizeof(struct sockaddr)) < 0)  {
      mrb_raise(mrb, E_RUNTIME_ERROR, "unable to send ICMP packet");
    }

  }
  
  // and collect answers
  int c, ret;
  fd_set rfds;
  struct timeval tv;
  char *host;
  int wait_time = 0; // how much did we already wait
  mrb_value key, ret_value;
  
  timeout *= 1000; // ms => usec
  
  ret_value = mrb_hash_new_capa(mrb, st->addresses_count);
  
  // we will receive both the ip header and the icmp data
  packet_size = sizeof(struct ip) + sizeof(struct icmp);
  
  while (1) {
    struct sockaddr_in from;
    socklen_t fromlen = sizeof(from);
    struct icmp *pkt;
    
    FD_ZERO(&rfds);
    FD_SET(st->icmp_sock, &rfds);
    
    fill_timeout(&tv, timeout - wait_time);

    ret = select(st->icmp_sock + 1, &rfds, NULL, NULL, &tv);
    if( ret == -1 ){
      printf("err: %d\n", errno);
      perror("select");
    }
    
    if( ret == 1 ){
      c = recvfrom(st->icmp_sock, packet, packet_size, 0, (struct sockaddr *) &from, &fromlen);
      if( c < 0 ) {
        if (errno == EINTR)
          continue;
        mrb_raise(mrb, E_RUNTIME_ERROR, "ping: recvfrom");
        continue;
      }
      
      printf("recv(%d, %ld, %ld)\n", c, sizeof(struct ip) + sizeof(struct icmp), packet_size);
          
      if (c >= sizeof(struct ip) + sizeof(struct icmp)) {
        struct ip *iphdr = (struct ip *) packet;
        
        pkt = (struct icmp *) (packet + (iphdr->ip_hl << 2));      /* skip ip hdr */
        if (pkt->icmp_type == ICMP_ECHOREPLY){
          host = inet_ntoa(from.sin_addr);
          printf("got reply from %s !\n", host);
          
          gettimeofday(&received_at, NULL);
          
          key = mrb_str_buf_new(mrb, strlen(host));
          // mrb_value mrb_str_buf_cat(mrb_state *mrb, mrb_value str, const char *ptr, size_t len);
          mrb_str_buf_cat(mrb, key, host, strlen(host));
          // void mrb_hash_set(mrb_state *mrb, mrb_value hash, mrb_value key, mrb_value val);
          mrb_hash_set(mrb, ret_value, key, mrb_fixnum_value(((received_at.tv_sec - sent_at.tv_sec) * 1000000 + (received_at.tv_usec - sent_at.tv_usec))));
          // break;
        }
      }
    }
    
    if( ret == 0 ){
      wait_time += tv.tv_sec * 1000000;
      wait_time += tv.tv_usec;
      
      // printf("%d %ld, %d\n", ret, tv.tv_sec, tv.tv_usec);
    }
    
    if( wait_time >= timeout ){
      puts("timed out");
      break;
    }
        
  }
  
  puts("out");

  
  return ret_value;
}

void mrb_mruby_ping_gem_init(mrb_state *mrb)
{
  struct RClass *udp = mrb_define_class(mrb, "Pinger", NULL);
  
  int ai = mrb_gc_arena_save(mrb);
  
  mrb_define_method(mrb, udp, "initialize", ping_initialize,  ARGS_NONE());
  mrb_define_method(mrb, udp, "set_targets", ping_set_targets,  ARGS_REQ(1));
  mrb_define_method(mrb, udp, "send_pings", ping_send_pings,  ARGS_REQ(1));
    
  mrb_gc_arena_restore(mrb, ai);
}

void mrb_mruby_ping_gem_final(mrb_state* mrb)
{
  
}
