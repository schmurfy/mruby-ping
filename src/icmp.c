#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/time.h>

#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>

#include <arpa/inet.h>
#include <fcntl.h>
#include <pthread.h>

#include <unistd.h>

#define MALLOC(X) mrb_malloc(mrb, X);
#define FREE(X) mrb_free(mrb, X);

#include "mruby-ping.h"

struct state {
  int icmp_sock;
  int raw_sock;
  struct target_address *targets;
  uint16_t targets_count;
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
  if( st->targets != NULL )
    FREE(st->targets);
    
  FREE(st);
}

static struct mrb_data_type ping_state_type = { "Pinger", ping_state_free };


static mrb_value ping_initialize(mrb_state *mrb, mrb_value self)
{
  int flags;
  struct state *st = MALLOC(sizeof(struct state));
  
  if ((st->raw_sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0) {
    mrb_raise(mrb, E_RUNTIME_ERROR, "cannot create raw socket, are you root ?");
    return mrb_nil_value();
  }
  
  if ((st->icmp_sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) < 0) {
    mrb_raise(mrb, E_RUNTIME_ERROR, "cannot create icmp socket, are you root ?");
    return mrb_nil_value();
  }
  
  // set the socket as non blocking
  flags = fcntl(st->icmp_sock, F_GETFL);
  if ( flags < 0){
    mrb_raise(mrb, E_RUNTIME_ERROR, "fnctl(GET) failed");
    return mrb_nil_value();
  }
  
  flags |= O_NONBLOCK;
  
  if (fcntl(st->icmp_sock, F_SETFL, flags) < 0){
    mrb_raise(mrb, E_RUNTIME_ERROR, "fnctl(SET) failed");
    return mrb_nil_value();
  }

  
  st->targets = NULL;
  
  DATA_PTR(self)  = (void*)st;
  DATA_TYPE(self) = &ping_state_type;
  
  return self;
}

static mrb_value ping_clear_targets(mrb_state *mrb, mrb_value self)
{
  struct state *st = DATA_PTR(self);
  
  if( st->targets != NULL ){
    mrb_free(mrb, st->targets);
  }
  
  return self;
}

static mrb_value ping_set_targets(mrb_state *mrb, mrb_value self)
{
  mrb_int n;
  mrb_value arr;
  struct state *st = DATA_PTR(self);
  
  mrb_get_args(mrb, "A", &arr);
    
  st->targets_count = RARRAY_LEN(arr);
  st->targets = MALLOC(sizeof(struct target_address) * st->targets_count );
  
  for( n = 0; n< st->targets_count; n++ ){
    mrb_value arr2 = mrb_ary_ref(mrb, arr, n);
    mrb_value r_addr = mrb_ary_ref(mrb, arr2, 0);
    mrb_value r_rtable = mrb_ary_ref(mrb, arr2, 1);
    
    if( !mrb_string_p(r_addr) ){
      mrb_raisef(mrb, E_TYPE_ERROR, "can't convert %s into String", mrb_obj_classname(mrb, r_addr));
    }
    else {
      st->targets[n].rtable = mrb_fixnum(r_rtable);
      st->targets[n].in_addr = inet_addr( mrb_str_to_cstr(mrb, r_addr) );
    }
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

// return t2 - t1 in microseconds
// static mrb_int timediff(struct timeval *t1, struct timeval *t2)
// {
//   return (t2->tv_sec - t1->tv_sec) * 1000000 +
//   (t2->tv_usec - t1->tv_usec);
// }


struct ping_reply {
  int seq;
  in_addr_t addr;
  struct timeval sent_at, received_at;
};

struct reply_thread_args {
  mrb_int           *timeout;
  struct state      *state;            // read-only
  struct ping_reply *replies;
  int               *replies_index;
};

static void *thread_icmp_reply_catcher(void *v)
{
  struct reply_thread_args *args = (struct reply_thread_args *)v;
  int c, ret;
  fd_set rfds;
  struct timeval tv, started_at;
  size_t packet_size;
  int wait_time = 0; // how much did we already wait
  
  // we will receive both the ip header and the icmp data
  packet_size = sizeof(struct ip) + sizeof(struct icmp);
  
  gettimeofday(&started_at, NULL);
  
  while (1) {
    struct sockaddr_in from;
    socklen_t fromlen = sizeof(from);
    
    FD_ZERO(&rfds);
    FD_SET(args->state->icmp_sock, &rfds);
    
    fill_timeout(&tv, *args->timeout - wait_time);
    ret = select(args->state->icmp_sock + 1, &rfds, NULL, NULL, &tv);
    if( ret == -1 ){
      perror("select");
      return NULL;
    }
    
    if( ret == 1 ){
      while(1){
        uint8_t packet[sizeof(struct ip) + sizeof(struct icmp)];
        c = recvfrom(args->state->icmp_sock, packet, packet_size, 0, (struct sockaddr *) &from, &fromlen);
        if( c < 0 ) {
          if ((errno != EINTR) && (errno != EAGAIN)){
            perror("recfrom");
            return NULL;
          }
          
          break;
        }
        if (c >= sizeof(struct ip) + sizeof(struct icmp)) {
          struct ip *iphdr = (struct ip *) packet;
          struct icmp *pkt = (struct icmp *) (packet + (iphdr->ip_hl << 2));      /* skip ip hdr */
          
          if( (pkt->icmp_type == ICMP_ECHOREPLY) && (pkt->icmp_id == 0xFFFF)){
            int i;
            
            // find which reply we just received
            for(i = 0; i< *args->replies_index; i++){
              struct ping_reply *reply = &args->replies[i];
              
              // same addr and sequence id
              if( (reply->addr == from.sin_addr.s_addr) && (reply->seq == ntohs(pkt->icmp_seq)) ){
                gettimeofday(&reply->received_at, NULL);
                // printf("got reply for %d after %d ms\n", reply->seq, timediff(&reply->sent_at, &reply->received_at) / 1000);
                break;
              }
            }
            
          }
        }
      }
    }
    else {
      // printf("select ret = %d\n", ret);
    }
    
    if( ret == 0 ){
      struct timeval now;
      gettimeofday(&now, NULL);
      wait_time += (now.tv_sec - started_at.tv_sec) * 1000000;
      wait_time += (now.tv_usec - started_at.tv_usec);
      
      // printf("%d %ld, %d\n", ret, tv.tv_sec, tv.tv_usec);
    }
    
    if( wait_time >= *args->timeout )
      break;
      
  }
  
  return NULL;
}

static mrb_value ping_send_pings(mrb_state *mrb, mrb_value self)
{
  struct state *st = DATA_PTR(self);
  mrb_int count, timeout, delay;
  mrb_value ret_value;
  int i, pos = 0;
  int sending_socket = st->icmp_sock;
  
  int replies_index = 0;
  struct ping_reply *replies;
  struct reply_thread_args thread_args;
  pthread_t reply_thread;
  
  struct icmp icmp;
  uint8_t packet[sizeof(struct ip) + sizeof(struct icmp)];
  size_t packet_size;
    
  mrb_get_args(mrb, "iii", &timeout, &count, &delay);
  timeout *= 1000; // ms => usec
  
  if( timeout <= 0 ) {
    mrb_raisef(mrb, E_TYPE_ERROR, "timeout should be positive and non null: %d", timeout);
    goto error;
  }
  
  packet_size = sizeof(icmp);
  
  ret_value = mrb_hash_new_capa(mrb, st->targets_count);
  
  // setup the receiver thread
  replies = MALLOC(st->targets_count * count * sizeof(struct ping_reply));
  bzero(replies, st->targets_count * count * sizeof(struct ping_reply));
  
  thread_args.state = st;
  thread_args.replies = replies;
  thread_args.replies_index = &replies_index;
  thread_args.timeout = &timeout;
  
  i = pthread_create(&reply_thread, NULL, thread_icmp_reply_catcher, &thread_args);
  if( i != 0 ){
    mrb_raisef(mrb, E_RUNTIME_ERROR, "thread creation failed: %d", i);
    goto free_replies;
  }
  
  // send each icmp echo request
  for(i = 0; i< st->targets_count; i++){
    int j;
    mrb_value key, arr;
    struct sockaddr_in dst_addr;
    
    // prepare destination address
    bzero(&dst_addr, sizeof(dst_addr));
    dst_addr.sin_family = AF_INET;
    dst_addr.sin_addr.s_addr = st->targets[i].in_addr;
    
    key = mrb_str_new_cstr(mrb, inet_ntoa(dst_addr.sin_addr));
    arr = mrb_ary_new_capa(mrb, count);
    mrb_hash_set(mrb, ret_value, key, arr);
    
    icmp.icmp_type = ICMP_ECHO;
    icmp.icmp_code = 0;
    icmp.icmp_id = 0xFFFF;
    
    for(j = 0; j< count; j++){
      struct ping_reply *reply = &replies[replies_index];
      
      reply->seq = j;
      reply->addr = dst_addr.sin_addr.s_addr;
      // printf("saved sent_at for seq %d\n", j);
      gettimeofday(&reply->sent_at, NULL);

      mrb_ary_set(mrb, arr, j, mrb_nil_value());
      
      icmp.icmp_seq = htons(j);
      icmp.icmp_cksum = 0;
      icmp.icmp_cksum = in_cksum((uint16_t *)&icmp, sizeof(icmp));
      
      memcpy(packet + pos, &icmp, sizeof(icmp));
      
    #ifdef __OpenBSD__
      // force routing table
      if (setsockopt(sending_socket, SOL_SOCKET, SO_RTABLE, &st->targets[i].rtable, sizeof(u_int)) == -1){
        perror("setsockopt (rtable) ");
      }
    #endif
      
      replies_index++;
      if (sendto(sending_socket, packet, packet_size, 0, (struct sockaddr *)&dst_addr, sizeof(struct sockaddr)) < 0)  {
        printf("sendto(dst: %s) error: %s\n", inet_ntoa(dst_addr.sin_addr), strerror(errno));
        // mrb_raisef(mrb, E_RUNTIME_ERROR, "unable to send ICMP packet: %S", strerror(errno));
      }
      else {
        usleep(delay * 1000);
      }
      
    }

  }
  
  pthread_join(reply_thread, NULL);
  
  // and process the received replies
  for(i = 0; i< replies_index; i++){
    char *host = inet_ntoa( *((struct in_addr *) &replies[i].addr));
    mrb_value key, value;
    mrb_int latency;
        
    key = mrb_str_new_cstr(mrb, host);
    value = mrb_hash_get(mrb, ret_value, key);
    
    if( (replies[i].received_at.tv_sec == 0) && (replies[i].received_at.tv_usec == 0) ){
      mrb_ary_set(mrb, value, replies[i].seq, mrb_nil_value());
    }
    else {
      latency = ((replies[i].received_at.tv_sec - replies[i].sent_at.tv_sec) * 1000000 + (replies[i].received_at.tv_usec - replies[i].sent_at.tv_usec));
      mrb_ary_set(mrb, value, replies[i].seq, mrb_fixnum_value(latency));
    }
  }
  
free_replies:
  FREE(replies);

error:
  return ret_value;
}

void mruby_ping_init_icmp(mrb_state *mrb)
{
  struct RClass *class = mrb_define_class(mrb, "ICMPPinger", NULL);
  
  int ai = mrb_gc_arena_save(mrb);
  
  mrb_define_method(mrb, class, "internal_init", ping_initialize,  ARGS_NONE());
  mrb_define_method(mrb, class, "_clear_targets", ping_clear_targets,  ARGS_NONE());
  mrb_define_method(mrb, class, "_set_targets", ping_set_targets,  ARGS_REQ(1));
  mrb_define_method(mrb, class, "_send_pings", ping_send_pings,  ARGS_REQ(1));
    
  mrb_gc_arena_restore(mrb, ai);
}
