#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/time.h>

#include <libnet.h>
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
#include <strings.h> // bzero

#define MALLOC(X) mrb_malloc(mrb, X);
#define REALLOC(P, X) mrb_realloc(mrb, P, X);
#define FREE(X) mrb_free(mrb, X);

#include "mruby-ping.h"

static char errbuf[LIBNET_ERRBUF_SIZE];

struct capture_socket {
  uint32_t  rtable;
#ifdef SO_BINDTODEVICE
  char      device[IFNAMSIZ];
#endif
  int socket;
};

struct state {
  struct capture_socket *capture_sockets;
  uint16_t capture_sockets_count;
  
  struct target_address *targets;
  uint16_t targets_count;
  
  libnet_t **libnet_contexts;
  uint16_t libnet_contexts_count;
};




static void ping_state_free(mrb_state *mrb, void *ptr)
{
  struct state *st = (struct state *)ptr;
  if( st->targets != NULL )
    FREE(st->targets);
    
  FREE(st);
}

static struct mrb_data_type ping_state_type = { "Pinger", ping_state_free };

static int init_capture_socket(mrb_state *mrb, struct state *st, struct target_address *ta)
{
  int i, ret = -1;
  
  // first check if we already have a socket in this routing table/device
  for(i = 0; i< st->capture_sockets_count; i++){
    const char *device = NULL;
#ifdef SO_BINDTODEVICE
    device = st->capture_sockets[i].device;
#endif

    if( (st->capture_sockets[i].rtable == ta->rtable) && ( !device || !strcmp(device, ta->device) ) ){
      ret = st->capture_sockets[i].socket;
      break;
    }
  }
  
  // create it if none already exist
  if( ret == -1 ){
    int index = st->capture_sockets_count++;
    
    if( st->capture_sockets == NULL ){
      st->capture_sockets = MALLOC(sizeof(struct capture_socket) * st->capture_sockets_count);
    }
    else {
      st->capture_sockets = REALLOC(st->capture_sockets, sizeof(struct capture_socket) * st->capture_sockets_count);
    }
    
    ret = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);

    if( ret != -1 ){
      int flags;
      
      // set the socket as non blocking
      flags = fcntl(ret, F_GETFL);
      if ( flags < 0){
        perror("fnctl(GET) failed");
        return -1;
      }
      
      flags |= O_NONBLOCK;
      
      if (fcntl(ret, F_SETFL, flags) < 0){
        perror("fnctl(SET) failed\n");
        return -1;
      }
      
#ifdef __OpenBSD__
      // force routing table, do nothing if rtable is 0 (default table)
      if( ta->rtable != 0 ){
        if( setsockopt(ret, SOL_SOCKET, SO_RTABLE, &ta->rtable, sizeof(ta->rtable)) == -1 ){
          perror("setsockopt(SO_RTABLE) ");
        }
      }
#endif

#ifdef SO_BINDTODEVICE
      if( strlen(ta->device) > 0 ){
        if( setsockopt(ret, SOL_SOCKET, SO_BINDTODEVICE, ta->device, strlen(ta->device) + 1) == -1 ){
          perror("setsockopt(SO_BINDTODEVICE) ");
        }
      }
      
      strncpy(st->capture_sockets[index].device, ta->device, IFNAMSIZ - 1);
#endif
      
      st->capture_sockets[index].rtable = ta->rtable;
      st->capture_sockets[index].socket = ret;
    }
  }
  
  return ret;
}

static libnet_t *find_libnet_context(struct state *st, const char *device)
{
  int i;
  libnet_t *ret = NULL;
  
  for(i = 0; i< st->libnet_contexts_count; i++){
    const char *context_device = libnet_getdevice(st->libnet_contexts[i]);
    
    // a libnet context already exists for this device, returns it and stop searching
    // if a device was not specified, take the first one
    if( !device[0] || !strcmp(context_device, device) ){
      ret = st->libnet_contexts[i];
      break;
    }
  }

  
  return ret;
}

static int init_libnet_context(mrb_state *mrb, struct state *st, const char *device)
{
  libnet_t *l;
  
  l = find_libnet_context(st, device);
  if( l == NULL ){
    // context not found, create a new one
    // we reuse the same error buffer since we are not multithreaded for this part
    l = libnet_init(LIBNET_RAW4, device, errbuf);
    if( l > 0 ){
      int index = st->libnet_contexts_count++;
      
      if( st->libnet_contexts == NULL ){
        st->libnet_contexts = MALLOC(sizeof(libnet_t*) * st->libnet_contexts_count);
      }
      else {
        st->libnet_contexts = REALLOC(st->libnet_contexts, sizeof(libnet_t*) * st->capture_sockets_count);
      }
      
#ifdef SO_BINDTODEVICE
      if( strlen(device) > 0 ){
        if( setsockopt(libnet_getfd(l), SOL_SOCKET, SO_BINDTODEVICE, device, strlen(device) + 1) == -1 ){
          perror("setsockopt(SO_BINDTODEVICE) ");
        }
      }
#endif
      
      st->libnet_contexts[index] = l;
      printf("** Created new context for device '%s' , fd: %d\n", device, libnet_getfd(l));
    }
  }
    
  return (l != NULL);
}

static mrb_value ping_initialize(mrb_state *mrb, mrb_value self)
{
  
  struct state *st = MALLOC(sizeof(struct state));
  
  st->capture_sockets = NULL;
  st->capture_sockets_count = 0;
  
  st->targets = NULL;
  
  st->libnet_contexts = NULL;
  st->libnet_contexts_count = 0;
  
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
  int ai = mrb_gc_arena_save(mrb);
  
  mrb_get_args(mrb, "A", &arr);
  
  // close existing icmp sockets
  if( st->capture_sockets != NULL ){
    FREE(st->capture_sockets);
    st->capture_sockets = NULL;
    st->capture_sockets_count = 0;
  }
    
  st->targets_count = RARRAY_LEN(arr);
  st->targets = MALLOC(sizeof(struct target_address) * st->targets_count );
  
  for( n = 0; n< st->targets_count; n++ ){
    mrb_value arr2 = mrb_ary_ref(mrb, arr, n);
    mrb_value r_addr = mrb_ary_ref(mrb, arr2, 0);
    mrb_value r_rtable = mrb_ary_ref(mrb, arr2, 1);
    mrb_value r_uid = mrb_ary_ref(mrb, arr2, 2);
    mrb_value r_ifname = mrb_ary_ref(mrb, arr2, 3);
    mrb_value r_src_addr = mrb_ary_ref(mrb, arr2, 4);
    
    if( !mrb_string_p(r_addr) ){
      mrb_raisef(mrb, E_TYPE_ERROR, "can't convert %s into String", mrb_obj_classname(mrb, r_addr));
    }
    else {
      const char *device = NULL;
      
      st->targets[n].rtable = mrb_fixnum(r_rtable);
      st->targets[n].in_addr = inet_addr( mrb_str_to_cstr(mrb, r_addr) );
      
      if( mrb_nil_p(r_src_addr) ){
        st->targets[n].in_addr_src = 0;
      }
      else {
        st->targets[n].in_addr_src = inet_addr( mrb_str_to_cstr(mrb, r_src_addr) );
      }
      
      st->targets[n].uid = (uint16_t) mrb_fixnum(r_uid);
      
#ifdef SO_BINDTODEVICE
      bzero(st->targets[n].device, sizeof(st->targets[n].device));
      
      if( !mrb_nil_p(r_ifname) ){
        strncpy(st->targets[n].device, mrb_str_to_cstr(mrb, r_ifname),
            sizeof(st->targets[n].device) - 1
          );
        
        device = st->targets[n].device;
      }
#endif
      
      // create capture socket
      if( init_capture_socket(mrb, st, &st->targets[n]) == -1 ){
        mrb_raise(mrb, E_RUNTIME_ERROR, "cannot create icmp socket, are you root ?");
      }
      
      // create libnet context
      if( init_libnet_context(mrb, st, device) == -1 ){
        mrb_raisef(mrb, E_RUNTIME_ERROR, "cannot create libnet context: %S", mrb_str_new_cstr(mrb, errbuf));
      }
    }
    
    mrb_gc_arena_restore(mrb, ai);
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
  uint16_t seq;
  uint16_t id;
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
  long wait_time = 0; // how much did we already wait
  
  // we will receive both the ip header and the icmp data
  packet_size = LIBNET_IPV4_H + LIBNET_ICMPV4_ECHO_H;
  
  gettimeofday(&started_at, NULL);
  
  while (1) {
    int i, maxfd = 0;
    struct sockaddr_in from;
    socklen_t fromlen = sizeof(from);
    
    FD_ZERO(&rfds);
    
    for(i = 0; i< args->state->capture_sockets_count; i++){
      FD_SET(args->state->capture_sockets[i].socket, &rfds);
      if( args->state->capture_sockets[i].socket > maxfd ){
        maxfd = args->state->capture_sockets[i].socket + 1;
      }
    }
    
    fill_timeout(&tv, *args->timeout - wait_time);
    ret = select(maxfd, &rfds, NULL, NULL, &tv);
    if( ret == -1 ){
      perror("select");
      return NULL;
    }
    
    if( ret > 0 ){
      for(i = 0; i< args->state->capture_sockets_count; i++){
        int sock = args->state->capture_sockets[i].socket;
        
        if( FD_ISSET(sock, &rfds) ){
          while(1){
            uint8_t packet[sizeof(struct ip) + sizeof(struct icmp)];
            c = recvfrom(sock, packet, packet_size, 0, (struct sockaddr *) &from, &fromlen);
            if( c < 0 ) {
              if ((errno != EINTR) && (errno != EAGAIN)){
                perror("recvfrom");
                return NULL;
              }
              
              break;
            }
            if (c >= packet_size) {
              struct ip *iphdr = (struct ip *) packet;
              struct icmp *pkt = (struct icmp *) (packet + (iphdr->ip_hl << 2));      /* skip ip hdr */
              
              if( pkt->icmp_type == ICMP_ECHOREPLY ){
                int i;
                
                // find which reply we just received
                for(i = 0; i< *args->replies_index; i++){
                  struct ping_reply *reply = &args->replies[i];
                  
                  // same addr, id and sequence id
                  if( (reply->addr == from.sin_addr.s_addr) && (reply->id == ntohs(pkt->icmp_id)) && (reply->seq == ntohs(pkt->icmp_seq)) ){
                    gettimeofday(&reply->received_at, NULL);
                    // printf("got reply for %d after %d ms\n", reply->seq, timediff(&reply->sent_at, &reply->received_at) / 1000);
                    break;
                  }
                }
                
              }
            }
          }
        }
        
      }
    }
    else {
      // printf("select ret = %d\n", ret);
    }
    
    {
      struct timeval now;
      gettimeofday(&now, NULL);
      wait_time = (now.tv_sec - started_at.tv_sec) * 1000000;
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
  int i, ai;
  uint16_t j;
    
  int replies_index = 0;
  struct ping_reply *replies;
  struct reply_thread_args thread_args;
  pthread_t reply_thread;
  
    
  mrb_get_args(mrb, "iii", &timeout, &count, &delay);
  timeout *= 1000; // ms => usec
  
  if( timeout <= 0 ) {
    mrb_raisef(mrb, E_TYPE_ERROR, "timeout should be positive and non null: %d", timeout);
    goto error;
  }
  
  
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
  ai = mrb_gc_arena_save(mrb);
  

  
  for(j = 0; j< count; j++){
    
    // for each "tick" send one icmp for each defined target
    // and then sleep
    for(i = 0; i< st->targets_count; i++){
      int sending_socket = -1;
      uint16_t reply_id;
      mrb_value key, arr;
      struct ping_reply *reply = &replies[replies_index];
      libnet_ptag_t t;
      libnet_t *l;
      const char *device = NULL;
      
#ifdef SO_BINDTODEVICE
      device = st->targets[i].device;
#endif
      
      l = find_libnet_context(st, device);
      if( l == NULL ){
        printf("fatal error, no context for device '%s', exiting.\n", device);
        exit(1);
      }
      
      reply_id = st->targets[i].uid;
      if( reply_id == 0 ){
        reply_id = 100 + i;
      }
      
      key = mrb_fixnum_value(reply_id);
      arr = mrb_ary_new_capa(mrb, count);
      mrb_hash_set(mrb, ret_value, key, arr);
      
      reply->id = reply_id;
      reply->seq = j + 1;
      reply->addr = st->targets[i].in_addr;
      // printf("saved sent_at for seq %d\n", j);

      mrb_ary_set(mrb, arr, j, mrb_nil_value());
      
      
      t = libnet_build_icmpv4_echo(
            ICMP_ECHO,                            /* type */
            0,                                    /* code */
            0,                                    /* checksum */
            reply_id,                             /* id */
            j + 1,                                /* sequence number */
            NULL,                                 /* payload */
            0,                                    /* payload size */
            l,                                    /* libnet handle */
            0
          );
      
      if( t == -1 ){
        printf("Can't build ICMP header: %s\n", libnet_geterror(l));
        goto error;
      }
      
      if( st->targets[i].in_addr_src != 0 ){
        t = libnet_build_ipv4(
            /* ip packet length */  LIBNET_IPV4_H + LIBNET_ICMPV4_ECHO_H + 0,
            /* tos */               0,
            /* id */                libnet_get_prand(LIBNET_PRu16),
            /* frag */              0,
            /* ttl */               100,
            /* protocol */          IPPROTO_ICMP,
            /* checksum */          0,
            /* src IP */            st->targets[i].in_addr_src,
            /* dst IP */            st->targets[i].in_addr,
            /* payload */           NULL,
            /* payload size */      0,
            /* libnet handle */     l,
            /* libnet ptag */       0
          );
        
      } else {
        t = libnet_autobuild_ipv4(
            LIBNET_IPV4_H + LIBNET_ICMPV4_ECHO_H + 0, /* length */
            IPPROTO_ICMP,                         /* protocol */
            st->targets[i].in_addr,               /* destination IP */
            l
          );
        
      }
      
      if( t == -1 ){
        printf("Can't build IP header: %s\n", libnet_geterror(l));
        goto error;
      }
      
      
      sending_socket = libnet_getfd(l);

      if( sending_socket != -1 ){
        
#ifdef SO_RTABLE
        if( setsockopt(sending_socket, SOL_SOCKET, SO_RTABLE, &st->targets[i].rtable, sizeof(st->targets[i].rtable)) == -1 ){
          perror("setsockopt(SO_RTABLE) ");
        }
#endif
        
        // send the icmp packet
        replies_index++;
        
        if( libnet_write(l) >= 0 ){
          gettimeofday(&reply->sent_at, NULL);
        }
        else {
          printf("writing packet failed: %s\n", libnet_geterror(l));
        }
        
        libnet_clear_packet(l);
      }
      
      mrb_gc_arena_restore(mrb, ai);
    }
    
    usleep(delay * 1000);
  }
  
  pthread_join(reply_thread, NULL);
  
  // and process the received replies
  for(i = 0; i< replies_index; i++){
    // char *host = inet_ntoa( *((struct in_addr *) &replies[i].addr));
    mrb_value key, value;
    mrb_int latency;
    
    // key = mrb_str_new_cstr(mrb, host);
    key = mrb_fixnum_value(replies[i].id);
    value = mrb_hash_get(mrb, ret_value, key);
    if( mrb_nil_p(value) ){
      printf("no array with key %d !\n", replies[i].id);
      goto error;
    }
    
    if( (replies[i].received_at.tv_sec == 0) && (replies[i].received_at.tv_usec == 0) ){
      mrb_ary_set(mrb, value, replies[i].seq - 1, mrb_nil_value());
    }
    else {
      latency = ((replies[i].received_at.tv_sec - replies[i].sent_at.tv_sec) * 1000000 + (replies[i].received_at.tv_usec - replies[i].sent_at.tv_usec));
      mrb_ary_set(mrb, value, replies[i].seq - 1, mrb_fixnum_value(latency));
    }
    
    mrb_gc_arena_restore(mrb, ai);
  }
  
free_replies:
error:
  FREE(replies);
  
  // libnet_destroy(l);
  return ret_value;
}

void mruby_ping_init_icmp(mrb_state *mrb)
{
  struct RClass *class = mrb_define_class(mrb, "ICMPPinger", mrb->object_class);
  
  int ai = mrb_gc_arena_save(mrb);
  
  mrb_define_method(mrb, class, "internal_init", ping_initialize,  MRB_ARGS_NONE());
  mrb_define_method(mrb, class, "_clear_targets", ping_clear_targets,  MRB_ARGS_NONE());
  mrb_define_method(mrb, class, "_set_targets", ping_set_targets,  MRB_ARGS_REQ(1));
  mrb_define_method(mrb, class, "_send_pings", ping_send_pings,  MRB_ARGS_REQ(1));
    
  mrb_gc_arena_restore(mrb, ai);
}
