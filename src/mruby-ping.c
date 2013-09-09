#include "mruby-ping.h"




void ping_set_targets_common(mrb_state *mrb, mrb_value arr, const uint16_t *targets_count, struct target_address *targets)
{
  int i;
  mrb_value obj;
  
  for(i = 0; i< *targets_count; i++){
    obj = mrb_ary_ref(mrb, arr, i);
    if( !mrb_string_p(obj) )
      mrb_raisef(mrb, E_TYPE_ERROR, "can't convert %s into String", mrb_obj_classname(mrb, obj));
    
    targets[i].in_addr = inet_addr( mrb_str_to_cstr(mrb, obj) );
  }
}

void mrb_mruby_ping_gem_init(mrb_state *mrb)
{
  mruby_ping_init_icmp(mrb);
  mruby_ping_init_arp(mrb);
}

void mrb_mruby_ping_gem_final(mrb_state* mrb)
{
  
}
