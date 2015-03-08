#include <stdlib.h>
#include <string.h>

#include "sr_utils.h"
#include "sr_if.h"
#include "sr_ip.h"
#include "sr_protocol.h"
#include "sr_icmp.h"


void handle_ip_packet(struct sr_instance* sr, uint8_t* packet, unsigned len)
{
  struct sr_ip_hdr* ip_header = (struct sr_ip_hdr*)packet;
  uint32_t src_ip = ip_header->ip_src;
  uint32_t des_ip = ip_header->ip_dst;

}


sr_ip_hdr_t* check_sum(uint8_t* packet, unsigned len)
{
  



}
