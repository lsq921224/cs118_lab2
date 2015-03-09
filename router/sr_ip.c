#include <stdlib.h>
#include <string.h>

#include "sr_utils.h"
#include "sr_if.h"
#include "sr_ip.h"
#include "sr_protocol.h"
#include "sr_icmp.h"


void handle_ip_packet(sr_instance_t sr, uint8_t* packet, unsigned len)
{
  sr_ip_hdr_t ip_header = (sr_ip_hdr_t)packet;
  uint32_t src_ip = ip_header->ip_src;
  uint32_t des_ip = ip_header->ip_dst;
  if (is_this_for_me(sr, des_ip)) 		// if destined to router
  {  
	fprintf(stderr, "This package is for me!\n")
	if (ip_header->ip_p != IPPROTO_ICMP)	// UDP TCP -> iCMP unreachable
	{
		printf("Received a message with TCP or UDP\n");
		icmp_port_unreachable(sr, src_ip, des_ip, packet, len);
	}
	icmp_echo(sr, des_ip, src_ip, packet, len);// ICMP -> ICMP processing
  }
  else
  {						// if destinded to others
	ip_header -> ip_ttl--;			// decrease TTL
	if (ip_header->ip_ttl == 0)		// if TTL = 0, ICMP time exceed
	{
		icmp_time_exceed(sr, src_ip, packet, len);
		return;
	}
	ip_header -> ip_sum = 0;
	ip_header -> ip_sum = cksum(ip_header, IPV4_HEADER_LEN);
	sr_rt_t route = find_routing_entry(sr, des_ip); 
	if (route == 0)		// if routing entry not found ->ICMP unreachable
	{
		icmp_net_unreachable(sr, src_ip, 0, packet, len);
		return;
	}			
  }
}

int is_this_for_me(sr_instance_t sr, uint32_t ip)
{ 
  sr_if_t interface = sr->if_list;
  while (interface != 0)
  {
	if (interface ->ip == ip)
		return 1;
	interface = interface -> next;
  }
  return 0;
}



sr_ip_hdr_t check_sum(uint8_t* packet, unsigned len)
{    
  fprintf(stderr, "cheking sum\n");
  


}
