#include <stdlib.h>
#include <string.h>

#include "sr_utils.h"
#include "sr_if.h"
#include "sr_ip.h"
#include "sr_protocol.h"
#include "sr_icmp.h"


void handle_ip_packet(sr_instance_t* sr, uint8_t* packet, unsigned len)
{
	sr_ip_hdr_t* ip_header = (sr_ip_hdr_t*)packet;
	uint16_t old_sum = ip_header -> ip_sum;
	ip_header -> ip_sum = 0;
	ip_header -> ip_sum = cksum(ip_header, IPV4_HEADER_LEN);
	if (old_sum != ip_header -> ip_sum)		/* very checksum; if fail: drop the packet */
	{
		printf("IP packet check sum failed!");
		return;
	}
 	uint32_t src_ip = ip_header->ip_src;
	uint32_t des_ip = ip_header->ip_dst;
  	if (is_this_for_me(sr, des_ip) == 1) 		/* if destined to router*/
  	{  
		fprintf(stderr, "This package is for me!\n");
		if (ip_header->ip_p != IPPROTO_ICMP)	/* UDP TCP -> iCMP unreachable */
		{
			printf("Received a message with TCP or UDP\n");
			icmp_port_unreachable(sr, src_ip, des_ip, packet, len);
			return;
		}
		icmp_echo(sr, des_ip, src_ip, packet, len);/* ICMP -> ICMP processing */
  	}
  	else
  	{						/* if destinded to others */
		ip_header -> ip_ttl--;			/* decrease TTL */
		if (ip_header->ip_ttl == 0)		/* if TTL = 0, ICMP time exceed */
		{
			icmp_time_exceed(sr, src_ip, packet, len);
			return;
		}
		
		send_packet(sr, ip_header -> ip_dst, htons(ethertype_ip), packet, len);							/* else try to send ip_packet */				
  	}
}

int is_this_for_me(sr_instance_t* sr, uint32_t ip)
{ 
  	sr_if_t* interface = sr->if_list;
	while (interface != 0)
  	{
		if (interface ->ip == ip)
			return 1;
		interface = interface -> next;
  	}
  	return 0;
}

int send_packet (sr_instance_t* sr,
			uint32_t des_ip,
			uint16_t type,
			uint8_t* packet,
			unsigned len)
{
	unsigned char des_mac[ETHER_ADDR_LEN];
	unsigned char src_mac[ETHER_ADDR_LEN];
	/*print_hdr_ip(packet); */
	sr_ip_hdr_t* ip_header = (sr_ip_hdr_t*)packet;
	uint32_t src_ip = ip_header->ip_src;
	ip_header -> ip_sum = 0;
	ip_header -> ip_sum = cksum(ip_header, IPV4_HEADER_LEN);
	sr_rt_t* route = find_routing_entry(sr, des_ip);	/* try to find routing entry */
	if (route == 0)						/* if not found ->ICMP net unreachable */
	{
		icmp_net_unreachable(sr, src_ip, 0, packet, len);
		return -1;
	}
	char* interface = find_interface(sr, route, src_mac);	/* try to find outgoing interface, if found, return interface name and set src_mac */
	int arp = find_dst_mac_in_arp(sr, route, des_mac);	/* try to lookup arp table */
	if (interface != 0 && arp == 1)				/* if both found, send ip packet */
	{
		fprintf(stderr, "printing sending IP header\n");
		print_hdr_ip(packet);
		uint8_t* pkt = malloc(ETHER_HEADER_LEN + len);
		memcpy(pkt, des_mac, ETHER_ADDR_LEN);
		memcpy(pkt + ETHER_ADDR_LEN, src_mac, ETHER_ADDR_LEN);
		memcpy(pkt + ETHER_ADDR_LEN * 2, &type, 2);
		memcpy(pkt + ETHER_HEADER_LEN, packet, len);
		if (ntohs(type) == ethertype_ip)
		{
			fprintf(stderr, "sending ip pakcet via ethernet frame..");	
		}
		int send = sr_send_packet(sr, pkt, ETHER_HEADER_LEN + len, interface);
		free(pkt);
		return send;
	}
	else if (interface != 0 && arp == 0)		/* if interface is found but arp is not found, send arp request */
	{
		uint8_t* pkt = malloc(ETHER_HEADER_LEN + len);
		memcpy(pkt, des_mac, ETHER_ADDR_LEN);
		memcpy(pkt + ETHER_ADDR_LEN, src_mac, ETHER_ADDR_LEN);
		memcpy(pkt + ETHER_ADDR_LEN * 2, &type, 2);
		memcpy(pkt + ETHER_HEADER_LEN, packet, len);
		char *arr = pkt + ETHER_HEADER_LEN + IPV4_HEADER_LEN;
		fprintf(stderr, "printing payload when storing to arpcache queue\n");
		int i;
				   for (i = 0; i < len - IPV4_HEADER_LEN; i ++) {
					 fprintf(stderr, " %2x", arr[i]);
					 }
		struct sr_arpreq *arp = sr_arpcache_queuereq(&(sr->cache), route->gw.s_addr, pkt, ETHER_HEADER_LEN + len, interface);
		/* handle_arpreq(sr, arp); */
		unsigned char value[ETHER_ADDR_LEN] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
		sr_arp_send_message(sr, arp_op_request, value, des_ip, interface);
	}
	return -1;				/* else cannot send packet */

}

int send_ip_packet (sr_instance_t* sr,
			uint32_t des_ip,
			uint32_t src_ip,
			unsigned char protocol,
			uint8_t* packet,
			unsigned len,
			uint16_t id,
			uint16_t seq)
{
	sr_rt_t* route = 0;
	sr_if_t* interface = 0;
	if (src_ip == 0)   /* ip packet is sent from me */
	{
		route = find_routing_entry(sr, des_ip);
		interface = sr -> if_list;
		if (route != 0)
		{	
			while (interface != 0)
			{
				if (strcmp(interface->name, route->interface) == 0)
					break;
				interface = interface -> next;
			}
		}
		if (interface == 0)     /* no interface to send packet	*/
			return -1;
	}
	uint8_t* pkt = malloc(IPV4_HEADER_LEN + len);
	sr_ip_hdr_t* ip_header = (sr_ip_hdr_t*)pkt;
	ip_header -> ip_v = 4;
	ip_header -> ip_hl = 5;
	ip_header -> ip_len = htons(IPV4_HEADER_LEN + len);
	ip_header -> ip_ttl = DEFAULT_TTL;
	ip_header -> ip_p = protocol;
	ip_header -> ip_dst = des_ip;
	if (src_ip == 0)
		ip_header -> ip_src = interface -> ip;
	else
		ip_header -> ip_src = src_ip;
	ip_header -> ip_sum = 0;
	ip_header -> ip_sum = cksum(ip_header, IPV4_HEADER_LEN);
	memcpy(pkt + IPV4_HEADER_LEN, packet, len);
	int send = send_packet(sr, des_ip, htons(ethertype_ip), pkt, IPV4_HEADER_LEN + len);
	free(pkt);
	return send;

}

char* find_interface(sr_instance_t* sr,
			sr_rt_t* route,
			unsigned char* src_mac)
{
	sr_if_t* interface = sr->if_list;
	if (route == 0)
		return 0;
	else
	{
		while (interface != 0)
		{
			if (strcmp(interface->name, route->interface) == 0)
				break;
			interface = interface -> next;
		}
	}
	if (interface != 0)
	{
		memcpy(src_mac, interface->addr, ETHER_ADDR_LEN);
	}
	return interface->name;
}

int find_dst_mac_in_arp(sr_instance_t* sr,
			sr_rt_t* route,
			unsigned char* des_mac)
{
	if (route == 0)
		return 0;
	struct sr_arpentry* arp = sr_arpcache_lookup(&(sr->cache), route->gw.s_addr);
	if (arp == 0)
		return 0;
	else
	{
		memcpy(des_mac, arp->mac, ETHER_ADDR_LEN);
		free(arp);
	}
	return 1;
}

sr_rt_t* find_routing_entry(sr_instance_t* sr,
				uint32_t des_ip)
{
	sr_rt_t* table = sr->routing_table;
	sr_rt_t* ret = 0;
	while (table != 0)
	{
		if ((des_ip & table->mask.s_addr) == (table->dest.s_addr & table->mask.s_addr))
		{
			if (ret == 0)
				ret = table;
			else if (ret -> mask.s_addr < table -> mask.s_addr)
				ret = table;
		}
		table = table -> next;
	}
	return ret;
}

