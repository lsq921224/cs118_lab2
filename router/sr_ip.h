#ifndef SR_IP_H
#define SR_IP_H

#include <sys/types.h>
#include "sr_router.h"
#include "sr_rt.h"

#define IPV4_HEADER_LEN 20
#define DEFAULT_TTL 64
#define ETHER_HEADER_LEN 14
#define IP_ADDR_LEN 4

int is_this_for_me(sr_instance_t* sr, 
		   uint32_t ip);

void handle_ip_packet(sr_instance_t* sr,
		      uint8_t* packet, 
		      unsigned len);

int send_ip_packet (sr_instance_t* sr,
			uint32_t des_ip,
			uint32_t src_ip,
			unsigned char protocol,
			uint8_t* packet,
			unsigned len
			);

int send_packet(sr_instance_t* sr,
		uint32_t des_ip,
		uint16_t type,
		uint8_t* packet,
		unsigned len);

char* find_interface(sr_instance_t* sr,
			sr_rt_t* route,
			unsigned char* src_mac);

int find_dst_mac_in_arp(sr_instance_t* sr,
			sr_rt_t* route,
			unsigned char* des_mac);

sr_rt_t* find_routing_entry(sr_instance_t* sr,
				uint32_t des_ip);
#endif
