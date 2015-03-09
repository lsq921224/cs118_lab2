#ifndef SR_IP_H
#define SR_IP_H

#include <sys/types.h>
#include "sr_router.h"

#define IPV4_HEADER_LEN 20
#define DEFAULT_TTL 64

int is_this_for_me(sr_instance_t* sr, 
		   uint32_t ip);

void handle_ip_packet(sr_instance_t* sr,
		      uint8_t* packet, 
		      unsigned len);

int send_ip_packet(sr_instance_t* sr, 
			uint32_t des_ip,
			uint32_t src_ip,
			unsigned char protocol, 
			uint8_t* packet, 
			unsigned len);

sr_ip_hdr_t* check_sum(uint8_t* packet, unsigned len);

#endif
