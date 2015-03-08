#ifndef SR_IP_H
#define SR_IP_H

#include <sys/types.h>
#include "sr_router.h"

void handle_ip_packet(struct sr_instance* sr,
		      uint8_t* packet, 
		      unsigned len);

int send_ip_packet(struct sr_instance* sr, 
		   uint32_t dest_ip, 
		   unsigned char protocol, 
		   uint8_t* packet, 
		   unsigned len);

sr_ip_hdr_t* check_sum(uint8_t* packet, unsigned len);

#endif
