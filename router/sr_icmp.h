#ifndef SR_ICMP_H
#define SR_ICMP_H

#include <sys/types.h>
#include "sr_router.h"

#define ICMP_HEADER_LEN 8

/* keep this function private
void send_icmp(sr_instance_t* sr,
		uint32_t des_ip,
		uint32_t src_ip,
		uint8_t* data,
		unsigned len,
		uint8_t type,
		uint8_t code);
*/

struct icmp {
    unsigned char type;
    unsigned char code;
    unsigned short sum;
    unsigned short id;
    unsigned short seq;
};
typedef struct icmp icmp_t;

void icmp_echo(sr_instance_t* sr, 
		uint32_t des_ip, 
		uint32_t src_ip, 
		uint8_t* packet, 
		unsigned len);

void icmp_port_unreachable (sr_instance_t* sr, 
				uint32_t des_ip, 
				uint32_t src_ip,
				uint8_t* packet, 
				unsigned len);

void icmp_time_exceed (sr_instance_t* sr,
			uint32_t des_ip,
			uint8_t* packet,
			unsigned len);

void icmp_net_unreachable (sr_instance_t* sr,
				uint32_t des_ip,
				uint32_t src_ip,
				uint8_t* packet,
				unsigned len);

void icmp_host_unreachable( sr_instance_t* sr,
                            uint32_t des_ip,
                            uint32_t src_ip,
                            uint8_t* packet,
                            unsigned len );
#endif
