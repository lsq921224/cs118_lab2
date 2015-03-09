#include <stdlib.h>
#include <string.h>

#include "sr_utils.h"
#include "sr_icmp.h"
#include "sr_ip.h"
#include "sr_protocol.h"

#define ICMP_ECHOREPLY		0
#define ICMP_DEST_UNREACH	3
#define ICMP_ECHO		8
#define ICMP_TIME_EXCEEDED	11

/* codes for unreach */
#define ICMP_NET_UNREACH	0
#define ICMP_HOST_UNREACH	1
#define ICMP_PORT_UNREACH	3

/* codes for time_exceeded */
#define ICMP_EXC_TTL		0

/* icmp min length */
#define ICMP_MINLEN		8

void send_icmp(sr_instance_t* sr,
		uint32_t des_ip,
		uint32_t src_ip,
		uint8_t* data,
		unsigned len,
		uint8_t type,
		uint8_t code)
{
	fprintf(stderr, "Sending ICMP message");
	uint8_t* packet = malloc(ICMP_HEADER_LEN + len);
	sr_icmp_hdr_t* icmp_header = (sr_icmp_hdr_t*)packet;
	icmp_header -> icmp_type = type;
	icmp_header -> icmp_code = code;
	memcpy(packet + sizeof(*icmp_header), data, len);
	icmp_header -> icmp_sum = 0;
	icmp_header -> icmp_sum = cksum(icmp_header, ICMP_HEADER_LEN + len);
	send_ip_packet(sr, des_ip, src_ip, IPPROTO_ICMP, packet, ICMP_HEADER_LEN + len);
	free(packet);
}

void icmp_echo(sr_instance_t* sr,
		uint32_t des_ip,
		uint32_t src_ip,
		uint8_t* packet,
		unsigned len)
{
	sr_icmp_hdr_t* icmp_header = (sr_icmp_hdr_t*)(packet + IPV4_HEADER_LEN);
	unsigned icmp_len = len - IPV4_HEADER_LEN;
	if (icmp_header -> icmp_type != ICMP_ECHO)
		return;
	uint16_t tempSum = icmp_header-> icmp_sum;
	icmp_header -> icmp_sum = 0;
	icmp_header -> icmp_sum = cksum(icmp_header, icmp_len);
	if (tempSum != icmp_header->sum)
	{
		printf("ICMP check sum failed!");
		return;
	}
	send_icmp(sr, src_ip, des_ip, packet + IPV4_HEADER_LEN + ICMP_HEADER_LEN, len - IPV4_HEADER_LEN - ICMP_HEADER_LEN, ICMP_ECHO, 0);
	
}

void icmp_port_unreachable (sr_instance_t* sr,
				uint32_t des_ip,
				uint32_t src_ip,
				uint8_t* packet,
				unsigned len)
{
	unsigned min_len = max(IPV4_HEADER_LEN + ICMP_MINLEN, len);
	send_icmp(sr, des_ip, src_ip, packet, min_len, ICMP_DEST_UNREACH, ICMP_PORT_UNREACH);

}

void icmp_time_exceed (sr_instance_t* sr,
			uint32_t des_ip,
			uint8_t* packet,
			unsigned len)
{
	unsigned min_len = max(IPV4_HEADER_LEN + ICMP_MINLEN, len);
	send_icmp(sr, des_ip, 0, packet, len, ICMP_TIME_EXCEEDED, ICMP_EXC_TTL);
}

void icmp_net_unreachable (sr_instance_t* sr,
				uint32_t des_ip,
				uint32_t src_ip,
				uint8_t* packet,
				unsigned len)
{
	unsigned min_len = max(IPV4_HEADER_LEN + ICMP_MINLEN, len);
	send_icmp(sr, des_ip, src_ip, packet, len, ICMP_DEST_UNREACH, ICMP_NET_UNREACH);

}