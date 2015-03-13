/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <stdio.h>
#include <assert.h>


#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"
#include "sr_ip.h"

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/
#define MAX_SEND_ARP 5
#define ICMP_T3_TYPE 3
#define ARP_BROADCAST_MAC 0xFFFFFFFFFFFF /* TODO: can I cast this as a char array? (char*) ... */


void sr_init(struct sr_instance* sr)
{
    /* REQUIRES */
    assert(sr);

    /* Initialize cache and cache cleanup thread */
    sr_arpcache_init(&(sr->cache));

    pthread_attr_init(&(sr->attr));
    pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t thread;

    pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);
    
    /* Add initialization code here! */

} /* -- sr_init -- */

/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);

  printf("*** -> Received packet of length %d \n",len);

  /* fill in code here */
  if (len < ETHER_HEADER_LEN)
	return;
  /* 
  unsigned short type = ntohs(*(unsigned short*)(packet + ETHER_ADDR_LEN + ETHER_ADDR_LEN));
  */ 
  enum sr_ethertype t = (enum sr_ethertype)ethertype(packet);
  switch (t) {
	case ethertype_ip:
	{
		fprintf(stderr, "receiving IP packet..\n");
		print_hdrs(packet,len);
		handle_ip_packet(sr, packet + ETHER_HEADER_LEN, len - ETHER_HEADER_LEN);
		break;
	}
	case ethertype_arp:
	{
		fprintf(stderr, "Receiving ARP packet..\n");
		print_hdrs(packet, len);
		/* FIXME handle_arp_packet(...) */
		sr_handle_arp_packet(sr, packet + ETHER_HEADER_LEN, len - ETHER_HEADER_LEN , interface);
		break;
	}
	default:
		break;
	}

}/* end sr_ForwardPacket */

void create_ethernet_header (sr_ethernet_hdr_t * eth_hdr, uint8_t* ether_dhost, uint8_t* ether_shost, uint16_t ether_type) {
	/* MAC addresses are arrays of 8 byte segments so do not need network/host order conversion */
    memcpy((void *) eth_hdr->ether_dhost, (void *) ether_dhost, sizeof(uint8_t) * ETHER_ADDR_LEN);
    memcpy((void *) eth_hdr->ether_shost, (void *) ether_shost, sizeof(uint8_t) * ETHER_ADDR_LEN);
    eth_hdr->ether_type = htons(ether_type);
}

void create_arp_header(sr_arp_hdr_t * arp_hdr, unsigned short arp_op, unsigned char * ar_sha, uint32_t ar_sip, unsigned char * ar_tha, uint32_t ar_tip) {
    arp_hdr->ar_hrd = htons(arp_hrd_ethernet);
    arp_hdr->ar_pro = htons(ethertype_ip);

    arp_hdr->ar_hln = ETHER_ADDR_LEN * sizeof(uint8_t);
    arp_hdr->ar_pln = sizeof(uint32_t);
    arp_hdr->ar_op = htons(arp_op);
    memcpy((void *) arp_hdr->ar_sha , ar_sha, sizeof(unsigned char) * ETHER_ADDR_LEN);
    arp_hdr->ar_sip = htonl(ar_sip);
    if (arp_op == arp_op_reply) {
    	memcpy((void *) arp_hdr->ar_tha , ar_tha, sizeof(unsigned char) * ETHER_ADDR_LEN);
    }
    else {
    	memset(arp_hdr->ar_tha, 0xFF, sizeof(unsigned char) * ETHER_ADDR_LEN);
    }

    arp_hdr->ar_tip = ar_tip;
}

void sr_arp_send_message(struct sr_instance * sr, unsigned short ar_op, unsigned char * ar_tha, uint32_t ar_tip, char * interface) {
	/* TODO: do we just use the first item in the list? */
	struct sr_if * iface = sr_get_interface(sr, interface);
	if (iface == NULL) {
		fprintf(stderr, "Invalid Interface: %s.\n", interface);
		return;
	}

    uint32_t ar_sip = ntohl(iface->ip);
    unsigned char * ar_sha = malloc(sizeof(unsigned char) * ETHER_ADDR_LEN);
    memcpy((void*) ar_sha, iface->addr, sizeof(unsigned char) * ETHER_ADDR_LEN);
    
    sr_ethernet_hdr_t * frame = malloc(sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t));
    create_ethernet_header(frame, ar_tha, (uint8_t *)ar_sha, ethertype_arp);
    
    void * ptr = (void *) frame;
    ptr += sizeof(sr_ethernet_hdr_t);

    create_arp_header((sr_arp_hdr_t *) ptr, ar_op, ar_sha, ar_sip, ar_tha, ar_tip);

    fprintf(stderr, "Sending ARP:\n");
    print_hdrs((uint8_t *)frame, sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t));
    sr_send_packet(sr, (uint8_t*) frame, sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t), interface );
    
    free(frame);
}

void sr_arp_request(struct sr_instance * sr, uint32_t ip_addr, uint8_t * packet, unsigned int packet_len, char * interface) {
	unsigned char value[ETHER_ADDR_LEN] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
	sr_arp_send_message(sr, arp_op_request, value, ip_addr, interface);
	sr_arpcache_queuereq(&(sr->cache), ip_addr, packet, packet_len, interface);
}

void sr_handle_arp_packet(struct sr_instance* sr,
                          uint8_t * packet,
                          unsigned int len,
                          char* interface) {
	if (len < sizeof(sr_arp_hdr_t)) {
		fprintf(stderr, "Packet is less than ARP length!\n");
		return;
	}
	
	sr_arp_hdr_t *arphdr = (sr_arp_hdr_t*)(packet);
	arphdr->ar_hrd = ntohs(arphdr->ar_hrd);		/* Convert all network address to host addresses */
	arphdr->ar_pro = ntohs(arphdr->ar_pro);
	arphdr->ar_op = ntohs(arphdr->ar_op);
	arphdr->ar_sip = ntohl(arphdr->ar_sip);
	arphdr->ar_tip = ntohl(arphdr->ar_tip);
	
	if(arphdr->ar_op == 1){ /* Receiving a request */
        memcpy((void*) (arphdr->ar_tha), (void *) (arphdr->ar_sha), (sizeof(unsigned char) * ETHER_ADDR_LEN)); /* switch around the fields (dest to src, vice versa) */
		uint32_t targetIP = arphdr->ar_tip;
		arphdr->ar_tip = arphdr->ar_sip;
		arphdr->ar_sip = targetIP;
        
		struct sr_if* interfaces = sr->if_list;
		while(interfaces != NULL){ /* Walk through interfaces if any of the interfaces has targetIP address */
			
			if(ntohl(interfaces->ip) == targetIP){	/* Respond only if there is a match */
                memcpy((void*) (arphdr->ar_sha), (void *) (interfaces->addr), (sizeof(unsigned char) * ETHER_ADDR_LEN));
				sr_arp_send_message(sr, arp_op_reply, arphdr->ar_tha, htonl(arphdr->ar_tip), interface); /* Send reply with interface that has targetIP address */
				break;
			}
            interfaces = interfaces->next;
		}

	}
	if (arphdr->ar_op == 2){ /* Receiving a reply */

		fprintf(stderr, "ar_op is 2\n");
		struct sr_arpreq* pending = sr_arpcache_insert(&sr->cache,arphdr->ar_sha,htonl(arphdr->ar_sip)); 
		if(pending == NULL)
		{
			fprintf(stderr,"pending is null\n");
		}  
		if (pending != NULL){
			fprintf(stderr,"Received ARP reply with address: ");
			struct sr_packet *pkt = pending -> packets;
			while (pkt != NULL)
			{
				fprintf(stderr, "now have arp entry, send packet again\n");
				memcpy (pkt -> buf,  arphdr->ar_sha, ETHER_ADDR_LEN);
				print_hdrs(pkt ->buf, pkt-> len);
				sr_send_packet(sr, pkt -> buf, pkt->len, interface);
				pkt = pkt->next;

			}
			sr_arpreq_destroy(&(sr->cache), pending);
			/*print_addr_ip_int(arphdr->ar_sip);*/
			/*
			print_addr_ip_int(ntohl(pending->ip));
			if(ntohl(pending->ip) == arphdr->ar_sip){			
				sr_arpreq_send_packets(sr, pending);
			}
			pending = pending->next;
			*/
		}
	}
    
}


void sr_arpreq_send_packets(struct sr_instance * sr, struct sr_arpreq * req) {
	struct sr_packet * current = req->packets;

	while (current != NULL) {
		struct sr_arpentry * entry = sr_arpcache_lookup(&(sr->cache), req->ip);
		if (entry != NULL) {
			unsigned char * destMAC = entry->mac;
			memcpy(((sr_ethernet_hdr_t *) current->buf)->ether_dhost, destMAC, sizeof(unsigned char) * ETHER_ADDR_LEN);
			sr_send_packet(sr, current->buf, current->len, current->iface);
			free(entry);
		}
		current = current->next;
	}
}
