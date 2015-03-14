#include <netinet/in.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>
#include <sched.h>
#include <string.h>

#include "sr_arpcache.h"
#include "sr_router.h"
#include "sr_if.h"
#include "sr_ip.h"
#include "sr_protocol.h"
#include "sr_icmp.h"
#include "sr_utils.h"
#include "sr_rt.h"





/* This function gets called every second. See the comments in the header file
   for an idea of what it should look like. */
void sr_arpcache_sweepreqs(struct sr_instance *sr) {
    /* Fill this in */
     struct sr_arpcache *cache = &(sr->cache);
     struct sr_arpreq *req = cache->requests;
     while(req != 0)
     {
       handle_arpreq(sr, req);
       req = req->next;
     }
}

struct sr_if* lookup_interface(struct sr_instance* sr,struct sr_rt* route)
{
  struct sr_if *interface = sr->if_list;
  if(route != 0)
  {
    while(interface != 0)
    {
      if(strcmp(interface->name, route->interface) == 0)
        return interface;
      interface = interface->next;
    }
  }
  return 0;
}   

/***************add by xin*************/
void send_arp_request( struct sr_instance* sr, uint32_t ip)
{
  uint8_t* buffer; 
  buffer = malloc(ETHER_HEADER_LEN + sizeof(struct sr_arp_hdr));
  
  struct sr_arp_hdr *arp_header = (struct sr_arp_hdr *)(buffer + ETHER_HEADER_LEN);
  
  arp_header->ar_hrd = htons( arp_hrd_ethernet );
  arp_header->ar_pro = htons( ethertype_ip );
  arp_header->ar_hln = ETHER_ADDR_LEN;
  arp_header->ar_pln = IP_ADDR_LEN;
  arp_header->ar_op  = htons( arp_op_request );
  memset(arp_header->ar_tha, 0, ETHER_ADDR_LEN );
  arp_header->ar_tip = ip;
  
  struct sr_rt* rt = find_routing_entry(sr, ip);
  struct sr_if* interface = lookup_interface(sr, rt);

  arp_header->ar_sip = interface->ip;
  memcpy(arp_header->ar_sha, interface->addr, ETHER_ADDR_LEN );
  
  memset(buffer, 0xFF, ETHER_ADDR_LEN);
  memcpy(buffer + ETHER_ADDR_LEN, interface->addr, ETHER_ADDR_LEN);
  uint16_t type = htons(ethertype_arp);
  memcpy(buffer+ETHER_ADDR_LEN+ETHER_ADDR_LEN, &type, 2 );

  /*fprintf(stderr, "Sending ARP Request from %s for %s\n", ip_to_string(arp_header->ar_sip), ip_to_string(ip)); 
  printAllHeaders(buffer, ETHER_HEADER_LEN + sizeof(struct sr_arp_hdr));*/
  

  sr_send_packet(sr, buffer, ETHER_HEADER_LEN + sizeof(struct sr_arp_hdr), interface->name );
  free( buffer );
  
}


void send_arp_reply(struct sr_instance* sr, struct sr_arp_hdr* req, struct sr_if* interface) 
{
   
    memcpy(req->ar_tha, req->ar_sha, ETHER_ADDR_LEN);
    req->ar_tip = req->ar_sip;
    memcpy(req->ar_sha, interface->addr, ETHER_ADDR_LEN );
    req->ar_sip = interface->ip;
    req->ar_op = htons(arp_op_reply);

    uint8_t* buffer = malloc( ETHER_HEADER_LEN + sizeof(struct sr_arp_hdr));
    memcpy( buffer, req->ar_tha, ETHER_ADDR_LEN );
    memcpy( buffer+ETHER_ADDR_LEN, req->ar_sha, ETHER_ADDR_LEN);
    uint16_t type = htons(ethertype_arp);
    memcpy(buffer+ETHER_ADDR_LEN+ETHER_ADDR_LEN, &type, 2);
    memcpy(buffer+ETHER_HEADER_LEN, (uint8_t*)req, sizeof(struct sr_arp_hdr));
    
    /*fprintf(stderr, "Sending ARP Reply from %s to %s\n", ip_to_string(req->ar_sip), ip_to_string(req->ar_tip));
    printAllHeaders(buffer, ETHER_HEADER_LEN + sizeof(struct sr_arp_hdr));*/
    

    sr_send_packet(sr, buffer, ETHER_HEADER_LEN + sizeof(struct sr_arp_hdr), interface->name);
    free(buffer);
}


int handle_arpreq(struct sr_instance *sr, struct sr_arpreq *req)
{
  time_t curtime = time(NULL);
  if((curtime - req->sent) > 1.0)
  {
    /*fprintf(stderr, "!!! %d\n",req->times_sent);*/
    if(req->times_sent >= 5)
    {
      struct sr_packet *pkt = req->packets;
      while(pkt != 0)
      {
        uint8_t* ip_pkt = (uint8_t*)(pkt->buf + ETHER_HEADER_LEN);
        struct sr_ip_hdr* ip_header = (struct sr_ip_hdr*)(pkt->buf + ETHER_HEADER_LEN);

        if((ip_header->ip_p != IPPROTO_ICMP) || (((struct sr_icmp_hdr*)(pkt->buf + ETHER_HEADER_LEN + IPV4_HEADER_LEN))->icmp_code == 8))
        {
          ip_header->ip_ttl++;
          ip_header->ip_sum = 0;
          ip_header->ip_sum = cksum(ip_header, IPV4_HEADER_LEN);
          icmp_host_unreachable(sr, ip_header->ip_src, 0, ip_pkt, pkt->len - ETHER_HEADER_LEN);
        }
        
        pkt = pkt->next;
      }
      sr_arpreq_destroy(&(sr->cache), req);
      return 0;
    }
    else
    {
      send_arp_request(sr, req->ip);
      req->sent = curtime;
      req->times_sent++;
      return 1;
    }
  }
  return 2;
}        


int cache_update(struct sr_arpcache *cache, uint32_t ip, unsigned char* mac ) 
{
    int update = 0;
    pthread_mutex_lock(&(cache->lock));
    struct sr_arpentry* entry = sr_arpcache_lookup(cache, ip);
    if(entry != 0) 
    {
       memcpy(entry->mac, mac, ETHER_ADDR_LEN);
       entry->valid = 1;
       update = 1;
    }
    else
        update = 0;
    pthread_mutex_unlock(&(cache->lock));
    return update;
}


void handle_arp_packet(struct sr_instance *sr, 
                        struct sr_arp_hdr* arp_header, 
                        char *interface )
{
    uint16_t hrd = ntohs( arp_header->ar_hrd );
    uint16_t pro = ntohs( arp_header->ar_pro );
    uint16_t op = ntohs( arp_header->ar_op );

    /*fprintf(stderr, "Received ARP Packet (O = %s) on %s from %s / %s\n", 
                   (op==1)?"Request":(op==2)?"Reply":"???",
                   interface,
                   ip_to_string( arp_header->ar_sip ),
                   hw_addr_to_string( arp_header->ar_sha ) );
     printARPHeader(arp_header);*/


    if( hrd != arp_hrd_ethernet || pro != ethertype_ip || arp_header->ar_hln != ETHER_ADDR_LEN ||
        arp_header->ar_pln != IP_ADDR_LEN || (op != arp_op_request && op != arp_op_reply) ) 
    {
        /*printf("get bad arp packet\n");*/
        return;
    }
    int update = cache_update(&(sr->cache), arp_header->ar_sip, arp_header->ar_sha);

    struct sr_if* interf = sr->if_list;
    while(interf != 0)
    {
      if(strcmp(interf->name, interface) == 0 && arp_header->ar_tip == interf->ip)
      {
        if(update == 0)
        {
          struct sr_arpreq * arp_req = sr_arpcache_insert(&(sr->cache),arp_header->ar_sha, arp_header->ar_sip);
          if(arp_req != 0)
          {
            struct sr_packet *pkt = arp_req->packets;
            while(pkt != 0)
            {
              memcpy( pkt->buf, arp_header->ar_sha, ETHER_ADDR_LEN );
              /*fprintf(stderr, "Sending Ethernet frame from %s (%s) to %s\n",
                     interf->addr,
                     interface,
                     arp_header->ar_sha);
              printAllHeaders(pkt->buf, pkt->len);*/
              sr_send_packet(sr, pkt->buf, pkt->len, interface);
              pkt = pkt->next;
           }
           sr_arpreq_destroy(&(sr->cache), arp_req);
         }
       }
      
       if(op == arp_op_request)
         send_arp_reply(sr, arp_header, interf);
       break;
    }
    interf = interf->next;
  }
}                              
/**************************************/


/* You should not need to touch the rest of this code. */

/* Checks if an IP->MAC mapping is in the cache. IP is in network byte order. 
   You must free the returned structure if it is not NULL. */
struct sr_arpentry *sr_arpcache_lookup(struct sr_arpcache *cache, uint32_t ip) {
    pthread_mutex_lock(&(cache->lock));
    
    struct sr_arpentry *entry = NULL, *copy = NULL;
    
    int i;
    for (i = 0; i < SR_ARPCACHE_SZ; i++) {
        if ((cache->entries[i].valid) && (cache->entries[i].ip == ip)) {
            entry = &(cache->entries[i]);
        }
    }
    
    /* Must return a copy b/c another thread could jump in and modify
       table after we return. */
    if (entry) {
        copy = (struct sr_arpentry *) malloc(sizeof(struct sr_arpentry));
        memcpy(copy, entry, sizeof(struct sr_arpentry));
    }
        
    pthread_mutex_unlock(&(cache->lock));
    
    return copy;
}

/* Adds an ARP request to the ARP request queue. If the request is already on
   the queue, adds the packet to the linked list of packets for this sr_arpreq
   that corresponds to this ARP request. You should free the passed *packet.
   
   A pointer to the ARP request is returned; it should not be freed. The caller
   can remove the ARP request from the queue by calling sr_arpreq_destroy. */
struct sr_arpreq *sr_arpcache_queuereq(struct sr_arpcache *cache,
                                       uint32_t ip,
                                       uint8_t *packet,           /* borrowed */
                                       unsigned int packet_len,
                                       char *iface)
{
    pthread_mutex_lock(&(cache->lock));
    
    struct sr_arpreq *req;
    for (req = cache->requests; req != NULL; req = req->next) {
        if (req->ip == ip) {
            break;
        }
    }
    
    /* If the IP wasn't found, add it */
    if (!req) {
        req = (struct sr_arpreq *) calloc(1, sizeof(struct sr_arpreq));
        req->ip = ip;
        req->next = cache->requests;
        cache->requests = req;
    }
    
    /* Add the packet to the list of packets for this request */
    if (packet && packet_len && iface) {
        struct sr_packet *new_pkt = (struct sr_packet *)malloc(sizeof(struct sr_packet));
        
        new_pkt->buf = (uint8_t *)malloc(packet_len);
        memcpy(new_pkt->buf, packet, packet_len);
        new_pkt->len = packet_len;
    new_pkt->iface = (char *)malloc(sr_IFACE_NAMELEN);
        strncpy(new_pkt->iface, iface, sr_IFACE_NAMELEN);
        new_pkt->next = req->packets;
        req->packets = new_pkt;
    }
    
    pthread_mutex_unlock(&(cache->lock));
    
    return req;
}

/* This method performs two functions:
   1) Looks up this IP in the request queue. If it is found, returns a pointer
      to the sr_arpreq with this IP. Otherwise, returns NULL.
   2) Inserts this IP to MAC mapping in the cache, and marks it valid. */
struct sr_arpreq *sr_arpcache_insert(struct sr_arpcache *cache, 
                                     unsigned char *mac, 
                                     uint32_t ip)
{
    pthread_mutex_lock(&(cache->lock));
    
    struct sr_arpreq *req, *prev = NULL, *next = NULL; 
    for (req = cache->requests; req != NULL; req = req->next) {
        if (req->ip == ip) {            
            if (prev) {
                next = req->next;
                prev->next = next;
            } 
            else {
                next = req->next;
                cache->requests = next;
            }
            
            break;
        }
        prev = req;
    }
    
    int i;
    for (i = 0; i < SR_ARPCACHE_SZ; i++) {
        if (!(cache->entries[i].valid))
            break;
    }
    
    if (i != SR_ARPCACHE_SZ) {
        memcpy(cache->entries[i].mac, mac, 6);
        cache->entries[i].ip = ip;
        cache->entries[i].added = time(NULL);
        cache->entries[i].valid = 1;
    }
    
    pthread_mutex_unlock(&(cache->lock));
    
    return req;
}

/* Frees all memory associated with this arp request entry. If this arp request 
   entry is on the arp request queue, it is removed from the queue. */
void sr_arpreq_destroy(struct sr_arpcache *cache, struct sr_arpreq *entry) {
    pthread_mutex_lock(&(cache->lock));
    
    if (entry) {
        struct sr_arpreq *req, *prev = NULL, *next = NULL; 
        for (req = cache->requests; req != NULL; req = req->next) {
            if (req == entry) {                
                if (prev) {
                    next = req->next;
                    prev->next = next;
                } 
                else {
                    next = req->next;
                    cache->requests = next;
                }
                
                break;
            }
            prev = req;
        }
        
        struct sr_packet *pkt, *nxt;
        
        for (pkt = entry->packets; pkt; pkt = nxt) {
            nxt = pkt->next;
            if (pkt->buf)
                free(pkt->buf);
            if (pkt->iface)
                free(pkt->iface);
            free(pkt);
        }
        
        free(entry);
    }
    
    pthread_mutex_unlock(&(cache->lock));
}

/* Prints out the ARP table. */
void sr_arpcache_dump(struct sr_arpcache *cache) {
    fprintf(stderr, "\nMAC            IP         ADDED                      VALID\n");
    fprintf(stderr, "-----------------------------------------------------------\n");
    
    int i;
    for (i = 0; i < SR_ARPCACHE_SZ; i++) {
        struct sr_arpentry *cur = &(cache->entries[i]);
        unsigned char *mac = cur->mac;
        fprintf(stderr, "%.1x%.1x%.1x%.1x%.1x%.1x   %.8x   %.24s   %d\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], ntohl(cur->ip), ctime(&(cur->added)), cur->valid);
        /*fprintf(stderr, "%.1x%.1x%.1x%.1x%.1x%.1x   %s   %.24s   %d\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], ip_to_string(cur->ip), ctime(&(cur->added)), cur->valid);*/
    }
    
    fprintf(stderr, "\n");
}

/* Initialize table + table lock. Returns 0 on success. */
int sr_arpcache_init(struct sr_arpcache *cache) {  
    /* Seed RNG to kick out a random entry if all entries full. */
    srand(time(NULL));
    
    /* Invalidate all entries */
    memset(cache->entries, 0, sizeof(cache->entries));
    cache->requests = NULL;
    
    /* Acquire mutex lock */
    pthread_mutexattr_init(&(cache->attr));
    pthread_mutexattr_settype(&(cache->attr), PTHREAD_MUTEX_RECURSIVE);
    int success = pthread_mutex_init(&(cache->lock), &(cache->attr));
    
    return success;
}

/* Destroys table + table lock. Returns 0 on success. */
int sr_arpcache_destroy(struct sr_arpcache *cache) {
    return pthread_mutex_destroy(&(cache->lock)) && pthread_mutexattr_destroy(&(cache->attr));
}

/* Thread which sweeps through the cache and invalidates entries that were added
   more than SR_ARPCACHE_TO seconds ago. */
void *sr_arpcache_timeout(void *sr_ptr) {
    struct sr_instance *sr = sr_ptr;
    struct sr_arpcache *cache = &(sr->cache);
    
    while (1) {
        sleep(1.0);
        
        pthread_mutex_lock(&(cache->lock));
    
        time_t curtime = time(NULL);
        
        int i;    
        for (i = 0; i < SR_ARPCACHE_SZ; i++) {
            if ((cache->entries[i].valid) && (difftime(curtime,cache->entries[i].added) > SR_ARPCACHE_TO)) {
                cache->entries[i].valid = 0;
            }
        }
        
        sr_arpcache_sweepreqs(sr);

        pthread_mutex_unlock(&(cache->lock));
    }
    
    return NULL;
}
