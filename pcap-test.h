#pragma once
#include <stdint.h>
#define ETH_MAC_ADDR 6

typedef struct {
    uint8_t dst_addr[ETH_MAC_ADDR];
    uint8_t src_addr[ETH_MAC_ADDR];
    uint16_t ether_type;
} Ethernet;

typedef struct {
    uint8_t v_hl; // version & IHL
    uint8_t tos;
    uint16_t len;
    uint16_t id;
    uint16_t fl_off;
    uint8_t ttl;
    uint8_t p; // protocol
    uint16_t checksum;
    uint32_t src_addr;
    uint32_t dst_addr;
} Ip;

#define IP_HL(ip)		(((ip)->v_hl) & 0x0f)

typedef struct {
    uint16_t src_p;
    uint16_t dst_p;
    uint32_t seq_num;
    uint32_t ack_num;
    uint8_t off_res;
    uint8_t flags;
    uint16_t window;
    uint16_t checksum;
    uint16_t urg_p;
} Tcp;

#define TCP_OFFSET(tcp)    (((tcp)->off_res) >> 4)