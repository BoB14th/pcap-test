#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <arpa/inet.h>
#include "pcap-test.h"

#define SIZE_ETHERNET 14

void usage() {
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
}

typedef struct {
	char* dev_;
} Param;

Param param = {
	.dev_ = NULL
};

const Ethernet *eth;
const Ip *ip;
const Tcp *tcp;

bool parse(Param* param, int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	return true;
}

void getEthAddr(const Ethernet *eth){
	printf("Src MAC: ");
	for (int i = 0; i < 6; i++)
	{
			printf("%02x", eth->src_addr[i]);
			if (i != 5)
				printf(":");
	}
	printf("\n");
	printf("Dst MAC: ");
	for (int i = 0; i < 6; i++)
	{
			printf("%02x", eth->dst_addr[i]);
			if (i != 5)
				printf(":");
	}
	printf("\n");
}

void getIpAddr(const Ip *ip){
	uint32_t src_addr, dst_addr;

	src_addr = ip->src_addr;
	dst_addr = ip->dst_addr;

	uint8_t *p = (uint8_t*)&src_addr;
	printf("Src IP: ");
	for (int i = 0; i < 4; i++){
		printf("%d", *(p+i));
		if (i != 3)
			printf(".");
	}
	printf("\n");

	p = (uint8_t*)&dst_addr;
	printf("Dst IP: ");
	for (int i = 0; i < 4; i++){
		printf("%d", *(p+i));
		if (i != 3)
			printf(".");
	}
	printf("\n");
}

void getPayload(const u_char* packet, int len){
	if (len > 20) len = 20;
	for (int i=0; i < len; i++){
		printf("%02x ", *(packet+i));
	}
	printf("\n");
}

void getTcpAddr(const Tcp *tcp){
	uint16_t src_p, dst_p;

	src_p = htons(tcp->src_p);
	dst_p = htons(tcp->dst_p);

	printf("Src Port: %d\n", src_p);
	printf("Dst Port: %d\n", dst_p);
}

void analysis_packet(const u_char* packet, struct pcap_pkthdr* header, const Ethernet *eth, const Ip *ip, const Tcp *tcp){
	int pay_len;
	const u_char* payload;
	
	if (htons(eth->ether_type) != 0x0800) return;
	
	printf("%u bytes captured\n", header->caplen);
	
	getEthAddr(eth);
	getIpAddr(ip);
	getTcpAddr(tcp);
	
	pay_len = SIZE_ETHERNET + IP_HL(ip)*4 + TCP_OFFSET(tcp)*4;
	payload = packet + pay_len;
	getPayload(payload, header->caplen - pay_len);
	printf("===============\n");
}

int main(int argc, char* argv[]) {
	if (!parse(&param, argc, argv))
		return -1;

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}
	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}

		eth = (Ethernet*)(packet);
		ip = (Ip*)(packet + SIZE_ETHERNET);
		tcp = (Tcp*)(packet + SIZE_ETHERNET + IP_HL(ip)*4);
		
		analysis_packet(packet, header, eth, ip, tcp);
	}

	pcap_close(pcap);
}
