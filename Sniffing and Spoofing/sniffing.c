#include <pcap.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <ctype.h>

struct ethheader {
	u_char ether_dhost[6];
	u_char ether_shost[6];
	u_short ether_type;
};

struct ipheader {
	unsigned char iph_ihl:4, iph_ver:4;
	unsigned char iph_tos;
	unsigned short int iph_len;
	unsigned short int iph_ident;
	unsigned short int iph_flag:3, iph_offset:13;
	unsigned char iph_ttl;
	unsigned char iph_protocol;
	unsigned short int iph_chksum;
	struct in_addr iph_sourceip;
	struct in_addr iph_destip;
};

typedef u_int tcp_seq;

struct tcpheader {
	u_short th_sport;
	u_short th_dport;
	tcp_seq th_seq;
	tcp_seq th_ack;
	u_char th_offx2;
	u_char th_flags;
	u_short th_win;
	u_short th_sum;
	u_short th_urp;
};

/* This function will be invoked by pcap for each captured packet.
We can process each packet inside the function.
*/
void got_packet(u_char *args, const struct pcap_pkthdr *header,
const u_char *packet) {
	int i = 0;
	int data_size = 0;
	
	struct ethheader *eth = (struct ethheader *) packet;
	
	if(ntohs(eth->ether_type) == 0x0800) {
		struct ipheader * ip = (struct ipheader *) (packet + sizeof(struct ethheader));
		printf("From: %s\n", inet_ntoa(ip->iph_sourceip));
		printf("To: %s\n", inet_ntoa(ip->iph_destip));
		/*
		struct tcpheader * tcp = (struct tcpheader *) (packet + sizeof(struct ethheader) + (ip->iph_ihl * 4));
		printf("From: %d\n", ntohs(tcp->th_sport));
		printf("To: %d\n", ntohs(tcp->th_dport));*/
		
		switch(ip->iph_protocol) {
			case IPPROTO_TCP:
				printf("Protocol: TCP\n");
				break;
			case IPPROTO_UDP:
				printf("Protocol: UDP\n");
				break;
			case IPPROTO_ICMP:
				printf("Protocol: ICMP\n");
				break;
			default:
				printf("Protocl: Other\n");
				break;
		}
		/*
		char *data = (u_char *) packet + sizeof(struct ethheader) + (ip->iph_ihl * 4) + ((tcp->th_offx2 & 0xf0) >> 4);

		for(int i = 0; i < 1024; i++) {
			if(isprint(*data)){ 
			printf("%c", *data);}
			else{
			printf(".");}
			data++;
		}*/


		
	}
}

int main() {
	pcap_t *handle;
	char errbuf[PCAP_ERRBUF_SIZE];
	struct bpf_program fp;
	char filter_exp[] = "proto icmp and src host 10.0.2.4 and dst 10.9.0.1";
	bpf_u_int32 net;
	
	// Step 1: Open live pcap session on NIC with name eth3
	// Students needs to change "eth3" to the name
	// found on their own machines (using ifconfig).
	handle = pcap_open_live("lo", BUFSIZ, 1, 1000, errbuf);
	
	// Step 2: Compile filter_exp into BPF psuedo-code
	pcap_compile(handle, &fp, filter_exp, 0, net);
	pcap_setfilter(handle, &fp);
	
	// Step 3: Capture packets
	pcap_loop(handle, -1, got_packet, NULL);
	pcap_close(handle); //Close the handle
	
	return 0;
}
// Note: don’t forget to add "-lpcap" to the compilation command.
// For example: gcc -o sniff sniff.c -lpcap
