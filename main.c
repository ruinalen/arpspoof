#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>

#define CMD_BUF_SIZE 256
#define IP_ADDR_BUF_SIZE 20
#define MAC_ADDR_BUF_SIZE 25
#define GATE_ADDR_BUF_SIZE 20
#define PACK_BUF_SIZE 1024 * 64
#define PCAP_ERR_BUF_SIZE 1024
#define SEND_BUF_SIZE 512

#include <stdlib.h>
#include <stdio.h>

#define CMD_BUF_SIZE 256
int get_my_mac_str(char *ifname, char *str, int len) {
	FILE* fp;
	char cmdbuf[CMD_BUF_SIZE];
	sprintf(cmdbuf, "/bin/bash -c \"ifconfig %s\" | grep \"inet \" | awk '{print $2}'\n", ifname);
	fp = popen(cmdbuf, "r");
	if (fp == NULL) {
		perror("Fail to fetch mac address\n");
		return EXIT_FAILURE;
	}
	fgets(str, len, fp);
	pclose(fp);
	return EXIT_SUCCESS;
}
int get_my_ip_str(char *ifname, char *str, int len) {
	FILE* fp;
	char cmdbuf[CMD_BUF_SIZE];
	sprintf(cmdbuf, "/bin/bash -c \"ifconfig %s\" | grep '[ ][0-9a-zA-Z][0-9a-zA-Z]:[0-9a-zA-Z][0-9a-zA-Z]:[0-9a-zA-Z][0-9a-zA-Z]:[0-9a-zA-Z][0-9a-zA-Z]:[0-9a-zA-Z][0-9a-zA-Z]:[0-9a-zA-Z][0-9a-zA-Z]' | awk '{print $2}'", ifname);
	fp = popen(cmdbuf, "r");
	if (fp == NULL) {
		perror("Fail to fetch IPv4 address\n");
		return EXIT_FAILURE;
	}
	fgets(str, len, fp);
	pclose(fp);
	return EXIT_SUCCESS;
}
int get_my_gateway_str(char *ifname, char *str, int len) {
	FILE* fp;
	char cmdbuf[CMD_BUF_SIZE];
	sprintf(cmdbuf, "/bin/bash -c 'route -n' | grep G | grep %s | awk '{print $2}'", ifname);
	fp = popen(cmdbuf, "r");
	if (fp == NULL) {
		perror("Fail to fetch gateway address\n");
		return EXIT_FAILURE;
	}
	fgets(str, len, fp);
	pclose(fp);
	return EXIT_SUCCESS;
}


int main(int argc, char* argv[]) {
	pcap_t *handle;
	char opt_verbose = 0;
	struct ether_header* eth_hdr;
	struct ether_arp* arp_hdr;
	u_char send_buf[SEND_BUF_SIZE];
	char errbuf[PCAP_ERR_BUF_SIZE];
	char my_ip_addr_str[IP_ADDR_BUF_SIZE];
	char my_mac_addr_str[MAC_ADDR_BUF_SIZE];
	char *ifname = NULL; //interface name
	char *victim_ip_addr_str = NULL; //victim ip address string
	char *target_ip_addr_str = NULL;
	if (argc < 4) {
		fprintf(stderr, "Usage: %s [-options] [Interface name] [victim IP] [target IP]\n", argv[0]);
		fprintf(stderr, "\t[options]\n\t\t-v : verbose mode\n");
		return EXIT_FAILURE;
	}
	for(int cnt = 1; cnt < argc; cnt++) {
		if (argv[cnt][0] == '-') {
			switch(argv[cnt][1]) {
				case 'v':
				opt_verbose = 1;
				break;
			}
		} else {
			if (ifname == NULL) {
				ifname = argv[cnt];
			} else if (victim_ip_addr_str == NULL) {
				victim_ip_addr_str = argv[cnt];
			} else {
				target_ip_addr_str = argv[cnt];
			}
		}
	}

	if (opt_verbose) {
		printf("ifname: %s\n", ifname);
		printf("victim_ip_addr_str: %s\n", victim_ip_addr_str);
		printf("target_ip_addr_str: %s\n", target_ip_addr_str);
	}

	if (get_my_mac_str(ifname, my_ip_addr_str, sizeof(my_ip_addr_str) - 1) == EXIT_FAILURE) {
		perror("Fail to fetch IPv4 address\n");
	 	exit(EXIT_FAILURE);
	}
	if (opt_verbose) {
		printf("My IPv4 addr: %s\n", my_ip_addr_str);
	}

	if (get_my_ip_str(ifname, my_mac_addr_str, sizeof(my_mac_addr_str) - 1) == EXIT_FAILURE) {
		perror("Fail to fetch Mac address\n");
		exit(EXIT_FAILURE);
	}
	if (opt_verbose) {
		printf("My Mac addr: %s\n", my_mac_addr_str);
	}

	handle = pcap_open_live(ifname, PACK_BUF_SIZE, 0, 1000, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "Cannot open device %s: %s\n", ifname, errbuf);
		exit(EXIT_FAILURE);
	}	
	if (opt_verbose) {
		printf("Open device [%s]\n", ifname);
	}

	// if (get_my_gateway_str(ifname, my_defgw_addr_str, sizeof(my_defgw_addr_str) - 1) == EXIT_FAILURE) {
	// 	perror("Fail to fetch default gateway\n");
	// 	exit(EXIT_FAILURE);
	// }
	// printf("My default Gateway addr: %s\n", my_defgw_addr_str);

	eth_hdr = (struct ether_header*)send_buf;
	sscanf("ff:ff:ff:ff:ff:ff", "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &eth_hdr->ether_dhost[0], &eth_hdr->ether_dhost[1], &eth_hdr->ether_dhost[2], &eth_hdr->ether_dhost[3], &eth_hdr->ether_dhost[4], &eth_hdr->ether_dhost[5]);
	if (opt_verbose) {
		printf("PACKET Dst MAC addr - %02X:%02X:%02X:%02X:%02X:%02X\n", eth_hdr->ether_dhost[0], eth_hdr->ether_dhost[1], eth_hdr->ether_dhost[2], eth_hdr->ether_dhost[3], eth_hdr->ether_dhost[4], eth_hdr->ether_dhost[5]);
	}

	sscanf(my_mac_addr_str, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &eth_hdr->ether_shost[0], &eth_hdr->ether_shost[1], &eth_hdr->ether_shost[2], &eth_hdr->ether_shost[3], &eth_hdr->ether_shost[4], &eth_hdr->ether_shost[5]);
	if (opt_verbose) {
		printf("PACKET Src MAC addr - %02X:%02X:%02X:%02X:%02X:%02X\n", eth_hdr->ether_shost[0], eth_hdr->ether_shost[1], eth_hdr->ether_shost[2], eth_hdr->ether_shost[3], eth_hdr->ether_shost[4], eth_hdr->ether_shost[5]);
	}
	eth_hdr->ether_type = ntohs(ETHERTYPE_ARP);
	if (opt_verbose) {
		printf("PACKET Ether type - %02X", (u_char)eth_hdr->ether_type);
		u_char *tmp = (u_char*)&eth_hdr->ether_type;
		tmp++;
		printf("%02X\n",*tmp);
	}
	arp_hdr = (struct ether_arp*)(send_buf + sizeof(struct ether_header));
	arp_hdr->ea_hdr.ar_hrd = ntohs(0x0001);
	arp_hdr->ea_hdr.ar_pro = ntohs(0x0800);
	arp_hdr->ea_hdr.ar_hln = 6;
	arp_hdr->ea_hdr.ar_pln = 4;
	arp_hdr->ea_hdr.ar_op = ntohs(0x0001);

	sscanf(my_mac_addr_str, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &arp_hdr->arp_sha[0], &arp_hdr->arp_sha[1], &arp_hdr->arp_sha[2], &arp_hdr->arp_sha[3], &arp_hdr->arp_sha[4], &arp_hdr->arp_sha[5]);
	sscanf(my_ip_addr_str, "%hhd.%hhd.%hhd.%hhd", &arp_hdr->arp_spa[0], &arp_hdr->arp_spa[1], &arp_hdr->arp_spa[2], &arp_hdr->arp_spa[3]);
	sscanf("00:00:00:00:00:00", "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &arp_hdr->arp_tha[0], &arp_hdr->arp_tha[1], &arp_hdr->arp_tha[2], &arp_hdr->arp_tha[3], &arp_hdr->arp_tha[4], &arp_hdr->arp_tha[5]);
	sscanf(victim_ip_addr_str, "%hhd.%hhd.%hhd.%hhd", &arp_hdr->arp_tpa[0], &arp_hdr->arp_tpa[1], &arp_hdr->arp_tpa[2], &arp_hdr->arp_tpa[3]);

	if (opt_verbose) {
		int len = sizeof(struct ether_header) + sizeof(struct ether_arp);
		for (int i=0; i < len; i++) {
			printf("%02X ", send_buf[i]);
			if (i % 16 == 15) putchar('\n');
			else if (i % 8 == 7) putchar(' ');
		}
		putchar('\n');
	}
	int pack_len = sizeof(struct ether_header) + sizeof(struct ether_arp);
	if (pcap_sendpacket(handle, send_buf, pack_len) == -1) {
		fprintf(stderr, "pcap_sendpacket err %s\n", pcap_geterr(handle));
		exit(EXIT_FAILURE);
	}

}
