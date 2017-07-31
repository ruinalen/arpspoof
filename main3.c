#include "sys/socket.h"
#include "sys/types.h"
#include "stdio.h"
#include "unistd.h"
#include "string.h"
#include "net/if.h"
#include "stdlib.h"
#include "arpa/inet.h"
#include "netinet/in.h"
#include "sys/ioctl.h"
#include "netpacket/packet.h"
#include "net/ethernet.h"
#include "netdb.h"

#define ETHER_TYPE_FOR_ARP 0x0806
#define HW_TYPE_FOR_ETHER 0x0001
#define OP_CODE_FOR_ARP_REQ 0x0001
#define HW_LEN_FOR_ETHER 0x06
#define HW_LEN_FOR_IP 0x04
#define PROTO_TYPE_FOR_IP 0x0800

typedef unsigned char byte1;
typedef unsigned short int byte2;
typedef unsigned long int byte4;

// For Proper memory allocation in the structure
#pragma pack(1)
typedef struct arp_packet
{
// ETH Header
byte1 dest_mac[6];
byte1 src_mac[6];
byte2 ether_type;
// ARP Header
byte2 hw_type;
byte2 proto_type;
byte1 hw_size;
byte1 proto_size;
byte2 arp_opcode;
byte1 sender_mac[6];
byte4 sender_ip;
byte1 target_mac[6];
byte4 target_ip;
// Paddign
char padding[18];
}ARP_PKT;

int print_pkt(char *, int len);

int main(int argc, char *argv[])
{
int arp_fd,if_fd,retVal;
struct sockaddr_in *sin;
struct sockaddr_ll sa;
struct ifreq ifr;
ARP_PKT pkt;
unsigned long int ipAddr;

if( argc != 3 )
{
printf("Usage: ./arp \n");
exit(1);
}
else if( getuid() && geteuid())
{
printf("Oops!\nDude you need SuperUser rights!\n");
exit(1);
}

/*=============================START of IP, MAC ADDRESS ACCESS========================*/

/* Open socket for accessing the IPv4 address of specified Interface */
if_fd = socket(AF_INET, SOCK_STREAM, 0);
if( if_fd < 0 )
{
perror("IF Socket");
exit(1);
}

/* provide interface name to ifreq structure */
memcpy(ifr.ifr_name, argv[1], IF_NAMESIZE);
/* IOCTL to get ip address */
retVal = ioctl(if_fd, SIOCGIFADDR, &ifr, sizeof(ifr));
if( retVal < 0 )
{
perror("IOCTL");
close(if_fd);
exit(1);
}

/* Simple typecasting for easy access to ip address */
sin = (struct sockaddr_in *)&ifr.ifr_addr;
ipAddr = ntohl(sin->sin_addr.s_addr);
#ifdef DBG_ARP
printf("IF Name: %s IP Address: %s ",argv[1], inet_ntoa(sin->sin_addr));
printf("IP = 0x%x\n",ipAddr);
#endif

retVal = ioctl(if_fd, SIOCGIFHWADDR, &ifr, sizeof(ifr));
if( retVal < 0 )
{
perror("IOCTL");
close(if_fd);
exit(1);
}
#ifdef DBG_ARP
printf("MAC address: %s is %02x:%02x:%02x:%02x:%02x:%02x \n",
argv[1],
ifr.ifr_hwaddr.sa_data[0]&0xFF,
ifr.ifr_hwaddr.sa_data[1]&0xFF,
ifr.ifr_hwaddr.sa_data[2]&0xFF,
ifr.ifr_hwaddr.sa_data[3]&0xFF,
ifr.ifr_hwaddr.sa_data[4]&0xFF,
ifr.ifr_hwaddr.sa_data[5]&0xFF);
#endif

/*-----------------------------END of IP,MAC ADDRESS ACCESS------------------------*/

/*=============================Start of ARP request sending====================*/
// Socket to send ARP packet
arp_fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
if( arp_fd == -1 )
{
perror("ARP Socket");
close(if_fd);
exit(1);
}

//====================== Formulate the ARP Packet ============================
// Ethernet Header
memset(pkt.dest_mac, 0xFF, (6 * sizeof(byte1)));
memset(pkt.src_mac, (ifr.ifr_hwaddr.sa_data[0]&0xFF), sizeof(byte1));
memset(pkt.src_mac+1, (ifr.ifr_hwaddr.sa_data[1]&0xFF), sizeof(byte1));
memset(pkt.src_mac+2, (ifr.ifr_hwaddr.sa_data[2]&0xFF), sizeof(byte1));
memset(pkt.src_mac+3, (ifr.ifr_hwaddr.sa_data[3]&0xFF), sizeof(byte1));
memset(pkt.src_mac+4, (ifr.ifr_hwaddr.sa_data[4]&0xFF), sizeof(byte1));
memset(pkt.src_mac+5, (ifr.ifr_hwaddr.sa_data[5]&0xFF), sizeof(byte1));
pkt.ether_type = htons(ETHER_TYPE_FOR_ARP);
// ARP Header
pkt.hw_type = htons(HW_TYPE_FOR_ETHER);
pkt.proto_type = htons(PROTO_TYPE_FOR_IP);
pkt.hw_size = HW_LEN_FOR_ETHER;
pkt.proto_size = HW_LEN_FOR_IP;
pkt.arp_opcode = htons(OP_CODE_FOR_ARP_REQ);
memcpy(pkt.sender_mac, pkt.src_mac, (6 * sizeof(byte1)));
pkt.sender_ip = htonl(ipAddr);
memset(pkt.target_mac, 0 , (6 * sizeof(byte1)));
pkt.target_ip = inet_addr(argv[2]);
// Padding
memset(pkt.padding, 0 , 18 * sizeof(byte1));


// For sending the packet We need it!
retVal = ioctl(if_fd, SIOCGIFINDEX, &ifr, sizeof(ifr));
if( retVal < 0 )
{
perror("IOCTL");
close(arp_fd);
close(if_fd);
exit(1);
}
sa.sll_family = AF_PACKET;
sa.sll_ifindex = ifr.ifr_ifindex;
sa.sll_protocol = htons(ETH_P_ARP);

/* Send it! */
retVal = sendto(arp_fd, &pkt, sizeof(pkt), 0,(struct sockaddr *)&sa, sizeof(sa));
if( retVal < 0 )
{
perror("sendto");
close(arp_fd);
close(if_fd);
exit(1);
}

#ifdef DBG_ARP
printf("\n=========PACKET=========\n");
print_pkt((void *)&pkt, sizeof(pkt));
#endif
return 0;
}

int print_pkt(char *buf, int len)
{
int j = 0;
for(j = 0; j < len; j++ )
{
if((j%16) == 0 && j != 0 )
printf("\n");
printf("%02x ",*(buf+j)& 0xFF );
}
printf("\n");
return 0;
} 
