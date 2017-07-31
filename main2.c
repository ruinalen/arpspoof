#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <asm/types.h>
#include <math.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>

#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/if_arp.h>

#define PROTO_ARP 0x0806
#define ETH2_HEADER_LEN 14
#define HW_TYPE 1
#define PROTOCOL_TYPE 0x800
#define MAC_LENGTH 6
#define IPV4_LENGTH 4
#define ARP_REQUEST 0x01
#define ARP_REPLY 0x02
#define BUF_SIZE 60

struct arp_header /* arp 헤더 구조체 선언 */
{
        unsigned short hardware_type;
        unsigned short protocol_type;
        unsigned char hardware_len;
        unsigned char  protocol_len;
        unsigned short opcode;
        unsigned char sender_mac[MAC_LENGTH];
        unsigned char sender_ip[IPV4_LENGTH];
        unsigned char target_mac[MAC_LENGTH];
        unsigned char target_ip[IPV4_LENGTH];
};

int main(int argc, char* argv[]) /* 인자 값을 우선은 하드 코딩해서 보내기로 함*/
{
        int sd;
	int i = 0;
	unsigned char source_ip[4] = {111,111,111,111};
        unsigned char target_ip[4] = {111,111,111,111};

	char *source_ip_strtok=argv[2];
	char *target_ip_strtok=argv[3];
	
	printf("첫번째 인자 값 : %s\n",source_ip_strtok);	//인자값 확인
	printf("두번째 인자 값 : %s\n",target_ip_strtok);	//인자값 확인

        unsigned char buffer[BUF_SIZE];
	
        struct ifreq ifr;	/*내 NIC 의 맥 주소를 받기 위한 구조체*/
        struct ethhdr *send_req = (struct ethhdr *)buffer;	/*패킷 송출을 위한 이더넷 헤더 구조체 할당*/
        struct ethhdr *rcv_resp= (struct ethhdr *)buffer;	/*패킷 수신을 위한 이더넷 헤더 구조체 할당*/
        struct arp_header *arp_req = (struct arp_header *)(buffer+ETH2_HEADER_LEN);	/*ARP 패킷을 보내기 위한 헤더 구조체 할당*/
        struct arp_header *arp_resp = (struct arp_header *)(buffer+ETH2_HEADER_LEN);	/*ARP 패킷을 수신하기 위한 헤더 구조체 할당*/
        struct sockaddr_ll socket_address;	/*sendto 함수를 위한 주소 값 저장 변수*/
        int index,ret,length=0,ifindex;		/*기본 인덱스 변수들 선언*/
	memset(buffer,0x00,60); /*버퍼 초기화*/


        sd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));/*소켓 생성*/
        strcpy(ifr.ifr_name,argv[1]); /*인터페이스를 첫번째 인자값으로 받기*/

	if (ioctl(sd, SIOCGIFINDEX, &ifr) == -1) {
	perror("SIOCGIFINDEX");
	exit(1);
    	}

    	ifindex = ifr.ifr_ifindex;
	printf("interface index is %d\n",ifindex);

        /*retrieve corresponding MAC*/
        if (ioctl(sd, SIOCGIFHWADDR, &ifr) == -1) {
                perror("SIOCGIFINDEX");
                exit(1);
        }
	close (sd);

        for (index = 0; index < 6; index++)/*맥주소를 받아오기 위한 for 문*/
        {

                send_req->h_dest[index] = (unsigned char)0xff;/*브로드캐스팅할 맥주소*/
                arp_req->target_mac[index] = (unsigned char)0x00;/**/
                /* Filling the source  mac address in the header*/
                send_req->h_source[index] = (unsigned char)ifr.ifr_hwaddr.sa_data[index];/**/
                arp_req->sender_mac[index] = (unsigned char)ifr.ifr_hwaddr.sa_data[index];/**/
                socket_address.sll_addr[index] = (unsigned char)ifr.ifr_hwaddr.sa_data[index];/*내 맥주소*/
        }
        printf("MAC address: %02X:%02X:%02X:%02X:%02X:%02X\n",
                        send_req->h_source[0],send_req->h_source[1],send_req->h_source[2],
                        send_req->h_source[3],send_req->h_source[4],send_req->h_source[5]);
        printf(" arp_req MAC address: %02X:%02X:%02X:%02X:%02X:%02X\n",
                        arp_req->sender_mac[0],arp_req->sender_mac[1],arp_req->sender_mac[2],
                        arp_req->sender_mac[3],arp_req->sender_mac[4],arp_req->sender_mac[5]);
        printf("socket_address MAC address: %02X:%02X:%02X:%02X:%02X:%02X\n",
                        socket_address.sll_addr[0],socket_address.sll_addr[1],socket_address.sll_addr[2],
                        socket_address.sll_addr[3],socket_address.sll_addr[4],socket_address.sll_addr[5]);

        /*prepare sockaddr_ll*/
        socket_address.sll_family = AF_PACKET;
        socket_address.sll_protocol = htons(ETH_P_ARP);
        socket_address.sll_ifindex = ifindex;
        socket_address.sll_hatype = htons(ARPHRD_ETHER);
        socket_address.sll_pkttype = (PACKET_BROADCAST);
        socket_address.sll_halen = MAC_LENGTH;
        socket_address.sll_addr[6] = 0x00;
        socket_address.sll_addr[7] = 0x00;

        /* Setting protocol of the packet */
        send_req->h_proto = htons(ETH_P_ARP);

        /* Creating ARP request */
        arp_req->hardware_type = htons(HW_TYPE);/* 1 */
        arp_req->protocol_type = htons(ETH_P_IP);/* 0x0800 */
        arp_req->hardware_len = MAC_LENGTH;/* 6 */
        arp_req->protocol_len =IPV4_LENGTH;/* 4 */
        arp_req->opcode = htons(ARP_REQUEST);/* 1 */
        for(index=0;index<5;index++)
        {
                arp_req->sender_ip[index]=(unsigned char)source_ip[index];
                arp_req->target_ip[index]=(unsigned char)target_ip[index];
        }
	// Submit request for a raw socket descriptor.
	if ((sd = socket (PF_PACKET, SOCK_RAW, htons (ETH_P_ALL))) < 0) { /*소켓 오픈 실패시*/
		perror ("socket() failed ");
		exit (EXIT_FAILURE);
	}

	buffer[32]=0x00;
        ret = sendto(sd, buffer, 42, 0, (struct  sockaddr*)&socket_address, sizeof(socket_address));
        if (ret == -1)
        {
                perror("sendto():");
                exit(1);
        }
        else
        {
                printf(" Sent the ARP REQ \n\t");
                for(index=0;index<42;index++)
                {
                        printf("%02X ",buffer[index]);
                        if(index % 16 ==0 && index !=0)
                        {printf("\n\t");}
                }
        }
printf("\n\t");
        memset(buffer,0x00,60);
        while(1)
        {
                length = recvfrom(sd, buffer, BUF_SIZE, 0, NULL, NULL);
                if (length == -1)
                {
                        perror("recvfrom():");
                        exit(1);
                }
                if(htons(rcv_resp->h_proto) == PROTO_ARP)
                {
                        //if( arp_resp->opcode == ARP_REPLY )
                        printf(" RECEIVED ARP RESP len=%d \n",length);
                        printf(" Sender IP :");
                        for(index=0;index<4;index++)
                                printf("%u.",(unsigned int)arp_resp->sender_ip[index]);

                        printf("\n Sender MAC :");
                        for(index=0;index<6;index++)
                                printf(" %02X:",arp_resp->sender_mac[index]);

                        printf("\nReceiver  IP :");
                        for(index=0;index<4;index++)
                                printf(" %u.",arp_resp->target_ip[index]);

                        printf("\n Self MAC :");
                        for(index=0;index<6;index++)
                                printf(" %02X:",arp_resp->target_mac[index]);

                        printf("\n  :");

                        break;
                }
        }

        return 0;
}
