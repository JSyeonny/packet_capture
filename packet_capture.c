#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pcap.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>	
#include <libnet-headers.h>

int main(int argc, char **argv)
{
	int i;
	char *dev;
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *descr;
	const u_char *packet;
	const u_char *packet2;
	struct pcap_pkthdr hdr;			
	
	struct libnet_ethernet_hdr *eptr; // libnet-headers.h
	struct libnet_ipv4_hdr *iptr;
	struct libnet_ipv4_hdr ip_hdr;
	struct libnet_tcp_hdr *tptr;


	u_char *ptr;
	
	// 잡을 디바이스 설정
	dev=pcap_lookupdev(errbuf);	
	if(dev == NULL)
	{
		printf("%s\n", errbuf);
		exit(1);
	}
	
	printf("DEV: %s\n", dev);
	
	while(1)
	{
		// 캡쳐할 디바이스 열기
		descr = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
		if (descr == NULL)
		{
			printf("pcap_open_live(): %s\n", errbuf);
			exit(1);
		}
	
		// 패킷 캡쳐
		packet = pcap_next(descr, &hdr);
		if (packet == NULL)
		{
			printf("\n\nDidn't grab packet\n\n");
			continue;
		}
	
	
	
	
		eptr = (struct libnet_ethernet_hdr *)packet;

			
		packet2 = packet + sizeof(struct libnet_ethernet_hdr);
		iptr = (struct libnet_ipv4_hdr *)packet2;

		if(iptr->ip_p == IPPROTO_TCP){
			printf("=============================================\n");
			printf("Ethernet type hex:%x dec:%d is an IP packet\n\n", ntohs(eptr->ether_type),ntohs(eptr->ether_type));
			
	
			// Src MAC
			ptr = eptr->ether_shost;
        		i = ETHER_ADDR_LEN;

        		printf("Src MAC : ");
        		while(i>0){
                		printf("%s%x", ( i == ETHER_ADDR_LEN ) ? " " : ":", *ptr++);
        			i--;
			}
 	      		printf("\n");

			// Dst MAC
			ptr = eptr->ether_dhost;
       			i = ETHER_ADDR_LEN;

       			printf("Dst MAC : ");
       			while(i>0){
               			printf("%s%x", ( i == ETHER_ADDR_LEN) ? " " : ":", *ptr++);
      				i--;
			}
  			
			printf("\n\n");
	

			// Src IP & Dst IP
			printf("Src IP : %s\n", inet_ntoa(iptr->ip_src));
			printf("Dst IP : %s\n\n", inet_ntoa(iptr->ip_dst));


			// Src Port & Dst Port
       			tptr = (struct libnet_tcp_hdr *)(packet + 32);

			printf("Src Port : %d\n" , ntohs(tptr->th_sport));
       			printf("Dst Port : %d\n" , ntohs(tptr->th_dport));

			sleep(1);
		}
	}

	return 0;
}
