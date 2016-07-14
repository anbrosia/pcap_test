#include <stdio.h> 
#include <stdlib.h>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h> 
#include <arpa/inet.h>
#include <netinet/if_ether.h>

char *dev;

void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data){

   struct ethhdr *eth;
   struct iphdr *iph;
   struct tcphdr *tcph;
   struct ether_header *eh;
   struct ip *ip;

   eth = (struct ethhdr *)pkt_data;
   eh = (struct ether_header *)pkt_data;

   if(ntohs(eh->ether_type) == ETHERTYPE_IP){
	iph = (struct iphdr *)(pkt_data + sizeof(struct ethhdr));
	ip = (struct ip *)(pkt_data + sizeof(struct ether_header));
	if(ip->ip_p == IPPROTO_TCP){
	   tcph = (struct tcphdr*)(pkt_data + (ip->ip_hl) * 4 + sizeof(struct ethhdr));
	   printf("[ Device : %s ]", dev);

	   printf("\n  eth.smac  ");
	   for(int i=0; i<6; i++){
		printf("%02x", eth->h_source[i]);
		if(i!=5){
		   printf(" : ");
		}
	   }

	   printf("\n  eth.dmac  ");
	   for(int i=0; i<6; i++){
		printf("%02x", eth->h_dest[i]);
		if(i!=5){
		   printf(" : ");
		}
	   }

	   printf("\n  ip.sip    %s", inet_ntoa(*(struct in_addr *)&iph->saddr));
	   printf("\n  ip.dip    %s", inet_ntoa(*(struct in_addr *)&iph->daddr));
	   printf("\n  tcp.sport %u", ntohs(tcph->source));
	   printf("\n  tcp.dport %u\n", ntohs(tcph->dest));
	}
   }
   else
	exit(1);
}

int main(int argc, char *argv[]){
   char errbuf[PCAP_ERRBUF_SIZE];
   pcap_t* handler;

   dev = pcap_lookupdev(errbuf);
   if(dev == NULL){
	printf("%s\n", errbuf);
	exit(1);
   }

   handler = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
   if(handler == NULL){
	printf("%s\n", errbuf);
	exit(1);
   }

   pcap_loop(handler, 0, packet_handler, NULL);

   return 0;
}

