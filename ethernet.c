#include "ethernet.h"
#include "ipv4.h"
#include "ipv6.h"
#include "arp.h"

void dechiffrage_ethernet(const u_char *packet, const struct pcap_pkthdr *header, int verbose)
{
	struct ether_header* partie_ethernet;
	partie_ethernet = (struct ether_header*) packet;
	
	int size_ethernet = sizeof(struct ether_header);
	
	if(verbose == 1)
	{
		printf("Ethernet/");
	}
	else if(verbose == 2)
	{
		//texte en gras et souligné
		printf("\e[1;4m");
		printf("Ethernet");

		//remettre le style par défaut
		printf("\033[0m");
		
		printf(", ");
		
		printf("Src: ");
		for(int i = 0; i < ETH_ALEN; i++)
		{
			printf("%.2x", partie_ethernet->ether_shost[i]);
			if(i < ETH_ALEN - 1)
				printf(":");
		}
		printf(", Dst: ");
		for(int i = 0; i < ETH_ALEN; i++)
		{
			printf("%.2x", partie_ethernet->ether_dhost[i]);
			if(i < ETH_ALEN - 1)
				printf(":");
		}
		printf("\n");
	}
	else if(verbose == 3)
	{
		//fond blanc et police noire
		printf("\n\033[1;30;47m");
		printf("Ethernet");
		//remettre le style par défaut
   		printf("\033[0m\n");

		printf("\tAdresse dest Ethernet: ");
		for(int i = 0; i < ETH_ALEN; i++)
		{
			printf("%.2x", partie_ethernet->ether_dhost[i]);
			if(i < ETH_ALEN - 1)
				printf(":");
		}
		printf("\n");
		
		printf("\tAdresse source Ethernet: ");
		for(int i = 0; i < ETH_ALEN; i++)
		{
			printf("%.2x", partie_ethernet->ether_shost[i]);
			if(i < ETH_ALEN - 1)
				printf(":");
		}
		printf("\n");
	}
	u_int16_t ethertype = ntohs(partie_ethernet->ether_type);
	
	if(ethertype == ETHERTYPE_IP) //IPv4
	{
		if(verbose == 3)
			printf("\tEthertype: IPv4 (%.4x)\n", ntohs(partie_ethernet->ether_type));
			
		dechiffrage_ipv4(packet, size_ethernet, header, false, verbose);
	}
	else if(ethertype == ETHERTYPE_IPV6) //IPv6
	{
		if(verbose == 3)
			printf("\tEthertype: IPv6 (%.4x)\n", ntohs(partie_ethernet->ether_type));
			
		dechiffrage_ipv6(packet, size_ethernet, header, verbose);
	}
	else if(ethertype == ETHERTYPE_ARP) //ARP
	{
		if(verbose == 3)
			printf("\tEthertype: ARP (%.4x)\n", ntohs(partie_ethernet->ether_type));
			
		dechiffrage_arp(packet, size_ethernet, verbose);
	}
}
