#include "arp.h"

void arp_print_ipv4(unsigned char tab[4])
{
	long int adresse = 0;
	struct in_addr addr;
	
	//mettre les hex de l'adresse IPv4 dans le long
	for (int i = 0; i < 4; i++) 
	{
		adresse <<= 8;  
		adresse |= tab[i];  
    	}
	addr.s_addr = htonl(adresse);
	char *s = inet_ntoa(addr);
	printf("%s", s);
}


void dechiffrage_arp(const u_char *packet, int size_of_lower_layer, int verbose)
{
	struct ether_arp* partie_arp;
	partie_arp = (struct ether_arp*) (packet + size_of_lower_layer);
	
	if(verbose == 1 || verbose == 2)
	{
		if(verbose == 1)
			printf("ARP ");
		else if(verbose == 2)
		{
			//texte en gras et souligné
			printf("\e[1;4m");
			printf("ARP");

			//remettre le style par défaut
			printf("\033[0m");
			
			printf(" ");
		}
		unsigned short int opcode = htons(partie_arp->ea_hdr.ar_op);
		if(opcode == 1)
			printf("Request (%u)", opcode);
		else if(opcode == 2)
			printf("Reply (%u)", opcode);
	}
	else if(verbose == 3)
	{
		//fond blanc et police noire
		printf("\n\033[1;30;47m");
		printf("Address Resolution Protocol");
		//remettre le style par défaut
   		printf("\033[0m\n");
		
		unsigned short int hardware_format = htons(partie_arp->ea_hdr.ar_hrd);
		if(hardware_format == 1)
			printf("\tHardware type: Ethernet (%u)\n", hardware_format);
		else printf("\tHardware type: %u\n", hardware_format);
			
		unsigned short int protocol_format = htons(partie_arp->ea_hdr.ar_pro);
		if(protocol_format == 0x0800)
			printf("\tProtocol type: IPv4 (%.4x)\n", protocol_format);
		else printf("\tProtocol type: %.4x\n", protocol_format);

		printf("\tHardware address length: %u\n", partie_arp->ea_hdr.ar_hln);
		printf("\tProtocol address length: %u\n", partie_arp->ea_hdr.ar_pln);
		
		printf("\tOperation: ");
		unsigned short int opcode = htons(partie_arp->ea_hdr.ar_op);
		if(opcode == 1)
			printf("Request (%u)\n", opcode);
		else if(opcode == 2)
			printf("Reply (%u)\n", opcode);
		
		printf("\tSender hardware address: ");
		for(int i = 0; i < ETH_ALEN; i++)
		{
			printf("%.2x", partie_arp->arp_sha[i]);
			if(i < ETH_ALEN - 1)
				printf(":");
		}
		printf("\n");
		
		printf("\tSender IP address: ");
		arp_print_ipv4(partie_arp->arp_spa);
		printf("\n");
		
		printf("\tTarget hardware address: ");
		for(int i = 0; i < ETH_ALEN; i++)
		{
			printf("%.2x", partie_arp->arp_tha[i]);
			if(i < ETH_ALEN - 1)
				printf(":");
		}
		printf("\n");
		
		printf("\tTarget IP address: ");
		arp_print_ipv4(partie_arp->arp_tpa);
	}
}
