#include "udp.h"
//protocoles applicatifs
#include "mon_bootp.h"
#include "dns.h"
#include "tftp.h"


void gere_partie_applicative_udp(struct udphdr* partie_udp, const u_char *packet, int size_of_lower_layer, const struct pcap_pkthdr *header, int verbose)
{
	if((htons(partie_udp->source) == PORT_BOOTP_SERVEUR && htons(partie_udp->dest) == PORT_BOOTP_CLIENT)
	|| (htons(partie_udp->source) == PORT_BOOTP_CLIENT && htons(partie_udp->dest) == PORT_BOOTP_SERVEUR))
	{
		dechiffrage_bootp(packet, size_of_lower_layer + sizeof(struct udphdr), header, verbose);
	}
	else if(htons(partie_udp->source) == PORT_DNS_UDP || htons(partie_udp->dest) == PORT_DNS_UDP)
	{
		dechiffrage_dns(packet, size_of_lower_layer + sizeof(struct udphdr), header, verbose);
	}
	else if(htons(partie_udp->source) == PORT_TFTP || htons(partie_udp->dest) == PORT_TFTP)
	{
		dechiffrage_tftp(packet, size_of_lower_layer + sizeof(struct udphdr), header, verbose);
	}
	else
	{
		if(verbose == 3)
		{
			//fond blanc et police noire
			printf("\n\033[1;30;47m");
			
			printf("Protocole applicatif inconnu...");
			
			//remettre le style par défaut
	   		printf("\033[0m\n");
		}
	}
}


void dechiffrage_udp(const u_char *packet, int size_of_lower_layer, const struct pcap_pkthdr *header, bool is_icmp, int verbose)
{
	struct udphdr* partie_udp;
	partie_udp = (struct udphdr*) (packet + size_of_lower_layer);
	
	if(verbose == 1)
	{
		printf("UDP/");
	}
	else if(verbose == 2)
	{
		//texte en gras et souligné
		printf("\e[1;4m");
		printf("UDP");

		//remettre le style par défaut
		printf("\033[0m");
		
		printf(", ");
	
		printf("Port source: %u, ", htons(partie_udp->source));
		printf("Port dest: %u\n", htons(partie_udp->dest));
	}
	else if(verbose == 3)
	{
		//fond blanc et police noire
		printf("\n\033[1;30;47m");
		
		printf("User Datagram Protocol");
		
		//remettre le style par défaut
   		printf("\033[0m\n");
		
		printf("\tPort source: %u\n", htons(partie_udp->source));
		printf("\tPort dest: %u\n", htons(partie_udp->dest));
		printf("\tLength: %u\n", htons(partie_udp->len));
		printf("\tChecksum: %.4x\n", htons(partie_udp->check));
	}
	
	if(is_icmp == false)
	{
		//gérer la partie applicative uniquement s'il reste des données dans le paquet
		if((unsigned char*) (&partie_udp->check) + sizeof(partie_udp->check) < &packet[header->len - 1])
		{
			gere_partie_applicative_udp(partie_udp, packet, size_of_lower_layer, header, verbose);
		}
	}
}
