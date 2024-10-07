#include "tcp.h"
//protocoles applicatifs
#include "smtp.h"
#include "dns.h"
#include "pop.h"
#include "imap.h"
#include "ftp.h"
#include "telnet.h"
#include "http1.h"
#include "http2.h"
#include "tls.h"

#include <ctype.h>


void gere_options_tcp(struct tcphdr* partie_tcp, int verbose)
{
	//Options en format TLV
	unsigned int longueur_options_octets = (partie_tcp->doff - 5) * 4;
	
	unsigned char* options = (unsigned char*)(&partie_tcp->urg_ptr + 1); //pointer sur la 1ere option 
	
	if(verbose == 3)
	{
		//texte en gras et souligné
		printf("\e[1;4m");
		printf("\tOPTIONS");

		//remettre le style par défaut
		printf("\033[0m\n");
	}
	
	while(longueur_options_octets != 0)
	{			
		//printf("Longueur options : %u\n", longueur_options_octets);
		
		struct option_tlv option = {0};
		option.type = *options;
		if(option.type == TCPOPT_EOL || option.type == TCPOPT_NOP)
		{
			if(option.type == TCPOPT_EOL)
			{
				if(verbose == 3)
					printf("\t\tPadding : %.2x", *options);
			}
			else if(option.type == TCPOPT_NOP)
			{
				if(verbose == 3)
					printf("\t\tNOP : %.2x", *options);
			}
			longueur_options_octets -= 1;
			options += 1;
		}
		else
		{
			option.length = *(options + 1); //champ suivant
			
			if(verbose == 3)
			{
				switch(option.type)
				{
					case TCPOPT_MAXSEG:
						printf("\t\tMaximum Segment Size Value : ");
						break;
						
					case TCPOPT_WINDOW:
						printf("\t\tWindow Size Shift Bits : ");
						break;
						
					case TCPOPT_SACK_PERMITTED:
						printf("\t\tSelective Acknowledgment Permitted : ");
						break;
						
					case TCPOPT_SACK:
						printf("\t\tSelective Acknowledgment : ");
						break;
						
					case TCPOPT_TIMESTAMP:
						printf("\t\tTimestamps : ");
						break;
						
					case 14:
						printf("\t\tAlternate Checksum Algorithm : ");
						break;
						
					case 15:
						printf("\t\tAlternate Checksum : ");
						break;
					
					default:
						printf("\t\tOption inconnue : ");
						break;
				}
			}
			
			if(verbose == 3)
				printf("Type %u, Length : %u, Value : ", option.type, option.length);
			
			unsigned char value[option.length - 2];
			for(int i = 2; i < option.length; i++) 
			{
				int j = 0;
				value[j] = *(options + i); //de *(options + 2) à *(options + option.length - 2)
				if(verbose == 3)
					printf("%.2x", value[j]);
				j += 1;
			}
			if(option.length <= 0)
			{
				longueur_options_octets -= 1;
				options += 1;
			}
			else
			{
				longueur_options_octets -= option.length; //taille de l'option lue enlevée
				options += option.length; 
			}
		}
		if(verbose == 3)
			printf("\n");
	}
}


int savoir_version_http(struct tcphdr* partie_tcp, const u_char *packet, int size_of_lower_layer, const struct pcap_pkthdr *header)
{
	float pourcentage = 0; //pourcentage de caractères ASCII dans la partie HTTP du paquet
	int longueur = 0; //longueur de la partie HTTP du paquet
	int nombre = 0; //nombre de caractères ASCII
	
	unsigned char* pointeur = (unsigned char*) (packet + size_of_lower_layer + partie_tcp->doff * 4);
	while(pointeur <= &packet[header->len - 1]) //tant que la fin du paquet n'est pas atteinte
	{
		longueur += 1;

		if(isalnum(*pointeur) != 0)
			nombre += 1;
		
		if(pointeur == &packet[header->len - 1]) //ne pas incrémenter pointeur après le dernier octet du paquet
			break;
		pointeur += 1; 
	}
	
	pourcentage = (float)nombre/(float)longueur;
	
	//HTTP/1.x étant composé de texte, son nombre de caractères ASCII est largement supérieur à HTTP/2
	if(pourcentage > 0.5) //pourcentage supérieur à 50% => HTTP/1.x
		return 1; //HTTP/1.x
	else return 2; //HTTP/2
}


void gere_partie_applicative_tcp(struct tcphdr* partie_tcp, const u_char *packet, int size_of_lower_layer, const struct pcap_pkthdr *header, int verbose)
{
	if(htons(partie_tcp->source) == PORT_SMTP || htons(partie_tcp->source) == PORT_SMTP_CHIFFR_IMPL || htons(partie_tcp->source) == PORT_SMTP_CHIFFR_EXPL)
	{
		dechiffrage_smtp(packet, size_of_lower_layer + partie_tcp->doff * 4, header, true, verbose);
	}
	if(htons(partie_tcp->dest) == PORT_SMTP || htons(partie_tcp->dest) == PORT_SMTP_CHIFFR_IMPL || htons(partie_tcp->dest) == PORT_SMTP_CHIFFR_EXPL)
	{
		dechiffrage_smtp(packet, size_of_lower_layer + partie_tcp->doff * 4, header, false, verbose);
	}
	else if(htons(partie_tcp->source) == PORT_DNS_TCP || htons(partie_tcp->dest) == PORT_DNS_TCP)
	{
		dechiffrage_dns(packet, size_of_lower_layer + partie_tcp->doff * 4, header, verbose);
	}
	else if(htons(partie_tcp->source) == PORT_POP || htons(partie_tcp->source) == PORT_POP_SSL)
	{
		dechiffrage_pop(packet, size_of_lower_layer + partie_tcp->doff * 4, header, true, verbose);
	}
	else if(htons(partie_tcp->dest) == PORT_POP || htons(partie_tcp->dest) == PORT_POP_SSL)
	{
		dechiffrage_pop(packet, size_of_lower_layer + partie_tcp->doff * 4, header, false, verbose);
	}
	else if(htons(partie_tcp->source) == PORT_IMAP || htons(partie_tcp->source) == PORT_IMAPS) //serveur IMAP
	{
		dechiffrage_imap(packet, size_of_lower_layer + partie_tcp->doff * 4, header, true, verbose);
	}
	else if(htons(partie_tcp->dest) == PORT_IMAP || htons(partie_tcp->dest) == PORT_IMAPS) //client IMAP
	{
		dechiffrage_imap(packet, size_of_lower_layer + partie_tcp->doff * 4, header, false, verbose);
	}
	else if((htons(partie_tcp->source) == PORT_FTP_DATA || htons(partie_tcp->dest) == PORT_FTP_DATA) || (htons(partie_tcp->source) == PORT_FTP_CONN || htons(partie_tcp->dest) == PORT_FTP_CONN))
	{
		dechiffrage_ftp(packet, size_of_lower_layer + partie_tcp->doff * 4, header, verbose);
	}
	else if(htons(partie_tcp->source) == PORT_TELNET || htons(partie_tcp->dest) == PORT_TELNET)
	{
		dechiffrage_telnet(packet, size_of_lower_layer + partie_tcp->doff * 4, header, verbose);
	}
	else if(htons(partie_tcp->source) == PORT_HTTP)
	{
		int version = savoir_version_http(partie_tcp, packet, size_of_lower_layer, header);

		if(version == 1) 
		{
			dechiffrage_http1(packet, size_of_lower_layer + partie_tcp->doff * 4, header, true, verbose);
		}
		else if(version == 2) 
		{
			dechiffrage_http2(packet, size_of_lower_layer + partie_tcp->doff * 4, header, true, verbose);
		}
	}
	else if(htons(partie_tcp->dest) == PORT_HTTP)
	{
		int version = savoir_version_http(partie_tcp, packet, size_of_lower_layer, header);

		if(version == 1) 
		{
			dechiffrage_http1(packet, size_of_lower_layer + partie_tcp->doff * 4, header, false, verbose);
		}
		else if(version == 2) 
		{
			dechiffrage_http2(packet, size_of_lower_layer + partie_tcp->doff * 4, header, false, verbose);
		}
	}
	else if(htons(partie_tcp->source) == PORT_HTTPS || htons(partie_tcp->dest) == PORT_HTTPS) //HTTP over TLS => HTTPS
	{
		dechiffrage_tls(packet, size_of_lower_layer + partie_tcp->doff * 4, header, verbose);
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


void dechiffrage_tcp(const u_char *packet, int size_of_lower_layer, const struct pcap_pkthdr *header, bool is_icmp, int verbose)
{
	struct tcphdr* partie_tcp;
	partie_tcp = (struct tcphdr*) (packet + size_of_lower_layer);

	if(verbose == 1)
	{
		printf("TCP/");
	}
	else if(verbose == 2)
	{
		//texte en gras et souligné
		printf("\e[1;4m");
		printf("TCP");

		//remettre le style par défaut
		printf("\033[0m");
		
		printf(", ");
		
		printf("Port source: %u, ", htons(partie_tcp->source));
		printf("Port dest: %u, ", htons(partie_tcp->dest));
		printf("Seq: %u, ", htonl(partie_tcp->seq));
		printf("Ack: %u, ", htonl(partie_tcp->ack_seq));
		printf("Data offset: %u\n", partie_tcp->doff);
	}
	else if(verbose == 3)
	{
		//fond blanc et police noire
		printf("\n\033[1;30;47m");
		
		printf("Transmission Control Protocol");
		
		//remettre le style par défaut
   		printf("\033[0m\n");
		
		printf("\tPort source: %u\n", htons(partie_tcp->source));
		printf("\tPort dest: %u\n", htons(partie_tcp->dest));
		printf("\tNum seq: %u\n", htonl(partie_tcp->seq));
	}
	
	if(is_icmp == false)
	{
		if(verbose == 3)
		{
			printf("\tNum ack: %u\n", htonl(partie_tcp->ack_seq));
			printf("\tData offset: %u\n", partie_tcp->doff);
			
			printf("\tFlag fin: %d\n", partie_tcp->fin);
			printf("\tFlag syn: %d\n", partie_tcp->syn);
			printf("\tFlag rst: %d\n", partie_tcp->rst);
			printf("\tFlag psh: %d\n", partie_tcp->psh);
			printf("\tFlag ack: %d\n", partie_tcp->ack);
			printf("\tFlag urg: %d\n", partie_tcp->urg);
			
			printf("\tTaille fenêtre: %u\n", htons(partie_tcp->window));
			printf("\tChecksum: %.4x\n", htons(partie_tcp->check));
			printf("\tPointeur d'urgence: %u\n", htons(partie_tcp->urg_ptr));
			
			if(partie_tcp->doff > 5) //il y a des options
			{
				gere_options_tcp(partie_tcp, verbose);
			}
		}
		
		//gérer la partie applicative uniquement s'il reste des données dans le paquet : il se peut qu'il y ait un paquet TCP avec un port dest ou src HTTP mais qu'il n'y ait pas de données
		if((unsigned char*) (packet + size_of_lower_layer + partie_tcp->doff * 4) < &packet[header->len - 1])
		{
			gere_partie_applicative_tcp(partie_tcp, packet, size_of_lower_layer, header, verbose);
		}
	}
}
