#include "ipv4.h"
#include <netinet/ip_icmp.h>
#include "tcp.h"
#include "udp.h"
#include "ipv6.h"


void gere_options_ipv4(struct iphdr* partie_ipv4, int verbose)
{
	//Options en format TLV
	unsigned int longueur_paquet_octets = partie_ipv4->ihl * 4;
	unsigned int longueur_options_octets = longueur_paquet_octets - 20; //20 octets pour un paquet sans options
	
	unsigned char* options = (unsigned char*)(&partie_ipv4->daddr + 1); //pointer sur la 1ere option 
	
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
		if(option.type == IPOPT_EOL || option.type == IPOPT_NOP)
		{
			if(option.type == IPOPT_EOL)
			{
				if(verbose == 3)
					printf("\t\tPadding : %.2x", *options);
			}
			else if(option.type == IPOPT_NOP)
			{
				if(verbose == 3)
					printf("\t\tNOP : %.2x", *options);
			}
			longueur_options_octets -= 1;
			options += 1; //avancer de 1 octet pour atteindre la prochaine option
		}
		else
		{
			option.length = *(options + 1); //champ suivant
			
			if(verbose == 3)
				printf("\t\tType %u, Length : %u, Value : ", option.type, option.length);
			
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


void print_type_code_icmp(uint8_t type, uint8_t code, int verbose)
{
	switch(type)
	{
		case ICMP_DEST_UNREACH:
			printf("Destination Unreachable Message\n");
			
			if(verbose == 3)
			{
				printf("\tError code : %u ", code);
				switch(code)
				{
					case ICMP_NET_UNREACH:
						printf("(net unreachable)\n");
						break;
						
					case ICMP_HOST_UNREACH:
						printf("(host unreachable)\n");
						break;
						
					case ICMP_PROT_UNREACH:
						printf("(protocol unreachable)\n");
						break;
						
					case ICMP_PORT_UNREACH:
						printf("(port unreachable)\n");
						break;
						
					case ICMP_FRAG_NEEDED:
						printf("(fragmentation needed and DF set)\n");
						break;
						
					case ICMP_SR_FAILED:
						printf("(source route failed)\n");
						break;
				
					default:
						break;
				}
			}
			break;
			
		case ICMP_TIME_EXCEEDED:
			printf("Time Exceeded Message\n");
			if(verbose == 3)
			{
				printf("\tError code : %u ", code);
				if(code == ICMP_EXC_TTL) 
				{
					printf("(time to live exceeded in transit)\n");		
				}
				else if(code == ICMP_EXC_FRAGTIME) 
				{
					printf("(fragment reassembly time exceeded)\n");
				}
			}
			break;
			
		case ICMP_PARAMETERPROB:
			printf("Parameter Problem Message\n");
			if(verbose == 3)
			{
				printf("\tError code : %u\n", code);
			}
			break;
			
		case ICMP_SOURCE_QUENCH:
			printf("Source Quench Message\n");
			if(verbose == 3)
			{
				printf("\tError code : %u\n", code);
			}
			break;
			
		case ICMP_REDIRECT:
			printf("Redirect Message\n");
			if(verbose == 3)
			{
				printf("\tError code : %u ", code);
				if(code == ICMP_REDIR_NET) 
				{
					printf("(Redirect datagrams for the Network)\n");		
				}
				else if(code == ICMP_REDIR_HOST) 
				{
					printf("(Redirect datagrams for the Host)\n");
				}
				else if(code == ICMP_REDIR_NETTOS) 
				{
					printf("(Redirect datagrams for the Type of Service and Network)\n");
				}
				else if(code == ICMP_REDIR_HOSTTOS) 
				{
					printf("(Redirect datagrams for the Type of Service and Host)\n");
				}
			}
			break;
			
		case ICMP_ECHO:
		case ICMP_ECHOREPLY:
			if(type == ICMP_ECHO)
				printf("Echo message\n");
			else if(type == ICMP_ECHOREPLY)
				printf("Echo reply message\n");
			if(verbose == 3)
			{
				printf("\tError code : %u\n", code);
			}
			break;
		
		case ICMP_TIMESTAMP:
		case ICMP_TIMESTAMPREPLY:
			if(type == ICMP_TIMESTAMP)
				printf("Timestamp message\n");
			else if(type == ICMP_TIMESTAMPREPLY)
				printf("Timestamp Reply Message\n");
			if(verbose == 3)
			{
				printf("\tError code : %u\n", code);
			}
			break;
			
		case ICMP_INFO_REQUEST:
		case ICMP_INFO_REPLY:
			if(type == ICMP_INFO_REQUEST)
				printf("Information Request Message\n");
			else if(type == ICMP_INFO_REPLY)
				printf("Information Reply Message\n");
			if(verbose == 3)
			{
				printf("\tError code : %u\n", code);
			}
	
		default:
			printf("Type ICMP inconnu...\n");
			if(verbose == 3)
			{
				printf("\tError code : %u\n", code);
			}
			break;
	}
}


void dechiffrage_ipv4(const u_char *packet, int size_of_lower_layer, const struct pcap_pkthdr *header, bool is_icmp, int verbose)
{
	struct iphdr* partie_ipv4;
	partie_ipv4 = (struct iphdr*) (packet + size_of_lower_layer);
	
	if(verbose == 1)
	{
		printf("IPv4/");
	}
	else if(verbose == 2)
	{
		//texte en gras et souligné
		printf("\e[1;4m");
		printf("IPv4");

		//remettre le style par défaut
		printf("\033[0m");
		
		printf(", ");
		
		struct in_addr in_src;
		in_src.s_addr = partie_ipv4->saddr;
		printf("Src: %s, ", inet_ntoa(in_src));
		
		struct in_addr in_dst;
		in_dst.s_addr = partie_ipv4->daddr;
		printf("Dst: %s\n", inet_ntoa(in_dst));
	}
	else if(verbose == 3)
	{
		//fond blanc et police noire
		printf("\n\033[1;30;47m");
		
		printf("Internet Protocol version 4");
		
		//remettre le style par défaut
   		printf("\033[0m\n");
	
		printf("\tVersion : %x\n", partie_ipv4->version);
		printf("\tIHL : %u\n", partie_ipv4->ihl);
		printf("\tTOS : %.2x\n", partie_ipv4->tos);
		printf("\tTotal length : %hu\n", htons(partie_ipv4->tot_len));
		printf("\tID : %.4x\n", htons(partie_ipv4->id));
		
		uint16_t flags_and_fragment_offset = htons(partie_ipv4->frag_off);
		printf("\tFlags : Reserved(%u), DF(%u), MF(%u)\n", (flags_and_fragment_offset & 32768) >> 15, (flags_and_fragment_offset & 16384) >> 14, (flags_and_fragment_offset & 8192) >> 13);
		
		printf("\tFragment Offset : %.4x\n", htons(partie_ipv4->frag_off));
		printf("\tTTL : %u\n", partie_ipv4->ttl);
		
		u_int8_t protocol = partie_ipv4->protocol;
		
		printf("\tProtocol : ");
		if(protocol == ICMP_PROTOCOL)
		{
			printf("ICMP (%u)\n", partie_ipv4->protocol);	
		}
		else if(protocol == TCP_PROTOCOL)
		{
			printf("TCP (%u)\n", partie_ipv4->protocol);
		}
		else if(protocol == UDP_PROTOCOL)
		{
			printf("UDP (%u)\n", partie_ipv4->protocol);
		}
		else if(protocol == 41) //ipv6
		{
			printf("IPv6 (%u)\n", partie_ipv4->protocol);
		}
		
		printf("\tChecksum : %.4x\n", htons(partie_ipv4->check));
		
		struct in_addr in_src;
		in_src.s_addr = partie_ipv4->saddr;
		printf("\tSource address : %s\n", inet_ntoa(in_src));
		
		struct in_addr in_dst;
		in_dst.s_addr = partie_ipv4->daddr;
		printf("\tDestination address : %s\n", inet_ntoa(in_dst));
	}
	
	if(partie_ipv4->ihl > 5) //il y a des options
	{
		gere_options_ipv4(partie_ipv4, verbose);
	}

	if(partie_ipv4->protocol == ICMP_PROTOCOL)
	{
		dechiffrage_icmpv4(packet, size_of_lower_layer + partie_ipv4->ihl * 4, header, verbose);	
	}
	else if(partie_ipv4->protocol == TCP_PROTOCOL)
	{
		dechiffrage_tcp(packet, size_of_lower_layer + partie_ipv4->ihl * 4, header, is_icmp, verbose);
	}
	else if(partie_ipv4->protocol == UDP_PROTOCOL)
	{
		dechiffrage_udp(packet, size_of_lower_layer + partie_ipv4->ihl * 4, header, is_icmp, verbose);
	}
	else if(partie_ipv4->protocol == 41) //ipv6
	{
		dechiffrage_ipv6(packet, size_of_lower_layer + partie_ipv4->ihl * 4, header, verbose);
	}
}



void dechiffrage_icmpv4(const u_char *packet, int size_of_lower_layer, const struct pcap_pkthdr *header, int verbose)
{
	struct icmphdr* partie_icmp;
	partie_icmp = (struct icmphdr*) (packet + size_of_lower_layer);
	
	if(verbose == 1)
	{
		printf("ICMPv4 ");
		printf("(type=%u)", partie_icmp->type);
		return;
	}
	else if(verbose == 2)
	{
		//texte en gras et souligné
		printf("\e[1;4m");
		printf("ICMPv4");

		//remettre le style par défaut
		printf("\033[0m");
		
		printf(", ");
		print_type_code_icmp(partie_icmp->type, partie_icmp->code, verbose);
	}
	else if(verbose == 3)
	{
		//fond blanc et police noire
		printf("\n\033[1;30;47m");
		
		printf("Internet Control Message Protocol Version 4");
		
		//remettre le style par défaut
   		printf("\033[0m\n");
		
		printf("\tMessage type: (%u) -> ", partie_icmp->type);
		print_type_code_icmp(partie_icmp->type, partie_icmp->code, verbose);
		printf("\tChecksum: %.4x\n", htons(partie_icmp->checksum));
	}
	
	int size_icmp = (sizeof(u_int8_t) * 2 + sizeof(u_int16_t)); //utilisation uniquement des 3 premiers champs de la struct
	
	//ICMP est la dernière partie d'un paquet 
	
	unsigned char* specific = (unsigned char*)(&partie_icmp->checksum + 1); 
	
	switch(partie_icmp->type)
	{
		case ICMP_DEST_UNREACH:
			
			if(partie_icmp->code != ICMP_FRAG_NEEDED)
			{
				if(verbose == 3)
					printf("\tUnused: ");
				for(int i = 0; i < 4; i++)
				{
					if(verbose == 3)
						printf("%.2x", *specific);
					specific += 1;
				}
				if(verbose == 3)
					printf("\n");
			}
			else
			{
				if(verbose == 3)
					printf("\tUnused: ");
				for(int i = 0; i < 2; i++)
				{
					if(verbose == 3)
						printf("%.2x", *specific);
					specific += 1;
				}
				if(verbose == 3)
					printf("\n");
				
				if(verbose == 3)
					printf("\tNext hop mtu: ");
				for(int i = 0; i < 2; i++)
				{
					if(verbose == 3)
						printf("%.2x", *specific);
					specific += 1;
				}
				if(verbose == 3)
					printf("\n");
			}
			
			dechiffrage_ipv4(packet, size_of_lower_layer + size_icmp + 4, header, true, verbose);
			break;
			
		case ICMP_TIME_EXCEEDED:
			
			if(verbose == 3)
				printf("Unused: ");
			for(int i = 0; i < 4; i++)
			{
				if(verbose == 3)
					printf("%.2x", *specific);
				specific += 1;
			}
			if(verbose == 3)
				printf("\n");
			dechiffrage_ipv4(packet, size_of_lower_layer + size_icmp + 4, header, true, verbose); 
			break;
			
		case ICMP_PARAMETERPROB:
			
			if(verbose == 3)
				printf("\tPointer: %.2x\n", *specific);
			specific += 1;
			
			if(verbose == 3)
				printf("\tUnused: ");
			for(int i = 0; i < 3; i++)
			{
				if(verbose == 3)
					printf("%.2x", *specific);
				specific += 1;
			}
			if(verbose == 3)
				printf("\n");
			dechiffrage_ipv4(packet, size_of_lower_layer + size_icmp + 4, header, true, verbose);
			break;
			
		case ICMP_SOURCE_QUENCH:
			
			if(verbose == 3)
				printf("\tUnused: ");
			for(int i = 0; i < 4; i++)
			{
				if(verbose == 3)
					printf("%.2x", *specific);
				specific += 1;
			}
			if(verbose == 3)
				printf("\n");
			dechiffrage_ipv4(packet, size_of_lower_layer + size_icmp + 4, header, true, verbose);
			break;
			
		case ICMP_REDIRECT:
			
			if(verbose == 3)
				printf("\tGateway Internet Address: ");
			for(int i = 0; i < 4; i++)
			{
				if(verbose == 3)
					printf("%.2x", *specific);
				specific += 1;
			}
			if(verbose == 3)
				printf("\n");
			dechiffrage_ipv4(packet, size_of_lower_layer + size_icmp + 4, header, true, verbose); 
			break;
			
		case ICMP_ECHO:
		case ICMP_ECHOREPLY:
			
			if(partie_icmp->code == 0)
			{
				if(verbose == 3)
					printf("\tIdentifier: ");
				for(int i = 0; i < 2; i++)
				{
					if(verbose == 3)
						printf("%.2x", *specific);
					specific += 1;
				}
				if(verbose == 3)
					printf("\n");
				
				if(verbose == 3)
					printf("\tSequence Number: ");
				for(int i = 0; i < 2; i++)
				{
					if(verbose == 3)
						printf("%.2x", *specific);
					specific += 1;
				}
				if(verbose == 3)
					printf("\n");
			}
			else
			{
				if(verbose == 3)
					printf("\tUnused: ");
				for(int i = 0; i < 4; i++)
				{
					if(verbose == 3)
						printf("%.2x", *specific);
					specific += 1;
				}
				if(verbose == 3)
					printf("\n");
			}
			
			if(verbose == 3)
				printf("\tSpecific data: ");
			for(int i = 0; specific <= &packet[header->len - 1]; i++) //print jusqu'à la fin du paquet
			{
				if(verbose == 3)
					printf("%.2x", *specific);
				if(specific == &packet[header->len - 1]) //ne pas incrémenter specific après le dernier octet du paquet
					break;
				specific += 1;
			}
			if(verbose == 3)
				printf("\n");
			break;
		
		case ICMP_TIMESTAMP:
		case ICMP_TIMESTAMPREPLY:
			
			if(verbose == 3)
				printf("\tIdentifier: ");
			for(int i = 0; i < 2; i++)
			{
				if(verbose == 3)
					printf("%.2x", *specific);
				specific += 1;
			}
			if(verbose == 3)
				printf("\n");
			
			if(verbose == 3)
				printf("\tSequence Number: ");
			for(int i = 0; i < 2; i++)
			{
				if(verbose == 3)
					printf("%.2x", *specific);
				specific += 1;
			}
			if(verbose == 3)
				printf("\n");
			
			if(verbose == 3)
				printf("\tOriginal Timestamp: ");
			for(int i = 0; i < 4; i++)
			{
				if(verbose == 3)
					printf("%.2x", *specific);
				specific += 1;
			}
			if(verbose == 3)
				printf("\n");
			
			if(verbose == 3)
				printf("\tReceive Timestamp: ");
			for(int i = 0; i < 4; i++)
			{
				if(verbose == 3)
					printf("%.2x", *specific);
				specific += 1;
			}
			if(verbose == 3)
				printf("\n");
			
			if(verbose == 3)
				printf("\tTransmit Timestamp: ");
			for(int i = 0; i < 4; i++)
			{
				if(verbose == 3)
					printf("%.2x", *specific);
				specific += 1;
			}
			if(verbose == 3)
				printf("\n");
			break;
			
		case ICMP_INFO_REQUEST:
		case ICMP_INFO_REPLY:
			
			if(verbose == 3)
				printf("\tIdentifier: ");
			for(int i = 0; i < 2; i++)
			{
				if(verbose == 3)
					printf("%.2x", *specific);
				specific += 1;
			}
			if(verbose == 3)
				printf("\n");
			
			if(verbose == 3)
				printf("\tSequence Number: ");
			for(int i = 0; i < 2; i++)
			{
				if(verbose == 3)
					printf("%.2x", *specific);
				specific += 1;
			}
			if(verbose == 3)
				printf("\n");
	
		default:	
			if(verbose == 3)
				printf("\t");
			for(int i = 0; specific <= &packet[header->len - 1]; i++) //print jusqu'à la fin du paquet
			{
				if(verbose == 3)
					printf("%.2x", *specific);
				if(specific == &packet[header->len - 1]) //ne pas incrémenter specific après le dernier octet du paquet
					break;
				specific += 1;
			}
			break;
	}
}

