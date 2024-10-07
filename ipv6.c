#include "ipv6.h"
//#include "icmpv6.h"
#include <netinet/icmp6.h>
#include "tcp.h"
#include "udp.h"


void gere_options(unsigned char** options_padding, unsigned int longueur_options_octets, int verbose)
{
	bool une_fois = false; //utilisée pour afficher une seule fois le texte OPTIONS
	
	while(longueur_options_octets != 0)
	{			
		if(verbose == 3)
		{
			if(une_fois == false)
			{
				//texte en gras et souligné
				printf("\e[1;4m");
				printf("\tOPTIONS");

				//remettre le style par défaut
				printf("\033[0m\n");
				
				une_fois = true;
			}	
		}
		
		struct ip6_opt option = {0};
		option.ip6o_type = **options_padding;
		if(option.ip6o_type == IP6OPT_PAD1 || option.ip6o_type == IP6OPT_PADN) //pas de longueur et de données
		{
			if(option.ip6o_type == IP6OPT_PAD1)
			{
				if(verbose == 3)
					printf("\t\t\tPadding: %.2x", **options_padding);
			}
			else if(option.ip6o_type == IP6OPT_PADN)
			{
				if(verbose == 3)
					printf("\t\t\tNOP: %.2x", **options_padding);
			}
				
			longueur_options_octets -= 1;
			*options_padding += 1;
		}
		else
		{
			option.ip6o_len = **(options_padding + 1); //champ suivant
			if(verbose == 3)
				printf("\t\t\tType %x, Length: %.2x", option.ip6o_type, option.ip6o_len);
			
			unsigned char value[option.ip6o_len]; //ATTENTION : le champ Length indique uniquement la longueur du champ Value et non de toute l'option comme en IPv4
			
			if(option.ip6o_len > 0)
				if(verbose == 3)
					printf(", Value: ");
			
			for(int i = 2; i < option.ip6o_len; i++) 
			{
				int j = 0;
				value[j] = **(options_padding + i); //de *(options + 2) à *(options + option.ip6o_len - 2)
				if(verbose == 3)
					printf("%.2x", value[j]);
				j += 1;
			}
			if(option.ip6o_len <= 0)
			{
				longueur_options_octets -= 1;
				*options_padding += 1;
			}
			else
			{
				longueur_options_octets -= option.ip6o_len; //taille de l'option lue enlevée
				*options_padding += option.ip6o_len; 
			}
		}
		if(verbose == 3)
			printf("\n");
	}
}


void print_ipv6_routing(uint16_t last_entry, unsigned char** pointeur, int verbose)
{
	unsigned char data[16];
	int nombre = 0; //compteur du nombre d'adresse IPv6
	for(unsigned char i = 0; i < (last_entry + 1) * 16; i++)
	{
		if((i % 16 == 0 && i != 0) || i == (last_entry + 1) * 16 - 1) //nouvelle adresse IPv6 qui commence
		{
			if(verbose == 3)
				printf("\t\t- Address[%d]: ", nombre); 
			struct in6_addr addr;
			for (int i = 0; i < 16; i++) 
			{
				addr.s6_addr[i] = data[i];
		    	}
			char ipv6_buf[INET6_ADDRSTRLEN];
			if(verbose == 3)
				printf("%s\n", inet_ntop(AF_INET6, addr.s6_addr, ipv6_buf, 128));
			nombre += 1;
		}	
		data[i%16] = **pointeur;
		*pointeur += 1;
	}
}

void print_next_header(uint8_t next_header, int profondeur) //profondeur pour afficher le bon nombre de tab
{
	char* chaine_tabulation;
	if(profondeur == 1)
		chaine_tabulation = "\t";
	else if(profondeur == 2)
		chaine_tabulation = "\t\t";
	
	printf("%sNext header: ", chaine_tabulation);
	switch(next_header)
	{
		case ICMPV6_PROTOCOL:
			printf("ICMPv6 (%u)\n", next_header);
			break;
		
		case TCP_PROTOCOL:
			printf("TCP (%u)\n", next_header);
			break;
		
		case UDP_PROTOCOL:
			printf("UDP (%u)\n", next_header);
			break;
		
		case 41: //IPv6
			printf("IPv6 (%u)\n", next_header);
			break;
		
		case ROUTING_EXTENSION:
			printf("ROUTING (%u)\n", next_header);
			break;
			
		case FRAGMENT_EXTENSION:
			printf("FRAGMENT (%u)\n", next_header);
			break;
			
		case HOP_BY_HOP_EXTENSION:
			printf("HOP BY HOP (%u)\n", next_header);
			break;
			
		case DESTINATION_EXTENSION:
			printf("DESTINATION (%u)\n", next_header);
			break;
		
		case 50: //cas spécial : ESP (Encapsulating Security Payload)
			printf("ESP (%u)\n", next_header);
			break;
			
		default:
			break;
	}
}


void print_type_code_icmpv6(uint8_t type, uint8_t code, int verbose)
{
	switch(type)
	{
		case ICMP6_DST_UNREACH:
			printf("Destination Unreachable Message\n");
			
			if(verbose == 3)
			{
				printf("\tError code: %u ", code);
				switch(code)
				{
					case ICMP6_DST_UNREACH_NOROUTE:
						printf("No route to destination\n");
						break;
						
					case ICMP6_DST_UNREACH_ADMIN:
						printf("Communication with destination administratively prohibited\n");
						break;
						
					case ICMP6_DST_UNREACH_BEYONDSCOPE:
						printf("Beyond scope of source address\n");
						break;
						
					case ICMP6_DST_UNREACH_ADDR:
						printf("Address unreachable\n");
						break;
						
					case ICMP6_DST_UNREACH_NOPORT:
						printf("Port unreachable\n");
						break;
						
					case 5:
						printf("Source address failed ingress/egress policy\n");
						break;
						
					case 6:
						printf("Reject route to destination\n");
						break;
					
					default:
						break;
				}
			}
			break;
			
		case ICMP6_PACKET_TOO_BIG:
			printf("Packet Too Big Message\n");
			if(verbose == 3)
			{
				printf("\tError code: %u\n", code);
			}
			break;
			
		case ICMP6_TIME_EXCEEDED:
			printf("Time Exceeded Message\n");
			if(verbose == 3)
			{
				printf("\tError code: %u ", code);
				if(code == ICMP6_TIME_EXCEED_TRANSIT)
				{
					printf("Hop limit exceeded in transit\n");
				}
				else if(code == ICMP6_TIME_EXCEED_REASSEMBLY)
				{
					printf("Fragment reassembly time exceeded\n");
				}
			}
			break;
			
		case ICMP6_PARAM_PROB:
			printf("Parameter Problem Message\n");
			if(verbose == 3)
			{
				printf("\tError code: %u ", code);
				if(code == ICMP6_PARAMPROB_HEADER)
				{
					printf("Erroneous header field encountered\n");
				}
				else if(code == ICMP6_PARAMPROB_NEXTHEADER)
				{
					printf("Unrecognized Next Header type encountered\n");
				}
				else if(code == ICMP6_PARAMPROB_OPTION)
				{
					printf("Unrecognized IPv6 option encountered\n");
				}
			}
			break;
			
		case ICMP6_ECHO_REQUEST:
		case ICMP6_ECHO_REPLY:
			if(type == ICMP6_ECHO_REQUEST)
				printf("Echo Request Message\n");
			else if(type == ICMP6_ECHO_REPLY)
				printf("Echo Reply Message\n");
			if(verbose == 3)
			{
				printf("\tError code: %u\n", code);
			}
			break;
			
		case ND_NEIGHBOR_SOLICIT:
			printf("Neighbor Solicitation Message\n");
			if(verbose == 3)
			{
				printf("\tError code: %u\n", code);
			}
			break;
			
		case ND_NEIGHBOR_ADVERT:
			printf("Neighbor Advertisement Message\n");
			if(verbose == 3)
			{
				printf("\tError code: %u\n", code);
			}
			break;
	
		default:
			printf("Type ICMP inconnu...\n");
			if(verbose == 3)
			{
				printf("\tError code: %u\n", code);
			}
			break;
	}
}



void gere_extension_ipv6(struct ip6_hdr** partie_ipv6, int* taille, unsigned char* next_header, int verbose) //IPv6 dans IPv6
{
	if(verbose == 1)
		printf("IPv6");
	else if(verbose == 2)
		printf(", IPv6 ");
	else if(verbose == 3)
	{
		//texte en gras et souligné
		printf("\e[1;4m");
		printf("\tInternet Protocol version 6");

		//remettre le style par défaut
		printf("\033[0m\n");
		unsigned char version = (htonl((*partie_ipv6)->ip6_ctlun.ip6_un1.ip6_un1_flow) & 0xF0000000) >> 28;
		
		unsigned char traffic_class = (htonl((*partie_ipv6)->ip6_ctlun.ip6_un1.ip6_un1_flow) & 0x0FF00000) >> 20;
		
		unsigned int flow_label = htonl((*partie_ipv6)->ip6_ctlun.ip6_un1.ip6_un1_flow) & 0x000FFFFF;
		
		printf("\t\tVersion: %.1x\n", version);
		printf("\t\tTraffic class: %.2x\n", traffic_class);
		printf("\t\tFlow label: %.5x\n", flow_label);
		
		printf("\t\tPayload length: %hu\n", (*partie_ipv6)->ip6_ctlun.ip6_un1.ip6_un1_plen);
		print_next_header((*partie_ipv6)->ip6_ctlun.ip6_un1.ip6_un1_nxt, 2);
		
		printf("\t\tHop limit: %u\n", (*partie_ipv6)->ip6_ctlun.ip6_un1.ip6_un1_hlim);
		
		char ipv6_buf_src[INET6_ADDRSTRLEN];
		printf("\t\tSource address: %s\n", inet_ntop(AF_INET6, (*partie_ipv6)->ip6_src.s6_addr, ipv6_buf_src, 128));
		
		char ipv6_buf_dst[INET6_ADDRSTRLEN];
		printf("\t\tDestination address: %s\n", inet_ntop(AF_INET6, (*partie_ipv6)->ip6_dst.s6_addr, ipv6_buf_dst, 128));
	}
	*next_header = (*partie_ipv6)->ip6_ctlun.ip6_un1.ip6_un1_nxt;
	
	*taille += sizeof(struct ip6_hdr);
}

void gere_extension_routing_type_0(struct ip6_hdr** partie_ipv6, struct ip6_rthdr** routing, int* taille, int verbose)
{
	unsigned char* type_specific_data = (unsigned char*)(&(*routing)->ip6r_segleft + 1);
	if(verbose == 1 || verbose == 2)
	{
		printf("type 0)");
	}
	else if(verbose == 3)
	{
		printf("\t\tType: type 0 routing \n");
	}
		
	//champ reserved sur 32 bits
	if(verbose == 3)
		printf("\t\tReserved: ");
		
	for(int i = 0; i < 4; i++)
	{
		if(verbose == 3)
			printf("%.2x", *type_specific_data);
		type_specific_data += 1;
	}
	
	if(verbose == 3)
		printf("\n");
	
	//il y a routing->ip6r_len/2 adresses
	if(verbose == 3)
		printf("\t\tAdresses: ");
	for(unsigned char i = 0; i < ((*routing)->ip6r_len/2) * 16; i++)
	{
		if(verbose == 3)
			printf("%.2x", *type_specific_data);
		type_specific_data += 1;
	}
	*routing = (struct ip6_rthdr*) type_specific_data; //pointe après l'en-tête d'extension
	*partie_ipv6 = (struct ip6_hdr*) (*routing);
	
	//4 octets du champ Reserved + adresses de la boucle for juste au-dessus
	*taille += 4 + (((*routing)->ip6r_len/2) * 16);
	
}

void gere_extension_routing_type_2(struct ip6_hdr** partie_ipv6, struct ip6_rthdr** routing, int* taille, int verbose)
{
	unsigned char* type_specific_data = (unsigned char*)(&(*routing)->ip6r_segleft + 1);
	if(verbose == 1 || verbose == 2)
	{
		printf("type 2)");
	}
	else if(verbose == 3)
	{
		printf("\t\tType: type 2 routing\n");
	}
		
	//champ reserved sur 32 bits
	if(verbose == 3)
		printf("\t\tReserved: ");
		
	for(int i = 0; i < 4; i++)
	{
		if(verbose == 3)
			printf("%.2x", *type_specific_data);
		type_specific_data += 1;
	}
	
	if(verbose == 3)
		printf("\n");
	

	if(verbose == 3)
		printf("\t\tHome address: ");
	for(int i  = 0; i < 16; i++)
	{
		if(verbose == 3)
			printf("%.2x", *type_specific_data);
		type_specific_data += 1;
	}
	*routing = (struct ip6_rthdr*) type_specific_data; //pointe après l'en-tête d'extension
	*partie_ipv6 = (struct ip6_hdr*) (*routing);
	
	//4 octets du champ Reserved + 16 octets de la boucle for juste au-dessus
	*taille += 4 + 16;
}

void gere_extension_routing_type_4(struct ip6_hdr** partie_ipv6, struct ip6_rthdr** routing, int* taille, int verbose)
{
	unsigned char* type_specific_data = (unsigned char*)(&(*routing)->ip6r_segleft + 1); 
	//champ last entry sur 8 bits
	unsigned char last_entry = *type_specific_data;
	
	if(verbose == 1 || verbose == 2)
	{
		printf("type 4)");
	}
	else if(verbose == 3)
	{
		printf("\t\tType: type 4 routing\n");
	}
	
	if(verbose == 3)
		printf("\t\tLast Entry: %.2x\n", last_entry);
	type_specific_data += 1;
	
	//champ flags sur 8 bits
	if(verbose == 3)
		printf("\t\tFlags: %.2x\n", *type_specific_data);
	type_specific_data += 1;
	
	//champ tag sur 16 bits
	if(verbose == 3)
		printf("\t\tTag: ");
	for(int i = 0; i < 2; i++)
	{
		if(verbose == 3)
			printf("%.2x", *type_specific_data);
		type_specific_data += 1;
	}
	
	if(verbose == 3)
		printf("\n");
	
	//=> va de 0 à lastentry
	if(verbose == 3)
		printf("\t\tSegments list: \n");
		
	print_ipv6_routing(last_entry, &type_specific_data, verbose);	
	
	//1 octet de Last entry, 1 octet de flag, 2 octets de tag et les octets de la boucle for juste au-dessus
	*taille += 1 + 1 + 2 + ((last_entry + 1) * 16);
	
	//champ options (TLV) : champ length = longueur du champ value (comme IPv6) 
	if((*routing)->ip6r_len > (last_entry + 1) * 2)
	{
		//Options en format TLV
		unsigned int longueur_options_octets = (*routing)->ip6r_len * 8;
		
		gere_options(&type_specific_data, longueur_options_octets, verbose);
		
		*taille += (*routing)->ip6r_len * 8;
	}
	*routing = (struct ip6_rthdr*) type_specific_data; //pointe après l'en-tête d'extension
	*partie_ipv6 = (struct ip6_hdr*) (*routing);
}

void gere_extension_routing_type_inconnu(struct ip6_hdr** partie_ipv6, struct ip6_rthdr** routing, int* taille, int verbose)
{
	if(verbose == 1 || verbose == 2)
	{
		printf("inconnu)");
	}
	else if(verbose == 3)
	{
		printf("\t\tType: type de routing inconnu.\n");
	}
	
	unsigned char* type_specific_data = (unsigned char*)(&(*routing)->ip6r_segleft + 1); 
	
	printf("\t\t");
	for(int i = 0; i < 4; i++) 
	{
		if(verbose == 3)
			printf("%.2x", *type_specific_data);
			
		type_specific_data += 1;
	}
	
	if((*routing)->ip6r_len > 0) //il reste des choses
	{
		for(int i = 0; i < 8 * (*routing)->ip6r_len; i++) 
		{
			if(verbose == 3)
				printf("%.2x", *type_specific_data);
				
			type_specific_data += 1;
		}
	}
	printf("\n");
	
	*routing = (struct ip6_rthdr*) type_specific_data; //pointe après l'en-tête d'extension
	*partie_ipv6 = (struct ip6_hdr*) (*routing);
	
	//4 octets de type specific data et les éventuels octets restants de l'extension
	*taille += 4 + 8 * (*routing)->ip6r_len;
}


void gere_extension_routing(struct ip6_hdr** partie_ipv6, int* taille, unsigned char* next_header, int verbose)
{
	struct ip6_rthdr* routing = (struct ip6_rthdr*) (*partie_ipv6);
				
	if(verbose == 1 || verbose == 2)
		printf("(Routing extension ");
	else if(verbose == 3)
	{
		//texte en gras et souligné
		printf("\e[1;4m");
		printf("\tRouting extension");

		//remettre le style par défaut
		printf("\033[0m\n");
		
		print_next_header(routing->ip6r_nxt, 2);

		printf("\t\tHeader length: %u\n", routing->ip6r_len); //vaut 0 si longueur = 64 bits, et si longueur supérieure à 64 bits alors vaut un nombre représentant la longueur de l'en-tête en nombre de 64 bits sans compter les 64 premiers bits
		printf("\t\tRouting type: %u\n", routing->ip6r_type); //vaut 2, 3 ou 4
		printf("\t\tSegments left: %u\n", routing->ip6r_segleft);
	}
	*next_header = routing->ip6r_nxt;
	
	*taille += sizeof(struct ip6_rthdr);
	
	if(routing->ip6r_type == ROUTING_TYPE_0)
	{
		gere_extension_routing_type_0(partie_ipv6, &routing, taille, verbose);
	}
	else if(routing->ip6r_type == ROUTING_TYPE_2)
	{
		gere_extension_routing_type_2(partie_ipv6, &routing, taille, verbose);
	}
	else if(routing->ip6r_type == ROUTING_TYPE_4)
	{
		gere_extension_routing_type_4(partie_ipv6, &routing, taille, verbose);
	}
	else //type de routing inconnu
	{
		gere_extension_routing_type_inconnu(partie_ipv6, &routing, taille, verbose);
	}
}


void gere_extension_fragment(struct ip6_hdr** partie_ipv6, int* taille, unsigned char* next_header, int verbose)
{
	struct ip6_frag* fragment = (struct ip6_frag*) *(partie_ipv6);
	if(verbose == 1 || verbose == 2)
	{
		printf("(Fragment extension)");
	}
	else if(verbose == 3)
	{
		//texte en gras et souligné
		printf("\e[1;4m");
		printf("\tFragment extension");

		//remettre le style par défaut
		printf("\033[0m\n");
		
		print_next_header(fragment->ip6f_nxt, 2);
		
		printf("\t\tReserved (1): %.2x\n", fragment->ip6f_reserved); 
	
		printf("\t\tFragment offset, Reserved (2) et More fragments flag: %.4x\n", htons(fragment->ip6f_offlg)); 
	
		printf("\t\tIdentification: %.8x\n", htonl(fragment->ip6f_ident));
	}
	*next_header = fragment->ip6f_nxt;
	
	fragment += sizeof(struct ip6_frag);
	
	*partie_ipv6 = (struct ip6_hdr*) fragment;
	
	*taille += sizeof(struct ip6_frag);
}


void gere_extension_hop_by_hop(struct ip6_hdr** partie_ipv6, int* taille, unsigned char* next_header, int verbose)
{
	struct ip6_hbh* hop_by_hop = (struct ip6_hbh*) *(partie_ipv6);
				
	//48 bits options et padding
	unsigned char* options_padding = (unsigned char*)(hop_by_hop) + 2; //2 octets dans la struct ip6_hbh
	
	if(verbose == 1 || verbose == 2)
	{
		printf("(Hop By Hop extension)");
	}
	else if(verbose == 3)
	{
		//texte en gras et souligné
		printf("\e[1;4m");
		printf("\tHop By Hop extension");

		//remettre le style par défaut
		printf("\033[0m\n");
		
		print_next_header(hop_by_hop->ip6h_nxt, 2);
		
		printf("\t\tHeader length: %u\n", hop_by_hop->ip6h_len); //vaut 0 si longueur = 64 bits, et si longueur supérieure à 64 bits alors vaut un nombre représentant la longueur de l'en-tête en nombre de 64 bits sans compter les 64 premiers bits
	}
	*next_header = hop_by_hop->ip6h_nxt;
	
	if(verbose == 3)
		printf("\t\tOptions-padding: ");
	for(int i = 0; i < 6; i++) 
	{
		if(verbose == 3)
			printf("%.2x", *options_padding);
		options_padding += 1;
	}
	if(verbose == 3)
		printf("\n");
	
	hop_by_hop = (struct ip6_hbh*) options_padding;
	
	*taille += sizeof(struct ip6_hbh) + 6;  //6 octets de options/padding
	
	if(hop_by_hop->ip6h_len > 0)
	{
		//Options en format TLV
		unsigned int longueur_options_octets = hop_by_hop->ip6h_len * 8;
		
		gere_options(&options_padding, longueur_options_octets, verbose);
		
		*taille += hop_by_hop->ip6h_len * 8;
	}
	hop_by_hop = (struct ip6_hbh*) options_padding;
	
	*partie_ipv6 = (struct ip6_hdr*) hop_by_hop;
}


void gere_extension_destination(struct ip6_hdr** partie_ipv6, int* taille, unsigned char* next_header, int verbose)
{
	struct ip6_dest* destination = (struct ip6_dest*) *(partie_ipv6);
	
	if(verbose == 1 || verbose == 2)
	{
		printf("(Destination extension)");
	}
	else if(verbose == 3)
	{
		//texte en gras et souligné
		printf("\e[1;4m");
		printf("\tDestination extension");

		//remettre le style par défaut
		printf("\033[0m\n");
		
		print_next_header(destination->ip6d_nxt, 2);
		printf("\t\tHeader length: %u\n", destination->ip6d_len); //vaut 0 si longueur = 64 bits, et si longueur supérieure à 64 bits alors vaut un nombre représentant la longueur de l'en-tête en nombre de 64 bits sans compter les 64 premiers bits
	}
	
	*next_header = destination->ip6d_nxt;
	
	//48 bits options et padding
	unsigned char* options_padding = (unsigned char*)destination;
	
	if(verbose == 3)
		printf("\t\tOptions-padding: ");
	for(int i = 0; i < 6; i++) 
	{
		if(verbose == 3)
			printf("%.2x", *options_padding);
		options_padding += 1;
	}
	if(verbose == 3)
		printf("\n");
	
	destination = (struct ip6_dest*) options_padding;
	
	*taille += sizeof(struct ip6_dest) + 6; //6 octets de options/padding
	
	if(destination->ip6d_len > 0)
	{
		//Options en format TLV
		unsigned int longueur_options_octets = destination->ip6d_len * 8;
		
		gere_options(&options_padding, longueur_options_octets, verbose);
		
		*taille += destination->ip6d_len * 8;
	}
	destination = (struct ip6_dest*) options_padding;
	
	*partie_ipv6 = (struct ip6_hdr*) destination;
}


void gere_extension_ESP(struct ip6_hdr** partie_ipv6, int* taille, unsigned char* next_header, const u_char *packet, const struct pcap_pkthdr *header, int verbose)
{
	struct ip6_ext* extension = (struct ip6_ext*) *(partie_ipv6);
	unsigned char* type_specific_data = (unsigned char*)extension;

	printf("/ESP ");
	
	if(verbose == 1)
		printf("ESP");
	else if(verbose == 2)
		printf(", ESP ");
	else if(verbose == 3)
	{
		//texte en gras et souligné
		printf("\e[1;4m");
		printf("\tEncapsulating Security Payload");

		//remettre le style par défaut
		printf("\033[0m\n");
	}
	
	for(int i = 0; type_specific_data <= &packet[header->len - 1]; i++) //print jusqu'à la fin du paquet
	{
		if(verbose == 3)
			printf("%.2x", *type_specific_data);
		if(type_specific_data == &packet[header->len - 1]) //ne pas incrémenter specific après le dernier octet du paquet
			break;
		type_specific_data += 1;
	}
	return;
}


void gere_extension_inconnue(struct ip6_hdr** partie_ipv6, int* taille, unsigned char* next_header, int verbose)
{
	struct ip6_ext* extension = (struct ip6_ext*) *(partie_ipv6);
	//48 bits options et padding
	unsigned char* type_specific_data = (unsigned char*)extension;
	
	if(verbose == 1 || verbose == 2)
	{
		printf("(extension inconnue)");
	}
	else if(verbose == 3)
	{
		//texte en gras et souligné
		printf("\e[1;4m");
		printf("\tEn-tête d'extension inconnue...");

		//remettre le style par défaut
		printf("\033[0m\n");
		
		print_next_header(extension->ip6e_nxt, 2);
		printf("\t\tHeader length: %u\n", extension->ip6e_len); //vaut 0 si longueur = 64 bits, et si longueur supérieure à 64 bits alors vaut un nombre représentant la longueur de l'en-tête en nombre de 64 bits sans compter les 64 premiers bits
	}
	*next_header = extension->ip6e_nxt;

	if(verbose == 3)
		printf("\t\tType specific data: ");
	for(int i = 0; i < 6; i++) 
	{
		if(verbose == 3)
			printf("%.2x", *type_specific_data);
		type_specific_data += 1;
	}
	if(verbose == 3)
		printf("\n");
	
	if(extension->ip6e_len > 0) //il reste des choses
	{
		for(int i = 0; i < extension->ip6e_len; i++) 
		{
			type_specific_data += i;
			if(verbose == 3)
				printf("%.2x", *type_specific_data);
		}
	}
	
	extension = (struct ip6_ext*) type_specific_data; //pointe après l'en-tête d'extension
	*partie_ipv6 = (struct ip6_hdr*) extension;
	
	*taille += sizeof(struct ip6_ext) + 6 + extension->ip6e_len * 8; 
}


void dechiffrage_ipv6(const u_char *packet, int size_of_lower_layer, const struct pcap_pkthdr *header, int verbose)
{
	struct ip6_hdr* partie_ipv6;	
	partie_ipv6 = (struct ip6_hdr*) (packet + size_of_lower_layer);
	
	if(verbose == 1)
	{
		printf("IPv6");
	}
	else if(verbose == 2)
	{
		//texte en gras et souligné
		printf("\e[1;4m");
		printf("IPV6");

		//remettre le style par défaut
		printf("\033[0m");
		
		printf(", ");
		
		char ipv6_buf_src[INET6_ADDRSTRLEN];
		printf("Src: %s, ", inet_ntop(AF_INET6, partie_ipv6->ip6_src.s6_addr, ipv6_buf_src, 128));
		
		char ipv6_buf_dst[INET6_ADDRSTRLEN];
		printf("Dst: %s ", inet_ntop(AF_INET6, partie_ipv6->ip6_dst.s6_addr, ipv6_buf_dst, 128));
	}
	else if(verbose == 3)
	{
		//fond blanc et police noire
		printf("\n\033[1;30;47m");
		
		printf("Internet Protocol version 6");
		
		//remettre le style par défaut
   		printf("\033[0m\n");
		
		unsigned char version = (htonl(partie_ipv6->ip6_ctlun.ip6_un1.ip6_un1_flow) & 0xF0000000) >> 28;
	
		unsigned char traffic_class = (htonl(partie_ipv6->ip6_ctlun.ip6_un1.ip6_un1_flow) & 0x0FF00000) >> 20;
		
		unsigned int flow_label = htonl(partie_ipv6->ip6_ctlun.ip6_un1.ip6_un1_flow) & 0x000FFFFF;
		
		printf("\tVersion: %.1x\n", version);
		printf("\tTraffic class: %.2x\n", traffic_class);
		printf("\tFlow label: %.5x\n", flow_label);
		
		printf("\tPayload length: %hu\n", htons(partie_ipv6->ip6_ctlun.ip6_un1.ip6_un1_plen));
		print_next_header(partie_ipv6->ip6_ctlun.ip6_un1.ip6_un1_nxt, 1);
		printf("\tHop limit: %u\n", partie_ipv6->ip6_ctlun.ip6_un1.ip6_un1_hlim);
		
		char ipv6_buf_src[INET6_ADDRSTRLEN];
		printf("\tSource address: %s\n", inet_ntop(AF_INET6, partie_ipv6->ip6_src.s6_addr, ipv6_buf_src, 128));
		
		char ipv6_buf_dst[INET6_ADDRSTRLEN];
		printf("\tDestination address: %s\n", inet_ntop(AF_INET6, partie_ipv6->ip6_dst.s6_addr, ipv6_buf_dst, 128));
	
	}
	
	unsigned char next_header = partie_ipv6->ip6_ctlun.ip6_un1.ip6_un1_nxt;
	
	//augmenter le pointeur partie_ipv6 à la fin de la struct ipv6
	unsigned char* pointeur = (unsigned char*) partie_ipv6;
	pointeur += sizeof(struct ip6_hdr);
	partie_ipv6 = (struct ip6_hdr*) pointeur;
	
	int taille = sizeof(struct ip6_hdr); //taille en-tête ipv6 + taille de ou des en-têtes d'extensions en octets
	
	while(next_header != ICMPV6_PROTOCOL && next_header != TCP_PROTOCOL && next_header != UDP_PROTOCOL)
	{
		switch(next_header)
		{
			case 41: //IPv6 dans IPv6
				gere_extension_ipv6(&partie_ipv6, &taille, &next_header, verbose);
				break;
				
			case ROUTING_EXTENSION:
				gere_extension_routing(&partie_ipv6, &taille, &next_header, verbose);
				break;
			
			case FRAGMENT_EXTENSION:
				gere_extension_fragment(&partie_ipv6, &taille, &next_header, verbose);
				break;
			
			case HOP_BY_HOP_EXTENSION:
				gere_extension_hop_by_hop(&partie_ipv6, &taille, &next_header, verbose);
				break;
				
			case DESTINATION_EXTENSION:
				gere_extension_destination(&partie_ipv6, &taille, &next_header, verbose);
				break;
				
			case 50: //cas spécial : ESP (Encapsulating Security Payload)
				gere_extension_ESP(&partie_ipv6, &taille, &next_header, packet, header, verbose);
				break;
			
			default:
				gere_extension_inconnue(&partie_ipv6, &taille, &next_header, verbose);
				break;
		}
	}
	
	if(verbose == 1)
		printf("/");
	else if(verbose == 2)
		printf("\n");
	
	if(next_header == ICMPV6_PROTOCOL)
	{
		dechiffrage_icmpv6(packet, size_of_lower_layer + taille, header, verbose); 
	}
	else if(next_header == TCP_PROTOCOL)
	{
		dechiffrage_tcp(packet, size_of_lower_layer + taille, header, false, verbose);
	}
	else if(next_header == UDP_PROTOCOL)
	{
		dechiffrage_udp(packet, size_of_lower_layer + taille, header, false, verbose);
	}
}



void dechiffrage_icmpv6(const u_char *packet, int size_of_lower_layer, const struct pcap_pkthdr *header, int verbose)
{
	struct icmp6_hdr* partie_icmpv6;
	partie_icmpv6 = (struct icmp6_hdr*) (packet + size_of_lower_layer);
	
	if(verbose == 1)
	{
		printf("ICMPv6 ");
		printf("(type=%u)\n", partie_icmpv6->icmp6_type);
		return;
	}
	else if(verbose == 2)
	{
		//texte en gras et souligné
		printf("\e[1;4m");
		printf("ICMPv6");

		//remettre le style par défaut
		printf("\033[0m");
		
		printf(", ");
		print_type_code_icmpv6(partie_icmpv6->icmp6_type, partie_icmpv6->icmp6_code, verbose);
	}
	else if(verbose == 3)
	{
		//fond blanc et police noire
		printf("\n\033[1;30;47m");
		
		printf("Internet Control Message Protocol Version 6");
		
		//remettre le style par défaut
   		printf("\033[0m\n");
   		
		printf("\tMessage type: (%u) -> ", partie_icmpv6->icmp6_type);
		print_type_code_icmpv6(partie_icmpv6->icmp6_type, partie_icmpv6->icmp6_code, verbose);
		printf("\tChecksum: %.4x\n", htons(partie_icmpv6->icmp6_cksum));
	}

	unsigned char* specific = (unsigned char*)(&partie_icmpv6->icmp6_cksum + 1); 
	
	switch(partie_icmpv6->icmp6_type)
	{
		case ICMP6_DST_UNREACH:
			
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
			break;
			
		case ICMP6_PACKET_TOO_BIG:
			if(verbose == 3)
				printf("\tMTU: ");
			for(int i = 0; i < 4; i++)
			{
				if(verbose == 3)
					printf("%.2x", *specific);
				specific += 1;
			}
			if(verbose == 3)
				printf("\n");
			break;
			
		case ICMP6_TIME_EXCEEDED:
			
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
			break;
			
		case ICMP6_PARAM_PROB:
			
			if(verbose == 3)
				printf("\tPointer: ");
			for(int i = 0; i < 4; i++)
			{
				if(verbose == 3)
					printf("%.2x", *specific);
				specific += 1;
			}
			if(verbose == 3)
				printf("\n");
			break;
			
		case ICMP6_ECHO_REQUEST:
		case ICMP6_ECHO_REPLY:
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
			break;
			
		case ND_NEIGHBOR_SOLICIT:
			if(verbose == 3)
				printf("\tReserved: ");
			for(int i = 0; i < 4; i++)
			{
				if(verbose == 3)
					printf("%.2x", *specific);
				specific += 1;
			}
			if(verbose == 3)
				printf("\n");
			break;
			
		case ND_NEIGHBOR_ADVERT:
			if(verbose == 3)
				printf("\tFlags Router, Solicited et Override: %.2x\n", *specific);
			specific += 1;
			
			if(verbose == 3)
				printf("\tReserved: ");
			for(int i = 0; i < 3; i++)
			{
				if(verbose == 3)
					printf("%.2x", *specific);
				specific += 1;
			}
			if(verbose == 3)
				printf("\n");
			break;
	
		default:
			break;
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
}
