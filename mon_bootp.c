#include "mon_bootp.h"
#include <stdbool.h>
#include <stdlib.h>
#include <netinet/ether.h>

enum mode_print
{
	PRINT_ADRESSE_IP,
	PRINT_STRING,
	PRINT_HEX,
	PRINT_INT
};


void affiche_type_option_message(unsigned char type, enum mode_print* mode, bool* is_padding)
{
	switch(type)
	{
		case TAG_PAD:
			if(*is_padding == false)
				printf("\t\tPadding: ");
			*mode = PRINT_HEX;
			*is_padding = true;
			break;
		
		case TAG_SUBNET_MASK:
			printf("\t\tSubnet mask: ");
			*mode = PRINT_ADRESSE_IP;
			break;
			
		case TAG_TIME_OFFSET:
			printf("\t\tTime offset: ");
			*mode = PRINT_HEX;
			break;
			
		case TAG_GATEWAY:
			printf("\t\tRouter: ");
			*mode = PRINT_ADRESSE_IP;
			break;
			
		case TAG_DOMAIN_SERVER:
			printf("\t\tDNS: ");
			*mode = PRINT_ADRESSE_IP;
			break;
			
		case TAG_HOSTNAME:
			printf("\t\tHost name: ");
			*mode = PRINT_STRING;
			break;
			
		case TAG_DOMAINNAME:
			printf("\t\tDomain name: ");
			*mode = PRINT_STRING;
			break;
			
		case TAG_BROAD_ADDR:
			printf("\t\tBroadcast address: ");
			*mode = PRINT_ADRESSE_IP;
			break;
			
		case TAG_NETBIOS_NS:
			printf("\t\tNetbios over TCP/IP name server: ");
			*mode = PRINT_ADRESSE_IP;
			break;
			
		case TAG_NETBIOS_SCOPE:
			printf("\t\tNetbios over TCP/IP scope: ");
			*mode = PRINT_ADRESSE_IP;
			break;
			
		case TAG_REQUESTED_IP :
			printf("\t\tRequested IP address: ");
			*mode = PRINT_ADRESSE_IP;
			break;
		
		case TAG_IP_LEASE:
			printf("\t\tLease time: ");
			*mode = PRINT_INT;
			break;
		
		case TAG_DHCP_MESSAGE:
			printf("\t\tDHCP message type: ");
			*mode = PRINT_HEX;
			break;
		
		case TAG_SERVER_ID:
			printf("\t\tServer identifier: ");
			*mode = PRINT_ADRESSE_IP;
			break;
		
		case TAG_PARM_REQUEST:
			printf("\t\tParameter request list: ");
			*mode = PRINT_HEX;
			break;
		
		case TAG_CLIENT_ID:
			printf("\t\tClient identifier: ");
			*mode = PRINT_HEX;
			break;
		
		case TAG_RENEWAL_TIME:
			printf("\t\tRenewal time: ");
			*mode = PRINT_INT;
			break;
			
		case TAG_REBIND_TIME:
			printf("\t\tRebind time: ");
			*mode = PRINT_INT;
			break;
			
		case TAG_END:
			printf("\t\tEnd: ");
			*mode = PRINT_HEX;
			break;
			
		default:
			printf("\t\tOption inconnue: ");
			*mode = PRINT_HEX;
			break;
	}
}


void affiche_type_dhcp_message(unsigned char type)
{
	switch(type)
	{
		case DHCPDISCOVER:
			printf(" -> DHCP Discover");
			break;
			
		case DHCPOFFER:
			printf(" -> DHCP Offer");
			break;
			
		case DHCPREQUEST:
			printf(" -> DHCP Request");
			break;
			
		case DHCPDECLINE:
			printf(" -> DHCP Decline");
			break;
			
		case DHCPACK:
			printf(" -> DHCP Ack");
			break;
			
		case DHCPNAK:
			printf(" -> DHCP Nack");
			break;
			
		case DHCPRELEASE:
			printf(" -> DHCP Release");
			break;
			
		case DHCPINFORM:
			printf(" -> DHCP Inform");
			break;
		
		default:
			break;
	}
}


void gere_options_bootp(struct bootp* partie_bootp, const u_char *packet, const struct pcap_pkthdr *header, int verbose)
{
	int indice = 4; //commencer à l'indice suivant le magic cookie
	
	enum mode_print mode = PRINT_HEX;
	bool is_padding = false;
	
	bool une_fois = false; //utilisée pour afficher une seule fois le texte OPTIONS

	while(&partie_bootp->bp_vend[indice] <= &packet[header->len - 1]) //tant que la fin du paquet n'est pas atteinte
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
		
		struct option_tlv option = {0};
		option.type = partie_bootp->bp_vend[indice];
		
		if(verbose == 3)
		{
			affiche_type_option_message(option.type, &mode, &is_padding);
		}

		if(&partie_bootp->bp_vend[indice] == &packet[header->len - 1])
		{
			indice += 1;
		}
		else
		{
			indice += 1;
			option.length = partie_bootp->bp_vend[indice]; //champ suivant
		}
		
		if(verbose == 3)
		{
			if(is_padding == false)
				printf("Type %u, Length: %.2x", option.type, option.length);
			else printf("00");
		}
		
		if(option.length > 0)
		{
			indice += 1;
			
			if(verbose == 3)
				printf(", Value: ");

			unsigned char value[option.length]; //ATTENTION : le champ Length indique uniquement la longueur du champ Value et non de toute l'option comme en IPv4
			for(int j = 0; j < option.length; j++) 
			{
				value[j] = partie_bootp->bp_vend[indice];
				indice += 1;
				if(mode == PRINT_STRING)
				{
					if(verbose == 3)
						printf("%c", value[j]);
				}
				else if(mode == PRINT_HEX)
				{
					if(verbose == 3)
						printf("%.2x", value[j]);
				}
			}
			
			if(verbose == 3)
			{
				//on ne peut print adresse IP et int qu'une fois qu'on a tout récupéré
				if(mode == PRINT_ADRESSE_IP) //print toutes les adresses IPv4
				{
					int choix_adresse = 0; //est incrémenté de 4 à chaque tour de boucle k pour atteindre chaque adresse
					for(int k = 0; k < option.length / 4; k++)
					{
						long int adresse = 0;
						struct in_addr addr;
						for (int i = 0 + choix_adresse; i < 4 + choix_adresse; i++) 
						{
							adresse <<= 8;  
							adresse |= value[i]; 
					    	}
						addr.s_addr = htonl(adresse);
						char *s = inet_ntoa(addr);
						char buf[48];
						if(snprintf(buf, 48, "%s", s) >= sizeof(buf))
						{
							fprintf(stderr, "erreur : snprintf\n");
							exit(1);
						}
						printf("%s", buf);
						choix_adresse += 4;
					}

				}
				else if(mode == PRINT_INT)
				{
					uint32_t nombre = 0;
					for (int i = 0; i < 4; i++) 
					{
						nombre <<= 8;  
						nombre |= value[i];  
				    	}
					printf("%d", nombre);
				}
			}
			
			//longueur = 1 => type est dans value[0]
			if(option.type == TAG_DHCP_MESSAGE)
			{
				affiche_type_dhcp_message(value[0]);
			}
		}
		if(verbose == 3 && is_padding == false)
			printf("\n");
		mode = PRINT_HEX; //reset du mode en hex par défaut
	}
}


void dechiffrage_bootp(const u_char *packet, int size_of_lower_layer, const struct pcap_pkthdr *header, int verbose)
{
	struct bootp* partie_bootp;
	partie_bootp = (struct bootp*) (packet + size_of_lower_layer);
	
	if(verbose == 1)
	{
		printf("BOOTP -> ");
	}
	else if(verbose == 2)
	{
		//texte en gras et souligné
		printf("\e[1;4m");
		printf("BOOTP");

		//remettre le style par défaut
		printf("\033[0m");
		
		printf(", ");
	}
	else if(verbose == 3)
	{
		//fond blanc et police noire
		printf("\n\033[1;30;47m");
		
		printf("Bootstrap Protocol");
		
		//remettre le style par défaut
   		printf("\033[0m\n");
		
		printf("\tOperation Code: ");
	}
	
	
	if(partie_bootp->bp_op == BOOTREQUEST)
		printf("Bootp Request");
	else if(partie_bootp->bp_op == BOOTREPLY)
		printf("Bootp Reply");
		
	if(verbose == 3)
	{	
		printf(" (%u)\n", partie_bootp->bp_op);
		
		uint8_t hardware_type = partie_bootp->bp_htype;
		if(hardware_type == 1)
			printf("\tHardware Address Type: Ethernet (%u)\n", hardware_type);
		else printf("\tHardware Address Type: %u\n", hardware_type);
		
		printf("\tHardware Address Length: %u\n", partie_bootp->bp_hlen);
		printf("\tHops: %u\n", partie_bootp->bp_hops);
		printf("\tTransaction Identifier: %.8x\n", htonl(partie_bootp->bp_xid));
		printf("\tSeconds: %u\n", htons(partie_bootp->bp_secs));
		
		uint16_t flags = htons(partie_bootp->bp_flags);
		printf("\tFlags: %.4x", flags); 
		if(flags == 0x8000) //si = 0x8000, alors broadcast
			printf(" (broadcast)\n");
		else if(flags == 0x0000)
			printf(" (unicast)\n");
		
		struct in_addr client_ip_address;
		client_ip_address = partie_bootp->bp_ciaddr;
		printf("\tClient IP Address: %s\n", inet_ntoa(client_ip_address));
		
		struct in_addr your_ip_address;
		your_ip_address = partie_bootp->bp_yiaddr;
		printf("\tYour IP Address: %s\n", inet_ntoa(your_ip_address));
		
		struct in_addr serveur_ip_address;
		serveur_ip_address = partie_bootp->bp_siaddr;
		printf("\tServer IP Address: %s\n", inet_ntoa(serveur_ip_address));
		
		struct in_addr gateway_ip_address;
		gateway_ip_address = partie_bootp->bp_giaddr;
		printf("\tGateway IP Address: %s\n", inet_ntoa(gateway_ip_address));
		
		printf("\tClient Hardware Address: ");
		
		struct ether_addr eth_addr;
		for (int i = 0; i < ETHER_ADDR_LEN; i++) 
		{
			eth_addr.ether_addr_octet[i] = partie_bootp->bp_chaddr[i];  
	    	}
		char* s = ether_ntoa(&eth_addr);
		printf("%s\n", s);
		
		printf("\tServer Host Name: ");
		for(int i = 0; i < 64; i++)
		{
			printf("%c", partie_bootp->bp_sname[i]);
		}
		printf("\n");
		
		printf("\tBoot File Name: ");
		for(int i = 0; i < 128; i++)
		{
			printf("%c", partie_bootp->bp_file[i]);
		}
		printf("\n");
		
		printf("\tVendor Specific Area / Options: \n"); //si magic cookie sur les 4 premiers octets, alors ce champ est utilisé
		
		u_int8_t magic_cookie[4] = VM_RFC1048; //valeur du magic cookie dans bootp.h
		bool is_magic_cookie = true;
		
		for(int i = 0; i < 4; i++)
		{
			if(partie_bootp->bp_vend[i] != magic_cookie[i])
			{
				is_magic_cookie = false;
				break;
			}
		}
		
		if(is_magic_cookie == true)
			printf("\tMagic cookie present!\n");
	}
	
	gere_options_bootp(partie_bootp, packet, header, verbose);
}

