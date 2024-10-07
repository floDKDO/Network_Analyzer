#include "dns.h"
#include <stdbool.h>
#include <stdlib.h>

struct dnshdr
{
	uint16_t id;
	uint16_t flags;
	uint16_t qdcount;
	uint16_t ancount;
	uint16_t nscount;
	uint16_t arcount;
};


void print_domain_name(unsigned char** pointeur, unsigned char* pointeur_base) 
{
	unsigned char* pointeur_temp = *pointeur; //au cas où il y a un pointeur, on garder sauvegardé la valeur de "pointeur" pour retourner au bon endroit 
	bool pointer_used = false;
	
	if(**pointeur == 0) //cas spécial : type OPT a un nom vide
	{
		printf("<Root>\n");
		*pointeur += 1;
		return;
	}
	
	//afficher le nom de domaine et prendre compte des éventuels pointeurs
	while(*pointeur_temp != 0)
	{		
		uint16_t test_pointeur = ((*pointeur_temp & 0b11000000) << 8) ;
		uint16_t offset = ((*pointeur_temp & 0b00111111) << 8) | *(pointeur_temp+1); 
		
		if(test_pointeur == 0b1100000000000000) //pointeur trouvé
		{
			pointeur_temp = pointeur_base + offset; //pointe sur la taille 
			if(pointer_used == false)
				*pointeur += 2; //on ajoute les 2 octets du pointeur
			pointer_used = true;
		}
		else
		{
			unsigned char size = *pointeur_temp;
			
			pointeur_temp += 1;
			if(pointer_used == false)
			{
				*pointeur += 1;
			}
			
			for(int i = 0; i < size; i++)
			{
				printf("%c", *(pointeur_temp));
				
				pointeur_temp += 1;
				if(pointer_used == false)
				{
					*pointeur += 1;
				}
			}
			printf(".");
		}
	}
	if(pointer_used == false)
		*pointeur += 1; //passer le 00 de fin
		
	printf("\n");
}


void print_ipv4(uint16_t rdlength, unsigned char** pointeur)
{
	unsigned char data[rdlength];
	
	//remplir le tableau data des hex de l'adresse IPv4
	for(int i = 0; i < rdlength; i++)
	{
		data[i] = **pointeur;
		*pointeur += 1;
	}

	long int adresse = 0;
	struct in_addr addr;
	
	//mettre les hex de l'adresse IPv4 dans le long
	for (int i = 0; i < 4; i++) 
	{
		adresse <<= 8;  
		adresse |= data[i];  
    	}
	addr.s_addr = htonl(adresse);
	char *s = inet_ntoa(addr);
	printf("\t\tAdresse IPv4: %s", s);
	printf("\n");
}


void print_ipv6(uint16_t rdlength, unsigned char** pointeur)
{
	unsigned char data[rdlength];
	
	//remplir le tableau data des hex de l'adresse IPv4
	for(int i = 0; i < rdlength; i++)
	{
		data[i] = **pointeur;
		*pointeur += 1;
	}

	struct in6_addr addr;
	for (int i = 0; i < 16; i++) 
	{
		addr.s6_addr[i] = data[i];
    	}
	char ipv6_buf[INET6_ADDRSTRLEN];
	printf("\t\tAdresse IPv6: %s", inet_ntop(AF_INET6, addr.s6_addr, ipv6_buf, 128));
	printf("\n");
}


void print_4_hex_in_decimal(unsigned char** pointeur)
{
	uint32_t value;
	
	//convertir 4 hex pointés par pointeur en paramètre en un uint32_t 
	for(int i = 0; i < 4; i++)
	{
		value <<= 8;
		value |= **pointeur;
		*pointeur += 1;
	}
	printf("%u\n", value);
}


void print_type_rr_message(uint16_t type)
{
	switch(type)
	{
		case TYPE_A:
			printf("(A)\n");
			break;
			
		case TYPE_NS:
			printf("(NS)\n");
			break;
		
		case TYPE_CNAME:
			printf("(CNAME)\n");
			break;
			
		case TYPE_SOA:
			printf("(SOA)\n");
			break;
			
		case TYPE_PTR:
			printf("(PTR)\n");
			break;
			
		case TYPE_HINFO:
			printf("(HINFO)\n");
			break;
			
		case TYPE_MX:
			printf("(MX)\n");
			break;
			
		case TYPE_TXT:
			printf("(TXT)\n");
			break;
		
		case TYPE_AAAA:
			printf("(AAAA)\n");
			break;
			
		case TYPE_OPT:
			printf("(OPT)\n");
			break;
			
		default:
			printf("(type inconnu...)\n");
			break;
	}
}


void handle_resource_record(uint16_t count, char* type, unsigned char** pointeur, unsigned char* pointeur_base) //pointeur est de type unsigned char** car il est modifié dans la fonction
{
	if(count > 0)
	{
		//texte en gras et souligné
		printf("\e[1;4m");
		printf("\t%s", type);
		//remettre le style par défaut
		printf("\033[0m\n");
	}
	
	for(int i = 0; i < count; i++)
	{	
		if(i > 0)
			printf("\n");
			
		printf("\t\tName: ");
		print_domain_name(pointeur, pointeur_base);
	
		uint16_t type = (*(*pointeur + 1) << 8) | **pointeur;
		type = htons(type);
		printf("\t\tType: %.2x", type);
		
		print_type_rr_message(type);
		
		*pointeur += 2;
		
		//convertir **pointeur et *(*pointeur + 1) en un uint16_t
		uint16_t class = (*(*pointeur + 1) << 8) | **pointeur;
		class = htons(class);
		printf("\t\tClass: %.4x", class);
		
		if(class == CLASS_IN) //IN
		{
			printf("(IN)\n");
		}
		else
		{
			printf("(classe inconnue...)\n");
		}
		*pointeur += 2;
		
		uint16_t gauche_ttl = (*(*pointeur + 1) << 8) | **pointeur;
		gauche_ttl = htons(gauche_ttl);
		*pointeur += 2;
		
		uint16_t droite_ttl = (*(*pointeur + 1) << 8) | **pointeur;
		droite_ttl = htons(droite_ttl);
		*pointeur += 2;
		
		//former ttl à partir de gauche_ttl et droite_ttl
		uint32_t ttl = (gauche_ttl << 16) | droite_ttl;
		printf("\t\tTTL: %u\n", ttl);
		
		uint16_t rdlength = (*(*pointeur + 1) << 8) | **pointeur;
		rdlength = htons(rdlength);
		printf("\t\tRdlength: %u\n", rdlength);
		*pointeur += 2;
		
		if(rdlength > 0)
		{
			unsigned char data[rdlength];
			
			switch(type)
			{
				case TYPE_A:
					print_ipv4(rdlength, pointeur);
					break;
					
				case TYPE_NS:
					printf("\t\tNS: ");
					print_domain_name(pointeur, pointeur_base);
					break;
				
				case TYPE_CNAME:
					printf("\t\tCNAME: ");
					print_domain_name(pointeur, pointeur_base);
					break;
					
				case TYPE_SOA:
					for(int i = 0; i < 2; i++)
					{
						if(i == 0)
							printf("\t\tPrimary name server: ");
						else if(i == 1)
							printf("\t\tResponsible authority's mailbox: ");
					
						print_domain_name(pointeur, pointeur_base);
					}

					printf("\t\tSerial Number: ");
					print_4_hex_in_decimal(pointeur);

					printf("\t\tRefresh Interval: ");
					print_4_hex_in_decimal(pointeur);

					printf("\t\tRetry Interval: ");
					print_4_hex_in_decimal(pointeur);

					printf("\t\tExpire Limit Interval: ");
					print_4_hex_in_decimal(pointeur);

					printf("\t\tMinimum TTL: ");
					print_4_hex_in_decimal(pointeur);
					break;
					
				case TYPE_PTR:
					printf("\t\tName: ");
					print_domain_name(pointeur, pointeur_base);
					break;
					
				case TYPE_MX:
				{
					uint16_t preference = ((**pointeur & 0xF) << 8) | **(pointeur+1);
					printf("\t\tPreference: %d\n", preference);
					*pointeur += 2;
					
					printf("\t\tName: ");
					print_domain_name(pointeur, pointeur_base);
				}
					break;
				
				case TYPE_AAAA:
					print_ipv6(rdlength, pointeur);
					break;
					
				default:
					for(int i = 0; i < rdlength; i++) //cas : texte basique 
					{
						data[i] = **pointeur;
						printf("\t\t%c", data[i]);
						*pointeur += 1;
					}
					break;
			}
		}
	}
}


void dechiffrage_dns(const u_char *packet, int size_of_lower_layer, const struct pcap_pkthdr *header, int verbose)
{
	struct dnshdr* partie_dns;
	partie_dns = (struct dnshdr*) (packet + size_of_lower_layer);

	if(verbose == 1)
	{
		printf("DNS");
		uint16_t flags = htons(partie_dns->flags);
		unsigned char qr = (flags & 0b1000000000000000) >> 15;
		if(qr == 0)
			printf("(Qr=query)\n");
		else if(qr == 1)
			printf("(Qr=response)\n");
			
		return;
	}
	else if(verbose == 2)
	{
		//texte en gras et souligné
		printf("\e[1;4m");
		printf("DNS");

		//remettre le style par défaut
		printf("\033[0m");
		
		printf(" ");
		
		uint16_t flags = htons(partie_dns->flags);
		unsigned char qr = (flags & 0b1000000000000000) >> 15;
		if(qr == 0)
			printf("(Qr=query), ");
		else if(qr == 1)
			printf("(Qr=response), ");
		
		printf("Question Count: %u, ", htons(partie_dns->qdcount));
		printf("Answer Record Count: %u, ", htons(partie_dns->ancount));
		printf("Authority Record Count: %u, ", htons(partie_dns->nscount));
		printf("Additional Record Count: %u\n", htons(partie_dns->arcount));
		return;
	}
	else if(verbose == 3)
	{
		//fond blanc et police noire
		printf("\n\033[1;30;47m");
		
		printf("Domain Name System");
		
		//remettre le style par défaut
   		printf("\033[0m\n");
	}
	
	unsigned char* pointeur_base = (unsigned char*)partie_dns; //sera utile pour les pointeurs
	
	printf("\tId: %.4x\n", htons(partie_dns->id));
	
	uint16_t flags = htons(partie_dns->flags);
	
	unsigned char qr = (flags & 0b1000000000000000) >> 15;
	unsigned char opcode = (flags & 0b0111100000000000) >> 11;
	unsigned char aa = (flags & 0b0000010000000000) >> 10;
	unsigned char tc = (flags & 0b0000001000000000) >> 9;
	unsigned char rd = (flags & 0b0000000100000000) >> 8;
	unsigned char ra = (flags & 0b0000000010000000) >> 7;
	unsigned char z = (flags & 0b0000000001110000) >> 4;
	unsigned char rcode = (flags & 0b0000000000001111);
	
	printf("\tQuery/Response flag: %.1x -> ", qr);
	if(qr == 0)
		printf("query\n");
	else if(qr == 1)
		printf("response\n");
		
	printf("\tOpcode: %.1x\n", opcode);
	printf("\tAuthoritative Answer flag: %.1x\n", aa);
	printf("\tTruncation flag: %.1x\n", tc);
	printf("\tRecursion Desired: %.1x\n", rd);
	printf("\tRecursion Available: %.1x\n", ra);
	printf("\tZero: %.1x\n", z);
	printf("\tResponse Code: %.1x\n", rcode);
	
	uint16_t qdcount = htons(partie_dns->qdcount);
	uint16_t ancount = htons(partie_dns->ancount);
	uint16_t nscount = htons(partie_dns->nscount);
	uint16_t arcount = htons(partie_dns->arcount);
	
	printf("\tQuestion Count: %u\n", htons(partie_dns->qdcount));
	printf("\tAnswer Record Count: %u\n", htons(partie_dns->ancount));
	printf("\tAuthority Record Count: %u\n", htons(partie_dns->nscount));
	printf("\tAdditional Record Count: %u\n", htons(partie_dns->arcount));
	
	if(qdcount > 0)
	{
		//texte en gras et souligné
		printf("\e[1;4m");
		printf("\tQUESTION");
		//remettre le style par défaut
		printf("\033[0m\n");
	}
		
	unsigned char* pointeur = (unsigned char*)(&partie_dns->arcount + 1); //pointer sur la partie Question

	for(int i = 0; i < qdcount; i++)
	{	
		if(i > 0)
			printf("\n");
			
		printf("\t\tName: ");
		print_domain_name(&pointeur, pointeur_base);
		
		uint16_t type = (*(pointeur + 1) << 8) | *pointeur;
		type = htons(type);
		printf("\t\tQuestion type: %u", type);
		pointeur += 2;
		
		print_type_rr_message(type);
		
		uint16_t class = (*(pointeur + 1) << 8) | *pointeur;
		class = htons(class);
		
		printf("\t\tQuestion class: ");
		for(int i = 0; i < 2; i++)
		{
			printf("%.2x", *pointeur);
			pointeur += 1;
		}
		
		if(class == CLASS_IN) //IN
		{
			printf("(IN)\n");
		}
		else
		{
			printf("(classe inconnue...)\n");
		}
	}
	
	handle_resource_record(ancount, "ANSWER", &pointeur, pointeur_base);
	handle_resource_record(nscount, "AUTHORITY", &pointeur, pointeur_base);
	handle_resource_record(arcount, "ADDITIONAL", &pointeur, pointeur_base);
}
