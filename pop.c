#include "pop.h"
#include <strings.h>


void gere_serveur_pop(unsigned char** pointeur, const u_char *packet, const struct pcap_pkthdr *header)
{
	printf("\tResponse indicator: ");
	while(**pointeur != ' ' && **pointeur != '\r') //récupérer l'indicateur
	{
		printf("%c", **pointeur);
		*pointeur += 1; 
	}
	printf("\n");
	
	*pointeur += 1; //ne pas afficher l'espace
	
	printf("\tResponse description: ");
	
	while(**pointeur != '\r' && *(*pointeur+1) !='\n')
	{
		printf("%c", **pointeur);
		*pointeur += 1;
		if(*(*pointeur-1) == '\n')
			printf("\t");
	}
	//ici, pointeur pointe sur \r
	
	printf("\t");
	while(*pointeur <= &packet[header->len - 1]) 
	{
		printf("%c", **pointeur);
		if(*pointeur == &packet[header->len - 1]) //ne pas incrémenter pointeur après le dernier octet du paquet
			break;
		*pointeur += 1;
		if(*(*pointeur-1) == '\n')
			printf("\t");
	}
}

void gere_client_pop(unsigned char** pointeur)
{
	printf("\tRequested command: ");
	while(**pointeur != ' ' && **pointeur != '\r') //récupérer la commande
	{
		printf("%c", **pointeur);
		*pointeur += 1; 
	}
	printf("\n");
	
	if(**pointeur == ' ')
	{
		*pointeur += 1; //ne pas print l'espace
		printf("\tRequested parameter: ");
	}
	else printf("\t");
	
	while(**pointeur != '\r' && *(*pointeur+1) !='\n')
	{
		printf("%c", **pointeur);
		*pointeur += 1;
	}
}

      
void dechiffrage_pop(const u_char *packet, int size_of_lower_layer, const struct pcap_pkthdr *header, bool is_server, int verbose)
{
	unsigned char* pointeur = (unsigned char*) (packet + size_of_lower_layer);
	
	if(verbose == 1)
	{
		printf("POP ");
	}
	else if(verbose == 2)
	{
		//texte en gras et souligné
		printf("\e[1;4m");
		printf("POP");

		//remettre le style par défaut
		printf("\033[0m");
		
		printf(" ");
	}
	else if(verbose == 3)
	{
		//fond blanc et police noire
		printf("\n\033[1;30;47m");
		
		printf("Post Office Protocol Version 3");
		
		//remettre le style par défaut
   		printf("\033[0m\n");
	}
	
	bool is_text = false;
	char commande[4] = {*pointeur, *(pointeur+1), *(pointeur+2), *(pointeur+3)};
	
	if(!(strcasecmp(commande, "QUIT") == 0 || strcasecmp(commande, "STAT") == 0 || strcasecmp(commande, "LIST") == 0 || strcasecmp(commande, "RETR") == 0 || strcasecmp(commande, "DELE") == 0 || strcasecmp(commande, "NOOP") == 0 || strcasecmp(commande, "RSET") == 0 || strcasecmp(commande, "TOP ") == 0 || strcasecmp(commande, "UIDL") == 0 || strcasecmp(commande, "USER") == 0 || strcasecmp(commande, "PASS") == 0 || strcasecmp(commande, "APOP") == 0 || strcasecmp(commande, "CAPA") == 0 || strcasecmp(commande, "AUTH") == 0) && is_server == false) 
	{
		//cas où le client envoie du texte, donc pas de commande
		is_text = true;
	}
	
	if(verbose == 1)
	{
		if(is_server == true)
			printf("(serveur)");
		else printf("(client)");
		
		return;
	}
	else if(verbose == 2)
	{
		if(is_server == true)
		{
			printf("(serveur), ");
			printf("Code: %s", commande);
		}
		else 
		{
			printf("(client), ");
			if(is_text == false)
				printf("Commande: %s", commande);
			else printf("Texte envoyé");
		}
		return;
	}
	
	//le message peut commencer par du texte => partie texte du message
	if(is_text == true)
	{
		printf("\tLine-based text data: ");
		while(pointeur <= &packet[header->len - 1]) //tant que la fin du paquet n'est pas atteinte
		{
			printf("%c", *pointeur);
			if(pointeur == &packet[header->len - 1]) //ne pas incrémenter pointeur après le dernier octet du paquet
				break;
			pointeur += 1;
		}
	}
	else
	{
		if(is_server == true)
		{
			gere_serveur_pop(&pointeur, packet, header);
		}
		else //client
		{
			gere_client_pop(&pointeur);
		}
	}
}
