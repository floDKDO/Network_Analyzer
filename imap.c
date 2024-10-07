#include "imap.h"
#include <string.h>


void print_arg(unsigned char** pointeur, int verbose)
{
	while(**pointeur != ' ') //récupérer l'argument
	{
		if(verbose == 3)
			printf("%c", **pointeur);
		*pointeur += 1; 
	}
	if(verbose == 3)
		printf("\n");
	*pointeur += 1;
}


void gere_serveur_imap(unsigned char** pointeur, const u_char *packet, const struct pcap_pkthdr *header, int verbose)
{
	while(*pointeur <= &packet[header->len - 1]) 
	{
		if(**pointeur != '*')
		{
			//tag
			printf("\tResponse tag: ");
			print_arg(pointeur, verbose); //récupérer le tag
			
			printf("\tResponse status: ");
			print_arg(pointeur, verbose); //récupérer le status (OK, ERR, BAD)
			
			if(**pointeur == '[')
			{
				printf("\t");
				print_arg(pointeur, verbose); //récupérer l'info entre crochets
			}
			
			printf("\tResponse command: ");
			print_arg(pointeur, verbose); //récupérer la commande
		}
		
		printf("\t");
		while(**pointeur != '\r' && *(*pointeur+1) !='\n') 
		{
			printf("%c", **pointeur);
			*pointeur += 1;
		}
		*pointeur += 1; //pointer sur \n
		printf("\n");
		*pointeur += 1; //pointer après le \n
	}
}

void gere_client_imap(unsigned char** pointeur, const u_char *packet, const struct pcap_pkthdr *header, int verbose)
{
	//tag
	if(verbose == 3)
	{
		printf("\tTag: ");
	}
	print_arg(pointeur, verbose); //récupérer le tag
	
	char commande[14]; //longueur max = "AUTHENTIFICATE"
	int i = 0;
	
	printf("\tCommande: ");
	while(true) //récupérer la commande
	{
		printf("%c", **pointeur);
		commande[i] = **pointeur;
		*pointeur += 1; 
		i += 1;
		if(**pointeur == ' ' || **pointeur == '\r')
			break;
	}
	printf("\n");
	if(verbose == 2)
		return;
	
	bool is_tabulation = true;
	
	if(strcmp(commande, "AUTHENTIFICATE") == 0)
	{
		*pointeur += 1; //pointer sur la premiere lettre de l'agument
		printf("\tAuthentication mechanism name: ");
		print_arg(pointeur, verbose); //récupérer l'argument
	}
	else if(strcmp(commande, "LOGIN") == 0)
	{
		*pointeur += 1; //pointer sur la premiere lettre de l'agument
		printf("\tUser name: ");
		print_arg(pointeur, verbose); //récupérer l'argument
		
		printf("\tPassword: ");
		is_tabulation = false;
	}
	else if(strcmp(commande, "SELECT") == 0 || strcmp(commande, "EXAMINE") == 0 || strcmp(commande, "CREATE") == 0 || strcmp(commande, "DELETE") == 0 || strcmp(commande, "SUBSCRIBE") == 0 || strcmp(commande, "UNSUBSCRIBE") == 0)
	{
		*pointeur += 1; //pointer sur la premiere lettre de l'agument
		
		printf("\tMailbox name: ");
		print_arg(pointeur, verbose); //récupérer l'argument
	}
	else if(strcmp(commande, "RENAME") == 0)
	{
		*pointeur += 1; //pointer sur la premiere lettre de l'agument
		printf("\tExisting mailbox name: ");
		print_arg(pointeur, verbose); //récupérer l'argument	
		
		printf("\tNew mailbox name: ");
		print_arg(pointeur, verbose); //récupérer l'argument
	}
	else if(strcmp(commande, "LIST") == 0 || strcmp(commande, "LSUB") == 0)
	{
		*pointeur += 1; //pointer sur la premiere lettre de l'agument
		printf("\tReference name: ");
		print_arg(pointeur, verbose); //récupérer l'argument
			
		printf("\tMailbox name with possible wildcards: ");	
		is_tabulation = false;
	}
	else if(strcmp(commande, "STATUS") == 0)
	{
		*pointeur += 1; //pointer sur la premiere lettre de l'agument
		printf("\tMailbox name: ");
		print_arg(pointeur, verbose); //récupérer l'argument
			
		printf("\tStatus data item names: ");	
		is_tabulation = false;		
	}
	else if(strcmp(commande, "APPEND") == 0)
	{
		//ici, on incrémente pas pointeur car on veut qu'il pointe sur l'espace après la commande pour compter le nombre d'arguments car il peut y avoir un ou deux arguments optionnels pour cette commande
		char* temp_pointeur = *pointeur;
		int nb_arg = 0; 
		
		while(*temp_pointeur != '\r' && *(temp_pointeur+1) !='\n') //compter le nombre d'espace => nombre d'arguments pour cette commande
		{
			if(*temp_pointeur == ' ')
				nb_arg += 1;
			temp_pointeur += 1;
		}
		
		printf("\tMailbox name: ");
		print_arg(pointeur, verbose); //récupérer l'argument
		
		if(nb_arg == 3)
		{
			printf("\tArgument: ");
			print_arg(pointeur, verbose); //récupérer l'argument
		}
		else if(nb_arg == 4)
		{
			printf("\tFlag parenthesized list: ");	
			print_arg(pointeur, verbose); //récupérer l'argument
		
			printf("\tDate/time string: ");	
			print_arg(pointeur, verbose); //récupérer l'argument
		}
		printf("\tMessage literal: ");	
		print_arg(pointeur, verbose); //récupérer l'argument
	}
	else if(strcmp(commande, "SEARCH") == 0)
	{
		//ici, on incrémente pas pointeur car on veut qu'il pointe sur l'espace après la commande pour compter le nombre d'arguments car il peut y avoir un argument optionnel pour cette commande
		char* temp_pointeur = *pointeur;
		int nb_arg = 0; 
		
		while(*temp_pointeur != '\r' && *(temp_pointeur+1) !='\n') //compter le nombre d'espace => nombre d'arguments pour cette commande
		{
			if(*temp_pointeur == ' ')
				nb_arg += 1;
			temp_pointeur += 1;
		}
		
		if(nb_arg == 2)
		{
			printf("\tSpecification: "); 
			print_arg(pointeur, verbose); //récupérer l'argument
		}
		
		printf("\tSearching criteria: ");
		print_arg(pointeur, verbose); //récupérer l'argument
	}
	else if(strcmp(commande, "FETCH") == 0)
	{
		*pointeur += 1; //pointer sur la premiere lettre de l'agument
		printf("\tSequence set: ");
		print_arg(pointeur, verbose); //récupérer l'argument
		
		printf("\tMessage data item names or macro: ");	
		is_tabulation = false;	
	}
	else if(strcmp(commande, "STORE") == 0)
	{
		*pointeur += 1; //pointer sur la premiere lettre de l'agument
		printf("\tSequence set: ");	
		print_arg(pointeur, verbose); //récupérer l'argument
		
		printf("\tMessage data item name: ");
		print_arg(pointeur, verbose); //récupérer l'argument
		
		printf("\tValue for message data item: ");
		print_arg(pointeur, verbose); //récupérer l'argument		
	}
	else if(strcmp(commande, "COPY") == 0)
	{
		*pointeur += 1; //pointer sur la premiere lettre de l'agument
		printf("\tSequence set: ");
		print_arg(pointeur, verbose); //récupérer l'argument
		
		printf("\tMailbox name: ");
		print_arg(pointeur, verbose); //récupérer l'argument
	}
	else if(strcmp(commande, "UID") == 0)
	{
		*pointeur += 1; //pointer sur la premiere lettre de l'agument
		printf("\tCommand name: ");
		print_arg(pointeur, verbose); //récupérer l'argument
		
		printf("\tCommand arguments: ");
		print_arg(pointeur, verbose); //récupérer l'argument
	}
	
	if(is_tabulation == true)
		printf("\t");
	//tout afficher jusqu'à la fin du paquet
	while(*pointeur <= &packet[header->len - 1]) 
	{
		printf("%c", **pointeur);
		if(*pointeur == &packet[header->len - 1]) //ne pas incrémenter pointeur après le dernier octet du paquet
			break;
		*pointeur += 1;
	}
}


void dechiffrage_imap(const u_char *packet, int size_of_lower_layer, const struct pcap_pkthdr *header, bool is_server, int verbose)
{
	unsigned char* pointeur = (unsigned char*) (packet + size_of_lower_layer);
	
	if(verbose == 1)
	{
		printf("IMAP ");
		if(is_server == true)
			printf("(serveur)");
		else printf("(client)");

		return;
	}
	else if(verbose == 2)
	{
		//texte en gras et souligné
		printf("\e[1;4m");
		printf("IMAP");

		//remettre le style par défaut
		printf("\033[0m");
		
		printf(" ");
		if(is_server == true)
		{
			printf("(serveur)");
			return;
		}
		else printf("(client),");
	}
	else if(verbose == 3)
	{
		//fond blanc et police noire
		printf("\n\033[1;30;47m");
		
		printf("Internet Message Access Protocol");
		
		//remettre le style par défaut
   		printf("\033[0m\n");
	}
	
	if(is_server == true)
	{	
		gere_serveur_imap(&pointeur, packet, header, verbose);
	}
	else
	{
		gere_client_imap(&pointeur, packet, header, verbose);
	}
}
