#include "http1.h"
#include <string.h>


void affiche_status_code_message(char status_code)
{
	switch(status_code)
	{
		case '1': 
			printf("-> Informational - Not used, but reserved for future use");
			break;
			
		case '2': 
			printf("-> Success - The action was successfully received, understood, and accepted");
			break;
			
		case '3': 
			printf("-> Redirection - Further action must be taken in order to complete the request");
			break;
			
		case '4': 
			printf("-> Client Error - The request contains bad syntax or cannot be fulfilled");
			break;
			
		case '5': 
			printf("-> Server Error - The server failed to fulfill an apparently valid request");
			break;
			
		default:
			break;
	}
	printf("\n");
}



void affiche_contenu(unsigned char** pointeur, const u_char *packet, const struct pcap_pkthdr *header)
{
	while(**pointeur != '\r' || *(*pointeur+1) != '\n' || *(*pointeur+2) != '\r' || *(*pointeur+3) != '\n') //cas en-tête(s) => on s'arrête quand on rencontre \r\n\r\n
	{
		printf("%c", **pointeur);
		if(*(*pointeur) == '\n')
			printf("\t");
		if(*pointeur == &packet[header->len - 1]) //ne pas incrémenter pointeur après le dernier octet du paquet
			break;
		*pointeur += 1;
	}
	//ici, pointeur pointe sur \r
	
	*pointeur += 1; //pointe sur \n
	*pointeur += 1; //pointe sur \r
	*pointeur += 1; //pointe sur \n
	
	//afficher l'éventuel corps
	while(*pointeur <= &packet[header->len - 1]) //tant que la fin du paquet n'est pas atteinte
	{

		printf("%C", **pointeur);
		if(*(*pointeur) == '\n')
			printf("\t");
		if(*pointeur == &packet[header->len - 1]) //ne pas incrémenter pointeur après le dernier octet du paquet
			break;
		*pointeur += 1; 
	}
}


void gere_serveur_http1(unsigned char** pointeur, const u_char *packet, const struct pcap_pkthdr *header, int verbose)
{
	if(verbose == 3)
		printf("\t(serveur)\n");
	else printf("(serveur), ");
	
	char version[5]; //récupérer l'éventuel HTTP/ pour différencier une full_response d'une simple response
	char* temp_pointeur = *pointeur;
	
	//ne pas avancer le pointeur, juste pour tester
	for(int i = 0; i < 5; i++)
	{
		version[i] = *temp_pointeur;
		temp_pointeur += 1;
	}
	
	if(strcmp(version, "HTTP/") == 0)
	{
		if(verbose == 3)
			printf("\tRequest version: "); //print version, vaut 0 si HTTP/1.0, ou 1 si HTTP/1.1
		
		//afficher HTTP/1.x
		for(int i = 0; i < 8; i++)
		{
			printf("%c", **pointeur);
			*pointeur += 1;
		}
		
		if(verbose == 2)
		{
			printf(" ");
		}
		else if(verbose == 3)
			printf("\n");
			
		*pointeur += 1; //pointe sur le premier chiffre de status_code
		
		char status_code[3];
		
		if(verbose == 3)
			printf("\tStatus code: ");
		
		//afficher le status code
		for(int i = 0; i < 3; i++)
		{
			printf("%c", **pointeur);
			status_code[i] = **pointeur;
			*pointeur += 1;
		}

		if(verbose == 3)
		{
			affiche_status_code_message(status_code[0]);
		}
		
		//on pointe actuellement sur l'espace 
		
		if(verbose == 3)
			printf("\tReason phrase:");
			
		//afficher reason phrase
		while(**pointeur != '\r')
		{
			printf("%c", **pointeur);
			*pointeur += 1;
		}
		
		if(verbose == 2)
			return;
		else if(verbose == 3)
			printf("\n");
	}
	//ici, on pointe sur \r
	
	*pointeur += 1; //pointer sur \n
	
	printf("\t");
	*pointeur += 1; //pointer sur l'éventuelle en-tête ou CRLF
		
	affiche_contenu(pointeur, packet, header);
}


void gere_client_http1(unsigned char** pointeur, const u_char *packet, const struct pcap_pkthdr *header, int verbose)
{
	if(verbose == 3)
		printf("\t(client)\n");
	else printf("(client), ");
	
	char request_method[4];
	for(int i = 0; i < 4; i++)
	{
		request_method[i] = **pointeur;
		*pointeur += 1;
	}
	
	if(verbose == 3)
		printf("\tRequest method: ");
	if(strcmp(request_method, "GET ") == 0)
	{
		printf("GET ");
		*pointeur -= 1; //comme cette commande fait 3 lettres, on va d'une case en arrière pour être au même niveau que les deux autres commandes
	}
	else if(strcmp(request_method, "HEAD") == 0)
	{
		printf("HEAD ");
	}
	else if(strcmp(request_method, "POST") == 0)
	{
		printf("POST ");
	}
	else if(strcmp(request_method, "PUT ") == 0)
	{
		printf("PUT ");
		*pointeur -= 1; //comme cette commande fait 3 lettres, on va d'une case en arrière pour être au même niveau que les deux autres commandes
	}
	else if(strcmp(request_method, "DELE") == 0) //DELETE
	{
		printf("DELETE ");
		*pointeur += 2; //ajouter 'T' et 'E'
	}
	else if(strcmp(request_method, "TRAC") == 0) //TRACE
	{
		printf("TRACE ");
		*pointeur += 1; //ajouter 'E'
	}
	else if(strcmp(request_method, "CONN") == 0) //CONNECT
	{
		printf("CONNECT ");
		*pointeur += 3; //ajouter 'E', 'C' et 'T'
	}
	else if(strcmp(request_method, "OPTI") == 0) //OPTIONS
	{
		printf("OPTIONS ");
		*pointeur += 3; //ajouter 'O', 'N' et 'S'
	}
	else
	{
		printf("%s ", request_method);
	}
	//on pointe actuellement sur l'espace 
	
	if(verbose == 1)
		return;
	
	//on pointe sur la première lettre de l'url_voulue
	*pointeur += 1;
	
	bool is_full_request = false;
	
	if(verbose == 3)
		printf("\n\tRequest URL: ");
	
	//afficher l'url et regarder si cette requête est une full request ou non
	while(**pointeur != ' ' && **pointeur != '\r')
	{
		printf("%c", **pointeur);
		*pointeur += 1;
		
		if(**pointeur == ' ')
		{
			is_full_request = true;
		}
		else if(**pointeur == '\r')
		{
			is_full_request = false;
		}
	}
	if(verbose == 3)
		printf("\n");
	
	int version; //vaut 0 si HTTP/1.0, ou 1 si HTTP/1.1
	if(is_full_request == true)
	{
		*pointeur += 1; //pointer sur la première lettre de HTTP-x
		
		if(verbose == 2)
			printf(" ");
		else if(verbose == 3)
			printf("\tRequest version: ");
		
		for(int i = 0; i < 8; i++) //HTTP/1.x possède 8 lettres
		{
			printf("%c", **pointeur);
			
			if(i == 7)
				version = **pointeur; //récupérer version
				
			*pointeur += 1;
		}
		if(verbose == 3)
			printf("\n");
	}
	
	if(verbose == 2)
		return;
	
	//ici, on pointe sur \r
	
	*pointeur += 1; //pointer sur \n
	printf("\t");
	
	if(is_full_request == true || version == 1) //avec HTTP/1.1, il n'y a plus de simple_request ou de full_request : on parle de request
	{
		*pointeur += 1; //pointer sur l'éventuelle en-tête ou CRLF
		affiche_contenu(pointeur, packet, header);
	}
}

      
void dechiffrage_http1(const u_char *packet, int size_of_lower_layer, const struct pcap_pkthdr *header, bool is_server, int verbose)
{
	unsigned char* pointeur = (unsigned char*) (packet + size_of_lower_layer);
	
	if(verbose == 1)
	{
		printf("HTTP ");
		if(is_server == true)
		{
			printf("(serveur)");
			return;
		}
		else 
		{
			printf("(client)");
			return;
		}
	}
	else if(verbose == 2)
	{
		//texte en gras et souligné
		printf("\e[1;4m");
		printf("HTTP");

		//remettre le style par défaut
		printf("\033[0m");
		
		printf(" ");
	}
	else if(verbose == 3)
	{
		//fond blanc et police noire
		printf("\n\033[1;30;47m");
		
		printf("Hypertext Transfer Protocol");
		
		//remettre le style par défaut
   		printf("\033[0m\n");
	}
	
	if(is_server == true)
	{
		gere_serveur_http1(&pointeur, packet, header, verbose);
	}
	else
	{
		gere_client_http1(&pointeur, packet, header, verbose);
	}
}
