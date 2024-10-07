#include "ftp.h"
#include <stdbool.h>
#include <ctype.h>
#include <strings.h>


void print_code_message(char tab[3])
{
	if(strcasecmp("200", tab) == 0) printf("Command okay.\n");
	else if (strcasecmp("500", tab) == 0) printf("Syntax error, command unrecognized.\n");
	else if (strcasecmp("501", tab) == 0) printf("Syntax error in parameters or arguments.\n");
	else if (strcasecmp("202", tab) == 0) printf("Command not implemented, superfluous at this site.\n");
	else if (strcasecmp("502", tab) == 0) printf("Command not implemented.\n");
	else if (strcasecmp("503", tab) == 0) printf("Bad sequence of commands.\n");
	else if (strcasecmp("504", tab) == 0) printf("Command not implemented for that parameter.\n");
	else if (strcasecmp("110", tab) == 0) printf("Restart marker reply.\n");
	else if (strcasecmp("211", tab) == 0) printf("System status, or system help reply.\n");
	else if (strcasecmp("212", tab) == 0) printf("Directory status.\n");
	else if (strcasecmp("213", tab) == 0) printf("File status.\n");
	else if (strcasecmp("214", tab) == 0) printf("Help message.\n");
	else if (strcasecmp("215", tab) == 0) printf("NAME system type.\n");
	else if (strcasecmp("120", tab) == 0) printf("Service ready in nnn minutes.\n");
	else if (strcasecmp("220", tab) == 0) printf("Service ready for new user.\n");
	else if (strcasecmp("221", tab) == 0) printf("Service closing control connection.\n");
	else if (strcasecmp("421", tab) == 0) printf("Service not available, closing control connection.\n");
	else if (strcasecmp("125", tab) == 0) printf("Data connection already open; transfer starting.\n");
	else if (strcasecmp("225", tab) == 0) printf("Data connection open; no transfer in progress.\n");
	else if (strcasecmp("425", tab) == 0) printf("Can't open data connection.\n");
	else if (strcasecmp("226", tab) == 0) printf("Closing data connection.\n");
	else if (strcasecmp("426", tab) == 0) printf("Connection closed; transfer aborted.\n");
	else if (strcasecmp("227", tab) == 0) printf("Entering Passive Mode (h1,h2,h3,h4,p1,p2).\n");
	else if (strcasecmp("230", tab) == 0) printf("User logged in, proceed.\n");
	else if (strcasecmp("530", tab) == 0) printf("Not logged in.\n");
	else if (strcasecmp("331", tab) == 0) printf("User name okay, need password.\n");
	else if (strcasecmp("332", tab) == 0) printf("Need account for login.\n");
	else if (strcasecmp("532", tab) == 0) printf("Need account for storing files.\n");
	else if (strcasecmp("150", tab) == 0) printf("File status okay; about to open data connection.\n");
	else if (strcasecmp("250", tab) == 0) printf("Requested file action okay, completed.\n");
	else if (strcasecmp("257", tab) == 0) printf("PATHNAME created.\n");
	else if (strcasecmp("350", tab) == 0) printf("Requested file action pending further information.\n");
	else if (strcasecmp("450", tab) == 0) printf("Requested file action not taken.\n");
	else if (strcasecmp("550", tab) == 0) printf("Requested action not taken.\n");
	else if (strcasecmp("451", tab) == 0) printf("Requested action aborted. Local error in processing.\n");
	else if (strcasecmp("551", tab) == 0) printf("Requested action aborted. Page type unknown.\n");
	else if (strcasecmp("452", tab) == 0) printf("Requested action not taken.\n");
	else if (strcasecmp("552", tab) == 0) printf("Requested file action aborted.\n");
	else if (strcasecmp("553", tab) == 0) printf("Requested action not taken.\n");
}


void gere_serveur_ftp(unsigned char** pointeur, const u_char *packet, const struct pcap_pkthdr *header, int verbose)
{
	//récupérer les 3 premiers octets en les mettant dans le tableau tab => contient le code
	char tab[3] = {**pointeur, *(*pointeur+1), *(*pointeur+2)};
	
	while(*pointeur < &packet[header->len - 1]) //tant que la fin du paquet n'est pas atteinte (pas <= pour ne pas dépasser)
	{	
		//récupérer le code
		if(verbose == 2)
			printf("Code: ");
		else if(verbose == 3)
			printf("\tCode: ");
		for(int i = 0; i < 3; i++)
		{
			printf("%c", tab[i]);
		}
		*pointeur += 3;
		
		if(verbose == 3)
			printf(", ");
		
		if(verbose == 3)
		{
			print_code_message(tab);
		}
		
		*pointeur += 1; //passer l'espace/tiret
		
		if(verbose == 3)
		{
			if(**pointeur != '\r' && *(*pointeur+1) !='\n')
				printf("\tParamètre: ");
		}
		
		//s'il y a un paramètre, l'afficher (il se termine par \r\n)
		while(**pointeur != '\r' && *(*pointeur+1) !='\n') 
		{
			if(verbose == 3)
				printf("%c", **pointeur);
			*pointeur += 1;
		}
		*pointeur += 1; //pointer sur \n
	}	
}

void gere_client_ftp(unsigned char** pointeur, int verbose)
{
	//récupérer les 4 premiers octets en les mettant dans le tableau commande => contient la commande du client
	char commande[4] = {**pointeur, *(*pointeur+1), *(*pointeur+2), *(*pointeur+3)};
	
	if(verbose == 2)
		printf("Requested command: ");
	else if(verbose == 3)
		printf("\tRequested command: ");
	
	for(int i = 0; i < 4; i++)
	{
		printf("%c", commande[i]);
	}
	
	if(verbose == 2)
		return;
	
	printf("\n");
	
	//on ne considère pas les commandes qui n'ont pas d'arguments
	if(!(strcasecmp("ABOR", commande) == 0 || strcasecmp("CDUP", commande) == 0 || strcasecmp("NOOP", commande) == 0 || strcasecmp("PASV", commande) == 0 || strcasecmp("PWD ", commande) == 0 || strcasecmp("QUIT", commande) == 0  || strcasecmp("REIN", commande) == 0 || strcasecmp("STOU", commande) == 0  || strcasecmp("SYST", commande) == 0) )
	{
		if(strcasecmp("CWD ", commande) == 0 || strcasecmp("MFF ", commande) == 0 || strcasecmp("MKD ", commande) == 0 || strcasecmp("RMD ", commande) == 0) //cas 2 : commandes à 3 lettres + argument
		{
			*pointeur += 4; //pointer sur la premiere lettre de l'arg pour une commande en 3 lettres
			
			printf("\tRequest arg: ");
			
			//afficher le paramètre (il se termine par \r\n)
			while(**pointeur != '\r' && *(*pointeur+1) !='\n') 
			{
				printf("%c", **pointeur);
				*pointeur += 1;
			}
		}
		else if(strcasecmp("HELP", commande) == 0 || strcasecmp("LIST", commande) == 0 || strcasecmp("NLST", commande) == 0 || strcasecmp("STAT", commande) == 0) //cas 3 : commandes à 4 lettres + argument optionnel
		{
			*pointeur += 4; //pointer sur l'éventuel \r si pas d'argument ou espace s'il y en a
			if(**pointeur != '\r') //il y a un argument
			{
				printf("\tRequest arg: ");
			
				//afficher le paramètre (il se termine par \r\n)
				while(**pointeur != '\r' && *(*pointeur+1) !='\n') 
				{
					printf("%c", **pointeur);
					*pointeur += 1;
				}
			}
		}
		else //commandes à 4 lettres + argument
		{
			*pointeur += 5; //pointer sur la premiere lettre de l'arg pour une commande en 4 lettres
			
			printf("\tRequest arg: ");
			
			//afficher le paramètre (il se termine par \r\n)
			while(**pointeur != '\r' && *(*pointeur+1) !='\n') 
			{
				printf("%c", **pointeur);
				*pointeur += 1;
			}
		}
	}
}


void dechiffrage_ftp(const u_char *packet, int size_of_lower_layer, const struct pcap_pkthdr *header, int verbose)
{
	unsigned char* pointeur = (unsigned char*) (packet + size_of_lower_layer);
	
	if(verbose == 1)
	{
		printf("FTP ");
	}
	else if(verbose == 2)
	{
		//texte en gras et souligné
		printf("\e[1;4m");
		printf("FTP");

		//remettre le style par défaut
		printf("\033[0m");
		
		printf(" ");
	}
	else if(verbose == 3)
	{
		//fond blanc et police noire
		printf("\n\033[1;30;47m");
		
		printf("File Transfer Protocol");
		
		//remettre le style par défaut
   		printf("\033[0m\n");
	}
	
	bool is_server = false;
	
	if(isdigit(*pointeur) != 0) //serveur
	{
		is_server = true;
	}
	else //client
	{
		is_server = false;
	}
	
	if(verbose == 1)
	{
		if(is_server == true)
			printf("(serveur)\n");
		else printf("(client)\n");
		
		return;
	}
	else if(verbose == 2)
	{
		if(is_server == true)
			printf("(serveur), ");
		else printf("(client), ");
	}
	
	if(is_server == true)
	{
		gere_serveur_ftp(&pointeur, packet, header, verbose);
	}
	else //client
	{	
		gere_client_ftp(&pointeur, verbose);
	}
}
