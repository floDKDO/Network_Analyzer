#include "smtp.h"
#include <string.h>
#include <strings.h>


void affiche_code_message(char tab[3])
{
	if(strcmp("211", tab) == 0)
		printf(" -> System status, or system help reply\n");
	else if(strcmp("214", tab) == 0)
		printf(" -> Help message\n");
	else if(strcmp("220", tab) == 0)
		printf(" -> <domain> Service ready\n");
	else if(strcmp("221", tab) == 0)
		printf(" -> <domain> Service closing transmission channel\n");
	else if(strcmp("250", tab) == 0)
		printf(" -> Requested mail action okay, completed\n");
	else if(strcmp("251", tab) == 0)
		printf(" -> User not local; will forward to <forward-path>\n");
	else if(strcmp("354", tab) == 0)
		printf(" -> Start mail input; end with <CRLF>.<CRLF>\n");
	else if(strcmp("421", tab) == 0)
		printf(" -> <domain> Service not available, closing transmission channel\n");
	else if(strcmp("450", tab) == 0)
		printf(" -> Requested mail action not taken: mailbox unavailable\n");
	else if(strcmp("451", tab) == 0)
		printf(" -> Requested action aborted: local error in processing\n");
	else if(strcmp("452", tab) == 0)
		printf(" -> Requested action not taken: insufficient system storage\n");
	else if(strcmp("500", tab) == 0)
		printf(" -> Syntax error, command unrecognized\n");
	else if(strcmp("501", tab) == 0)
		printf(" -> Syntax error in parameters or arguments\n");
	else if(strcmp("502", tab) == 0)
		printf(" -> Command not implemented\n");
	else if(strcmp("503", tab) == 0)
		printf(" -> Bad sequence of commands\n");
	else if(strcmp("504", tab) == 0)
		printf(" -> Command parameter not implemented\n");
	else if(strcmp("550", tab) == 0)
		printf(" -> Requested action not taken: mailbox unavailable\n");
	else if(strcmp("551", tab) == 0)
		printf(" -> User not local; please try <forward-path>\n");
	else if(strcmp("552", tab) == 0)
		printf(" -> Requested mail action aborted: exceeded storage allocation\n");
	else if(strcmp("553", tab) == 0)
		printf(" -> Requested action not taken: mailbox name not allowed\n");
	else if(strcmp("554", tab) == 0)
		printf(" -> Transaction failed\n");
}



void gere_serveur_smtp(unsigned char** pointeur, const u_char *packet, const struct pcap_pkthdr *header)
{	
	//récupérer le code
	char tab[3] = {**pointeur, *(*pointeur+1), *(*pointeur+2)};
	printf("\tCode : ");
	for(int i = 0; i < 3; i++)
	{
		printf("%c", tab[i]);
	}
	*pointeur += 3;
	
	affiche_code_message(tab);

	*pointeur += 1; //passer l'espace/tiret
	
	if(**pointeur != '\r' && *(*pointeur+1) !='\n')
		printf("\tParamètre: ");
	while(*pointeur <= &packet[header->len - 1]) //tant que la fin du paquet n'est pas atteinte
	{
		if(**pointeur == '\r' && *(*pointeur+1) == '\n')
		{
			if(*pointeur + 2 <= &packet[header->len - 1]) //n'est pas la fin du paquet : il reste une ou des lignes 
			{
				*pointeur += 2; //passer à la ligne suivante (\r + \n)
				*pointeur += 4; //ne pas afficher le code pour chaque ligne, on l'affiche juste pour la première
				printf("\n\tParamètre: ");
			}	
		}
		printf("%c", **pointeur);
		if(*(*pointeur) == '\n')
			printf("\t");
		if(*pointeur == &packet[header->len - 1]) //ne pas incrémenter pointeur après le dernier octet du paquet
			break;
		*pointeur += 1;
	}	
}

void gere_client_smtp(unsigned char** pointeur, const u_char *packet, const struct pcap_pkthdr *header)
{
	//récupérer les 4 caractères de la commande 
	//attention, le client n'envoie pas forcément une commande 
	//DATA n'a pas de paramètre  
	char tab[5] = {**pointeur, *(*pointeur+1), *(*pointeur+2), *(*pointeur+3)}; //tenter de récupérer la commande s'il y en a une

	if(strcasecmp("EHLO", tab) == 0)
	{
		printf("\tExtended SMTP utilisé\n");
	}
	
	if(strcasecmp("EHLO", tab) == 0 || strcasecmp("HELO", tab) == 0 || strcasecmp("MAIL", tab) == 0 || strcasecmp("RCPT", tab) == 0 || strcasecmp("DATA", tab) == 0 || strcasecmp("SEND", tab) == 0 || strcasecmp("SOML", tab) == 0 || strcasecmp("SAML", tab) == 0 || strcasecmp("RSET", tab) == 0 || strcasecmp("VRFY", tab) == 0 || strcasecmp("EXPN", tab) == 0 || strcasecmp("HELP", tab) == 0 || strcasecmp("NOOP", tab) == 0 || strcasecmp("QUIT", tab) == 0 || strcasecmp("TURN", tab) == 0) //commande
	{
		printf("\tCommande: ");
		for(int i = 0; i < 4; i++)
		{
			printf("%c", tab[i]);
		}
		printf("\n");
		*pointeur += 4;
		
		if(**pointeur != '\r' && *(*pointeur+1) !='\n')
			printf("\tParamètre: ");
	}
	else
	{
		printf("\tTexte: ");
	}
	
	while(*pointeur <= &packet[header->len - 1]) //tant que la fin du paquet n'est pas atteinte
	{
		printf("%c", **pointeur);
		if(*pointeur == &packet[header->len - 1]) //ne pas incrémenter pointeur après le dernier octet du paquet
			break;
		*pointeur += 1;
	}
}



void dechiffrage_smtp(const u_char *packet, int size_of_lower_layer, const struct pcap_pkthdr *header, bool is_server, int verbose)
{
	unsigned char* pointeur = (unsigned char*) (packet + size_of_lower_layer);
	
	if(verbose == 1)
	{
		printf("SMTP ");
	}
	else if(verbose == 2)
	{
		//texte en gras et souligné
		printf("\e[1;4m");
		printf("SMTP");

		//remettre le style par défaut
		printf("\033[0m");
		
		printf(" ");
	}
	else if(verbose == 3)
	{
		//fond blanc et police noire
		printf("\n\033[1;30;47m");
		
		printf("Simple Mail Transfer Protocol");
		
		//remettre le style par défaut
   		printf("\033[0m\n");
	}
	
	bool is_text = false;
	
	char commande[5] = {*pointeur, *(pointeur+1), *(pointeur+2), *(pointeur+3)};
	char tab[4] = {*pointeur, *(pointeur+1), *(pointeur+2)};
	
	if(!(strcmp(commande, "HELO") == 0 || strcmp(commande, "EHLO") == 0 || strcmp(commande, "MAIL") == 0 || strcmp(commande, "RCPT") == 0 || strcmp(commande, "DATA") == 0 || strcmp(commande, "SEND") == 0 || strcmp(commande, "SOML") == 0 || strcmp(commande, "SAML") == 0 || strcmp(commande, "RSET") == 0 || strcmp(commande, "VRFY") == 0 || strcmp(commande, "EXPN") == 0 || strcmp(commande, "HELP") == 0 || strcmp(commande, "NOOP") == 0 || strcmp(commande, "QUIT") == 0 || strcmp(commande, "TURN") == 0) && is_server == false) //client
	{
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
			printf("Code: %s", tab);
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
			pointeur += 1;
			if(*(pointeur-1) == '\n')
				printf("\t");
		}
	}
	else
	{
		if(is_server == true)
		{
			gere_serveur_smtp(&pointeur, packet, header);	
		}
		else //client
		{
			gere_client_smtp(&pointeur, packet, header);
		}
	}
}
