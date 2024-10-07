#include "telnet.h"
#include <stdbool.h>


void affiche_subcommand_message(unsigned char* pointeur, int profondeur) //profondeur pour afficher le bon nombre de tab
{
	char* chaine_tabulation;
	if(profondeur == 1)
		chaine_tabulation = "\t";
	else if(profondeur == 2)
		chaine_tabulation = "\t\t";
		
	switch(*pointeur)
	{
		case ECHO_SUBCOMM:
			printf("%sSous-commande: Echo\n", chaine_tabulation);
			break;
			
		case SUPPRESS_SUBCOMM:
			printf("%sSous-commande: Suppress Go Ahead\n", chaine_tabulation);
			break;
			
		case TERM_TYPE_SUBCOMM:
			printf("%sSous-commande: Terminal Type\n", chaine_tabulation);
			break;
			
		case WIND_SIZE_SUBCOMM:
			printf("%sSous-commande: Window Size\n", chaine_tabulation);
			break;
			
		case TERM_SPEED_SUBCOMM:
			printf("%sSous-commande: Terminal Speed\n", chaine_tabulation);
			break;
			
		case LINE_MODE_SUBCOMM:
			printf("%sSous-commande: Line Mode\n", chaine_tabulation);
			break;
			
		case ENV_VAR_SUBCOMM:
			printf("%sSous-commande: Environment variables\n", chaine_tabulation);
			break;
			
		case NEW_ENV_VAR_SUBCOMM:
			printf("%sSous-commande: New Environment variables\n", chaine_tabulation);
			break;
	
		default:
			printf("%sSous-commande inconnue...\n", chaine_tabulation);
			break;
	}
}

      
void dechiffrage_telnet(const u_char *packet, int size_of_lower_layer, const struct pcap_pkthdr *header, int verbose)
{
	unsigned char* pointeur = (unsigned char*) (packet + size_of_lower_layer);
	
	if(verbose == 1)
	{
		printf("Telnet");
		return;
	}
	else if(verbose == 2)
	{
		//texte en gras et souligné
		printf("\e[1;4m");
		printf("Telnet");

		//remettre le style par défaut
		printf("\033[0m");
		
		printf(" ");
		return;
	}

	//fond blanc et police noire
	printf("\n\033[1;30;47m");
	
	printf("Telnet");
	
	//remettre le style par défaut
	printf("\033[0m\n");
	
	bool is_iac = false;
	bool is_suboption = false;
	bool une_fois = false;
	
	while(pointeur <= &packet[header->len - 1]) //tant que la fin du paquet n'est pas atteinte
	{	
		if(*pointeur == IAC_COMMAND) 
		{
			is_iac = true;
			pointeur += 1;
			continue; //pour ne pas aller par erreur dans le if suivant
		}
		
		if(is_iac == true)
		{
			if(*pointeur == WILL_COMMAND || *pointeur == WONT_COMMAND || *pointeur == DO_COMMAND || *pointeur == DONT_COMMAND)
			{
				if(*pointeur == WILL_COMMAND) 
				{
					printf("\tCommande: Will (%u)\n", *pointeur);	
				}
				else if(*pointeur == WONT_COMMAND) 
				{
					printf("\tCommande: Won't (%u)\n", *pointeur);
				}
				else if(*pointeur == DO_COMMAND) 
				{
					printf("\tCommande: Do (%u)\n", *pointeur);
				}
				else if(*pointeur == DONT_COMMAND) 
				{
					printf("\tCommande: Don't (%u)\n", *pointeur);
				}
				pointeur += 1; //pointer sur la subcommand
				
				affiche_subcommand_message(pointeur, 2);
				
				pointeur += 1;
				is_iac = false;
			}
			else if(*pointeur == SB_COMMAND)
			{
				pointeur += 1; //pointer sur la subcommand
				
				bool is_arg = false; //argument de la subcommand ?
				bool une_fois = false;
				
				while(*pointeur != IAC_COMMAND && *(pointeur + 1) != SE_COMMAND) //!= fff0
				{
					if(is_arg == false)
					{
						affiche_subcommand_message(pointeur, 1);
						is_arg = true;
					}
					else
					{
						if(une_fois == false)
						{
							printf("\tParamètres: ");
							une_fois = true;
						}
						printf("%c", *pointeur);
					}
					if(pointeur == &packet[header->len - 1]) //ne pas incrémenter pointeur après le dernier octet du paquet
						break;
					pointeur += 1;
				}
				printf("\n");
				is_arg = false;
				is_iac = false;
				pointeur += 1; //pointer sur f0
				pointeur += 1; //pointer sur la suite
				printf("\tSous-commande end\n");
			}
			else
			{
				printf("%c", *pointeur);
				if(pointeur == &packet[header->len - 1]) //ne pas incrémenter pointeur après le dernier octet du paquet
					break;
				pointeur += 1;
			}
		}
		else
		{
			if(une_fois == false)
			{
				printf("\tData: ");
				une_fois = true;
			}
			printf("%c", *pointeur);
			if(pointeur == &packet[header->len - 1]) //ne pas incrémenter pointeur après le dernier octet du paquet
				break;
			pointeur += 1;
		}
	}
}
