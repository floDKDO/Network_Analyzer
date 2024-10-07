#include "tftp.h"
#include <stdbool.h>


void affiche_error_code_message(uint16_t error_code)
{
	switch(error_code)
	{
		case ERR_NOT_DEF:
			printf("Not defined, see error message (if any).\n");
			break;
			
		case ERR_FILE_NOT_FOUND:
			printf("File not found.\n");
			break;
			
		case ERR_ACC_VIOLATION:
			printf("Access violation.\n");
			break;
			
		case ERR_DISK_FULL:
			printf("Disk full or allocation exceeded.\n");
			break;
			
		case ERR_ILLEGAL_OP:
			printf("Illegal TFTP operation.\n");
			break;
			
		case ERR_UNKNOWN_ID:
			printf("Unknown transfer ID.\n");
			break;
			
		case ERR_FILE_EXISTS:
			printf("File already exists.\n");
			break;
			
		case ERR_NO_USER:
			printf("No such user.\n");
			break;
	
		default:
			break;
	}
}



void dechiffrage_tftp(const u_char *packet, int size_of_lower_layer, const struct pcap_pkthdr *header, int verbose)
{
	unsigned char* pointeur = (unsigned char*) (packet + size_of_lower_layer);
	
	//récupérer l'opcode
	uint16_t opcode = (uint16_t)(((*pointeur & 0xF) << 8) | *(pointeur+1));
	
	if(verbose == 1)
	{
		printf("TFTP ");
	}
	else if(verbose == 2)
	{
		//texte en gras et souligné
		printf("\e[1;4m");
		printf("TFTP");

		//remettre le style par défaut
		printf("\033[0m");
		
		printf(", ");
	}
	else if(verbose == 3)
	{
		//fond blanc et police noire
		printf("\n\033[1;30;47m");
		
		printf("Trivial File Transfer Protocol");
		
		//remettre le style par défaut
   		printf("\033[0m\n");
		
		printf("\tOpcode: ");
	}
	
	if(opcode == OP_RRQ || opcode == OP_WRQ)
	{
		if(opcode == OP_RRQ)
		{
			printf("RRQ (%u)", opcode);
			if(verbose == 1 || verbose == 2)
				return;
		}
		else if(opcode == OP_WRQ)
		{
			printf("WRQ (%u)", opcode);
			if(verbose == 1 || verbose == 2)
				return;
		}
		printf("\n");
			
		pointeur += 2; //aller après l'opcode
		
		printf("\tFilename: ");
		while(*pointeur != 0)
		{
			printf("%c", *pointeur);
			pointeur += 1;
		}
		printf("\n");
		pointeur += 1; //ici, pointe sur le 1ere caractère du mode
		
		printf("\tMode: ");
		while(*pointeur != 0)
		{	
			printf("%c", *pointeur);
			pointeur += 1;
		}
		printf("\n");
	}
	else if(opcode == OP_DATA)
	{
		printf("DATA (3)");
		if(verbose == 1 || verbose == 2)
			return;
		pointeur += 2; //aller après l'opcode
		
		printf("\n");
		
		//récupérer le block number
		uint16_t block_number = (uint16_t)(((*pointeur & 0xF) << 8) | *(pointeur+1));
		printf("\tBlock number: %u\n", block_number);
		pointeur += 2; //aller après le block number
		
		printf("\tData: ");
		while(pointeur <= &packet[header->len - 1])
		{
			printf("%c", *pointeur);
			if(pointeur == &packet[header->len - 1]) //ne pas incrémenter pointeur après le dernier octet du paquet
				break;
			pointeur += 1;
		}
		printf("\n");
	}
	else if(opcode == OP_ACK)
	{
		printf("ACK (4)");
		if(verbose == 1 || verbose == 2)
			return;
		pointeur += 2; //aller après l'opcode
		
		printf("\n");
		
		//récupérer le block number
		uint16_t block_number = (uint16_t)(((*pointeur & 0xF) << 8) | *(pointeur+1));
		printf("\tBlock number: %u\n", block_number);
		pointeur += 2; //aller après le block number
	}
	else if(opcode == OP_ERR)
	{
		printf("ERR (5)");
		if(verbose == 1 || verbose == 2)
			return;
		pointeur += 2; //aller après l'opcode
		
		printf("\n");
		
		//récupérer l'error_code
		uint16_t error_code = (uint16_t)(((*pointeur & 0xF) << 8) | *(pointeur+1));
		
		printf("\tError code: %u -> ", error_code);
		
		affiche_error_code_message(error_code);
		
		pointeur += 2; //aller après l'error_code
		
		printf("\tError message: ");
		while(*pointeur != 0)
		{
			printf("%c", *pointeur);
			pointeur += 1;
		}
	}
}

