#include "http2.h"

struct http2_frame
{
	unsigned char length[3];
	uint8_t type;
	uint8_t flags;
	unsigned char stream_identifier[4];
	//payload...
};


void affiche_type(uint8_t type, int verbose)
{
	//texte en gras et souligné
	if(verbose == 3)
		printf("\e[1;4m");
		
	switch(type)
	{
		case TYPE_DATA:
			if(verbose == 1 || verbose == 2)
				printf("DATA ");
			else if(verbose == 3)
				printf("\tDATA");
			break;
			
		case TYPE_HEADERS:
			if(verbose == 1 || verbose == 2)
				printf("HEADERS ");
			else if(verbose == 3)
				printf("\tHEADERS");
			break;
		
		case TYPE_PRIORITY:
		
			if(verbose == 1 || verbose == 2)
				printf("PRIORITY ");
			else if(verbose == 3)
				printf("\tPRIORITY");
			break;
			
		case TYPE_RST_STREAM:
		
			if(verbose == 1 || verbose == 2)
				printf("RST_STREAM ");
			else if(verbose == 3)
				printf("\tRST_STREAM");
			break;
			
		case TYPE_SETTINGS:
			if(verbose == 1 || verbose == 2)
				printf("SETTINGS ");
			else if(verbose == 3)
				printf("\tSETTINGS");
			break;
		
		case TYPE_PUSH_PROMISE:
			if(verbose == 1 || verbose == 2)
				printf("PUSH_PROMISE ");
			else if(verbose == 3)
				printf("\tPUSH_PROMISE");
			break;
		
		case TYPE_PING:
			if(verbose == 1 || verbose == 2)
				printf("PING ");
			else if(verbose == 3)
				printf("\tPING");
			break;
		
		case TYPE_GOAWAY:
			if(verbose == 1 || verbose == 2)
				printf("GOAWAY ");
			else if(verbose == 3)
				printf("\tGOAWAY");
			break;
		
		case TYPE_WINDOW_UPDATE:
			if(verbose == 1 || verbose == 2)
				printf("WINDOW_UPDATE ");
			else if(verbose == 3)
				printf("\tWINDOW_UPDATE");
			break;
			
		case TYPE_CONTINUATION:
			if(verbose == 1 || verbose == 2)
				printf("CONTINUATION ");
			else if(verbose == 3)
				printf("\tCONTINUATION");
			break;
		
		default:
			break;
	}
	
	if(verbose == 3)
		printf("\033[0m\n"); //remettre le style par défaut
}


void affiche_code_erreur_message(uint32_t code_erreur)
{
	switch(code_erreur)
	{
		case NO_ERROR:
			printf("-> NO_ERROR\n");
			break;
		
		case PROTOCOL_ERROR:
			printf("-> PROTOCOL_ERROR\n");
			break;
			
		case INTERNAL_ERROR:
			printf("-> INTERNAL_ERROR\n");
			break;
			
		case FLOW_CONTROL_ERROR:
			printf("-> FLOW_CONTROL_ERROR\n");
			break;
			
		case SETTINGS_TIMEOUT:
			printf("-> SETTINGS_TIMEOUT\n");
			break;
			
		case STREAM_CLOSED:
			printf("-> STREAM_CLOSED\n");
			break;
			
		case FRAME_SIZE_ERROR:
			printf("-> FRAME_SIZE_ERROR\n");
			break;
			
		case REFUSED_STREAM:
			printf("-> REFUSED_STREAM\n");
			break;
			
		case CANCEL:
			printf("-> CANCEL\n");
			break;
			
		case COMPRESSION_ERROR:
			printf("-> COMPRESSION_ERROR\n");
			break;
			
		case CONNECT_ERROR:
			printf("-> CONNECT_ERROR\n");
			break;
			
		case ENHANCE_YOUR_CALM:
			printf("-> ENHANCE_YOUR_CALM\n");
			break;
			
		case INADEQUATE_SECURITY:
			printf("-> INADEQUATE_SECURITY\n");
			break;
			
		case HTTP_1_1_REQUIRED:
			printf("-> HTTP_1_1_REQUIRED\n");
			break;
		
		default:
			printf("-> erreur inconnue...\n");
			break;
	}
}


void affiche_valeur_identifier_message(uint16_t valeur_identifier)
{
	switch(valeur_identifier)
	{
		case SETTINGS_HEADER_TABLE_SIZE:
			printf("-> SETTINGS_HEADER_TABLE_SIZE\n");
			break;
			
		case SETTINGS_ENABLE_PUSH:
			printf("-> SETTINGS_ENABLE_PUSH\n");
			break;
			
		case SETTINGS_MAX_CONCURRENT_STREAMS:
			printf("-> SETTINGS_MAX_CONCURRENT_STREAMS\n");
			break;
			
		case SETTINGS_INITIAL_WINDOW_SIZE:
			printf("-> SETTINGS_INITIAL_WINDOW_SIZE\n");
			break;
			
		case SETTINGS_MAX_FRAME_SIZE:
			printf("-> SETTINGS_MAX_FRAME_SIZE\n");
			break;
			
		case SETTINGS_MAX_HEADER_LIST_SIZE:
			printf("-> SETTINGS_MAX_HEADER_LIST_SIZE\n");
			break;
		
		default:
			printf("-> identifier inconnu...\n");
			break;
	}
}

      
void dechiffrage_http2(const u_char *packet, int size_of_lower_layer, const struct pcap_pkthdr *header, bool is_server, int verbose)
{
	unsigned char* pointeur = (unsigned char*) (packet + size_of_lower_layer);
	
	struct http2_frame* http2_frame; 
	
	if(verbose == 1)
	{
		printf("HTTP2 ");
	}
	else if(verbose == 2)
	{
		//texte en gras et souligné
		printf("\e[1;4m");
		printf("HTTP2");

		//remettre le style par défaut
		printf("\033[0m");
		
		printf(", ");
	}
	else if(verbose == 3)
	{
		//fond blanc et police noire
		printf("\n\033[1;30;47m");
		printf("Hypertext Transfer Protocol 2");
		//remettre le style par défaut
   		printf("\033[0m\n");
	}
	
	while(pointeur <= &packet[header->len - 1]) //tant que la fin du paquet n'est pas atteinte
	{
		http2_frame = (struct http2_frame*) pointeur;
		
		uint8_t type = http2_frame->type;
		affiche_type(type, verbose);
		
		//conversion du tableau length en un uint32_t de la forme : length = [0][1][2]
		uint32_t length = (uint32_t)http2_frame->length[0] << 16 |
			          (uint32_t)http2_frame->length[1] << 8 |
			          (uint32_t)http2_frame->length[2];
		
		if(verbose == 3)   
		{       
			printf("\t\tLength: %u\n", length);
			printf("\t\tType: %.2x\n", type);
		}
		
		uint8_t flags = http2_frame->flags;
		
		if(verbose == 3)
		{
			printf("\t\tFlags: %.2x\n", flags);
			printf("\t\tStream identifier: ");
			for(int i = 0; i < 4; i++)
				printf("%.2x", http2_frame->stream_identifier[i]);
			printf("\n");
		}
		
		pointeur += sizeof(struct http2_frame);
		
		switch(type)
		{
			case TYPE_DATA:
			case TYPE_HEADERS:
			case TYPE_PUSH_PROMISE:
			{
				unsigned char pad_length = 0;
				if(flags & 0b00001000) //PADDED flag is on
				{
					if(verbose == 3)
						printf("\t\tPad length: %.2x\n", *pointeur);
					pad_length = *pointeur;
					pointeur += 1;
					length -= 1;
				}
				
				if(type == TYPE_DATA)
				{
					if(verbose == 3)
						printf("\t\tData: ");
				}
				else if(type == TYPE_HEADERS)
				{
					if(flags & 0b00100000) //Priority flag is on
					{
						if(verbose == 3)
							printf("\t\tStream dependency: ");
							
						for(int i = 0; i < 4; i++)
						{
							if(verbose == 3)
								printf("%.2x", *pointeur);
							pointeur += 1;
							length -= 1;
						}
						
						if(verbose == 3)
						{
							printf("\n");
							printf("\t\tWeight: %.2x\n", *pointeur);
						}
						pointeur += 1;
					}
					
					if(verbose == 3)
						printf("\t\tHeader block fragment: ");
				}
				else if(type == TYPE_PUSH_PROMISE)
				{
					if(verbose == 3)
						printf("\t\tPromised stream ID: ");
						
					for(int i = 0; i < 4; i++)
					{
						if(verbose == 3)
							printf("%.2x", *pointeur);
						pointeur += 1;
						length -= 1;
					}
					
					if(verbose == 3)
					{
						printf("\n");
						printf("\t\tHeader block fragment: ");
					}
				}
				
				while((length - pad_length) > 0)
				{
					if(verbose == 3)
					{
						if(type == TYPE_DATA)
							printf("%c", *pointeur);
						else printf("%.2x", *pointeur);
					}
					pointeur += 1;
					length -= 1;
				}
				if(verbose == 3)
					printf("\n");
			}
				break;	
			
			case TYPE_PRIORITY:
			{	
				if(verbose == 3)
					printf("\t\tStream dependency: ");
					
				for(int i = 0; i < 4; i++)
				{
					if(verbose == 3)
						printf("%.2x", *pointeur);
					pointeur += 1;
				}
				
				if(verbose == 3)
				{
					printf("\n");
					printf("\t\tWeight: %.2x\n", *pointeur);
				}
				pointeur += 1;
			}
				break;
				
			case TYPE_RST_STREAM:
			{
				if(verbose == 3)
					printf("\t\tError code: ");
					
				unsigned char error_code[4];
				for(int i = 0; i < 4; i++)
				{
					if(verbose == 3)
						printf("%.2x", *pointeur);
					error_code[i] = *pointeur;
					pointeur += 1;
				}
				
				//conversion du tableau en un uint32_t de la forme : 00[0][1][2]
				uint32_t code_erreur = (uint32_t)error_code[0] << 24 |
					  	(uint32_t)error_code[1] << 16 |
					  	(uint32_t)error_code[2] << 8 |
					  	(uint32_t)error_code[3];
					
				if(verbose == 3)
				{  	
					affiche_code_erreur_message(code_erreur);
				}
			}
				break;
				
			case TYPE_SETTINGS:
			{
				while(length > 0)
				{
					if(verbose == 3)
						printf("\t\tIdentifier: ");
						
					unsigned char identifier[2];
					for(int i = 0; i < 2; i++)
					{
						if(verbose == 3)
							printf("%.2x", *pointeur);
						identifier[i] = *pointeur;
						pointeur += 1;
						length -= 1;
					}

			    		uint16_t valeur_identifier = (uint32_t)identifier[0] << 8 |
						  	  		(uint32_t)identifier[1];
						  
					if(verbose == 3)
					{  
						affiche_valeur_identifier_message(valeur_identifier);
					}
					
					unsigned char tab_value[4];
					for(int i = 0; i < 4; i++)
					{
						tab_value[i] = *pointeur;
						length -= 1;
						pointeur += 1;
					}
					
					//convertir les 4 hex du tableau en un uint32_t
					uint32_t value = (uint32_t)tab_value[0] << 24 |
						  	(uint32_t)tab_value[1] << 16 |
						  	(uint32_t)tab_value[2] << 8 |
						  	(uint32_t)tab_value[3];
					
					if(verbose == 3)
					{
						printf("\t\tValue: %u\n", value);
						printf("\n");
					}
				}
			}
				break;
			
			case TYPE_PING:
				if(verbose == 3)
					printf("\t\tOpaque Data: ");
					
				for(int i = 0; i < 8; i++)
				{
					if(verbose == 3)
						printf("%.2x", *pointeur);
					pointeur += 1;
				}
				break;
			
			case TYPE_GOAWAY:
				if(verbose == 3)
					printf("\t\tLast stream ID: ");
					
				for(int i = 0; i < 4; i++)
				{
					if(verbose == 3)
						printf("%.2x", *pointeur);
					pointeur += 1;
					length -= 1;
				}
				
				if(verbose == 3)
				{
					printf("\n");
					printf("\t\tError code ID: ");
				}
				for(int i = 0; i < 4; i++)
				{
					if(verbose == 3)
						printf("%.2x", *pointeur);
					pointeur += 1;
					length -= 1;
				}
				if(verbose == 3)
				{
					printf("\n");
					printf("\t\tAdditional Debug Data: ");
				}
				break;
			
			case TYPE_WINDOW_UPDATE:
				if(verbose == 3)
					printf("\t\tWindow Size Increment: ");
				for(int i = 0; i < 4; i++)
				{
					if(verbose == 3)
						printf("%.2x", *pointeur);
					pointeur += 1;
				}
				break;
				
			case TYPE_CONTINUATION:
				if(verbose == 3)
					printf("\t\tHeader block fragment: ");
				break;
			
			default:
				break;
		}
		
		//afficher pour ces types les éventuels octets restants
		if(type == TYPE_DATA || type == TYPE_HEADERS || type == TYPE_PUSH_PROMISE || type == TYPE_GOAWAY || type == TYPE_CONTINUATION)
		{
			while(length > 0) 
			{
				if(verbose == 3)
					printf("%c", *pointeur);
				length -= 1;
				pointeur += 1;
			}
		}
	}
}
