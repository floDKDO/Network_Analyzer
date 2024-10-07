#include "tls.h"

struct tls_frame
{
	uint8_t content_type;
	unsigned char version[2];
	unsigned char length[2];
	//payload...
};


void affiche_content_type(uint8_t content_type)
{
	printf("\tContent-type -> ");
	
	switch(content_type)
	{
		case TLS_CIPHER:
			printf("Change_cipher_spec");
			break;
			
		case TLS_ALERT:
			printf("Alert");
			break;
			
		case TLS_HANDSHAKE:
			printf("Handshake");
			break;
			
		case TLS_APP_DATA:
			printf("Application data");
			break;
			
		case TLS_HEARTBEAT:
			printf("Heartbeat");
			break;
			
		case TLS_TLS1_2:
			printf("TLS1.2 cid");
			break;
			
		case TLS_ACK:
			printf("ACK");
			break;
			
		case TLS_RETURN:
			printf("Return_routability_check");
			break;
	
		default:
			printf("Données inconnues...");
			break;
	}
	printf(" (%u)", content_type);
}

      
void dechiffrage_tls(const u_char *packet, int size_of_lower_layer, const struct pcap_pkthdr *header, int verbose)
{
	unsigned char* pointeur = (unsigned char*) (packet + size_of_lower_layer);
	
	if(verbose == 1)
	{
		printf("TLS (HTTPS)");
		return;
	}
	else if(verbose == 2)
	{
		//texte en gras et souligné
		printf("\e[1;4m");
		printf("TLS (HTTPS)");

		//remettre le style par défaut
		printf("\033[0m");
		
		printf(", ");
	}
	else if(verbose == 3)
	{
		//fond blanc et police noire
		printf("\n\033[1;30;47m");
		
		printf("Transport Layer Security pour HTTPS");
		
		//remettre le style par défaut
   		printf("\033[0m\n");
	}

	struct tls_frame* tls_frame = (struct tls_frame*) pointeur;
	
	if(verbose == 2)
	{
		printf("Content_type: %u, ", tls_frame->content_type);
	}
	else if(verbose == 3)
	{
		printf("\tContent_type: %u\n", tls_frame->content_type);
	}
	
	if(verbose == 3)
	{
		printf("\tVersion: ");
		for(int i = 0; i < 2; i++)
			printf("%.2x", tls_frame->version[i]);
		printf("\n");
	}
	
	uint16_t length = (uint32_t)tls_frame->length[0] << 8 |
			   (uint32_t)tls_frame->length[1];
			
	if(verbose == 2)
	{
		printf("Length: %u\n", length);
		return;
	}
	
	printf("\tLength: %u\n", length);
	
	pointeur += sizeof(struct tls_frame); 
	
	affiche_content_type(tls_frame->content_type);
	
	printf("\n\t<Contenu encrypté non affiché>\n");
	
	//contenu inintelligible
	/*while(length > 0)
	{
		printf("%.2x", *pointeur);
		pointeur += 1;
		length -= 1;
	}*/
}
