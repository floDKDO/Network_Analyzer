#include "ethernet.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdbool.h>

#include <pcap.h> 

void paquet_recu(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
	int* verbose = (int*) args;
	
	static long int num_paquet = 1;
	
	printf("////////////////////////////////////////////////////////////////////////////////////////////////////////////\n");
	
	//fond blanc et police noire
	printf("\033[1;30;47m");
    
	if(*verbose == 1)
	{
		printf("Paquet %ld:", num_paquet);
	}
	else if(*verbose == 2)
	{
		printf("Paquet %ld (%d octets)", num_paquet, header->len);
	}
	else if(*verbose == 3)
	{
		printf("Paquet %ld: %d octets capturés.", num_paquet, header->len);
	}
	
	//remettre le style par défaut
   	printf("\033[0m");
   	
   	if(*verbose == 2 || *verbose == 3)
   		printf("\n");
   	else if(*verbose == 1)
   		printf(" ");
	
	dechiffrage_ethernet(packet, header, *verbose);
	
	printf("\n");
	
	num_paquet += 1;
}



int main(int argc, char* argv[])
{
	bool option_i = false, option_o = false, option_f = false, option_v = false; 
	
	int verbose;
	char* nom_interface;
	char* fichier_d_entree;
	char* filtre;
	
	int opt;
	while((opt = getopt(argc, argv, "i:o:f:v:")) != -1)
	{
		switch(opt)
		{
			case 'i': 
				option_i = true; 
				nom_interface = optarg;
				break;
				
			case 'o':
				option_o = true;
				fichier_d_entree = optarg;
				break;
				
			case 'f':
				option_f = true;
				filtre = optarg;
				break;
				
			case 'v':
				option_v = true;
				
				if(strcmp(optarg, "1") != 0 && strcmp(optarg, "2") != 0 && strcmp(optarg, "3") != 0)
				{
					printf("Valeur de verbose impossible\n");
					exit(1);
				}
				verbose = atoi(optarg);
				break;
				
			default:
				break;
		}
	}
	
	if(option_v == false)
	{
		printf("Option v obligatoire\n");
		exit(1);
	}
	
	if(option_i == false && option_o == false)
	{
		printf("Options i ou o obligatoires\n");
		exit(1);
	}
	
	if(option_i == true && option_o == true)
	{
		printf("Options i et o impossibles en même temps\n");
		exit(1);
	}
	
	pcap_t* capture;
	char errbuf[PCAP_ERRBUF_SIZE];
	struct bpf_program fp;
	if(option_i == true)
	{
		pcap_if_t* alldevsp = NULL;
		
		if(pcap_findalldevs(&alldevsp, errbuf) == -1)
		{
			fprintf(stderr, "erreur\n");
			exit(1);
		}
		
		bool interface_trouvee = false;
		while (alldevsp != NULL) 
		{
			if(strcmp(alldevsp->name, nom_interface) == 0)
			{
				interface_trouvee = true;
				break;
			}
			alldevsp = alldevsp->next;
		}
		
		if(interface_trouvee == false)
		{
			fprintf(stderr, "Interface inconnue...\n");
			exit(1);
		}
		
		//texte en gras et souligné
		printf("\e[1;4mInterface:\033[0m %s\n", nom_interface);
		
		bpf_u_int32 netaddr, netmask;
		
		if(pcap_lookupnet(nom_interface, &netaddr, &netmask, errbuf) == -1)
		{
			fprintf(stderr, "erreur\n");
			exit(1);
		}
		
		struct in_addr in;
		in.s_addr = netaddr;
		
		struct in_addr in_mask;
		in_mask.s_addr = netmask;
		
		//texte en gras et souligné
		printf("\e[1;4mAdresse:\033[0m %s\n", inet_ntoa(in));
		printf("\e[1;4mMasque:\033[0m %s\n", inet_ntoa(in_mask)); 
		printf("\n");
		
		
		if((capture = pcap_open_live(nom_interface, BUFSIZ, 1, 1000, errbuf)) == NULL)
		{
			fprintf(stderr, "erreur : %s\n", errbuf);
			exit(1);
		}
		
		if(option_f == true)
		{
			if(pcap_compile(capture, &fp, filtre, 0, netmask) == -1)
			{
				fprintf(stderr, "erreur : %s\n", errbuf);
				exit(1);
			}
		}
		
	}
	else if(option_o == true)
	{
		if((capture = pcap_open_offline(fichier_d_entree, errbuf)) == NULL)
		{
			fprintf(stderr, "erreur : %s\n", errbuf);
			exit(1);
		}
		
		if(option_f == true)
		{
			if(pcap_compile(capture, &fp, filtre, 0, PCAP_NETMASK_UNKNOWN) == -1)
			{
				fprintf(stderr, "erreur : %s\n", errbuf);
				exit(1);
			}
		}	
	}
	
	if(option_f == true)
	{
		if(pcap_setfilter(capture, &fp) != 0)
		{
			fprintf(stderr, "erreur : %s\n", errbuf);
			exit(1);
		}
	}
	
	
	if(pcap_loop(capture, -1, &paquet_recu, (u_char*)&verbose) != 0)
	{
		fprintf(stderr, "erreur : %s\n", errbuf);
		exit(1);
	}
	
	pcap_close(capture);
	
	return 0;
}
