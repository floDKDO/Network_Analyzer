analyseur : main.o arp.o ethernet.o ipv4.o ipv6.o tcp.o udp.o mon_bootp.o smtp.o dns.o pop.o imap.o ftp.o tftp.o http1.o http2.o telnet.o tls.o
	gcc -o analyseur main.o arp.o ethernet.o ipv4.o ipv6.o tcp.o udp.o mon_bootp.o smtp.o dns.o pop.o imap.o ftp.o tftp.o telnet.o http1.o http2.o tls.o -Wall -Wextra -lpcap

main.o : main.c arp.h ethernet.h ipv4.h ipv6.h tcp.h udp.h mon_bootp.h
	gcc -c main.c

arp.o : arp.c arp.h
	gcc -c arp.c

ethernet.o : ethernet.c ethernet.h ipv4.h ipv6.h arp.h
	gcc -c ethernet.c
	
ipv4.o : ipv4.c ipv4.h tcp.h udp.h
	gcc -c ipv4.c
	
ipv6.o : ipv6.c ipv6.h tcp.h udp.h
	gcc -c ipv6.c
	
tcp.o : tcp.c tcp.h smtp.h dns.h pop.h
	gcc -c tcp.c
	
udp.o : udp.c udp.h mon_bootp.h dns.h
	gcc -c udp.c

mon_bootp.o : mon_bootp.c mon_bootp.h
	gcc -c mon_bootp.c 
	
smtp.o : smtp.c smtp.h
	gcc -c smtp.c
	
pop.o : pop.c pop.h
	gcc -c pop.c	

imap.o : imap.c imap.h
	gcc -c imap.c
	
dns.o : dns.c dns.h
	gcc -c dns.c

ftp.o : ftp.c ftp.h
	gcc -c ftp.c

tftp.o : tftp.c tftp.h
	gcc -c tftp.c

telnet.o : telnet.c telnet.h
	gcc -c telnet.c
	
http1.o : http1.c http1.h
	gcc -c http1.c
	
http2.o : http2.c http2.h
	gcc -c http2.c

tls.o : tls.c tls.h
	gcc -c tls.c

clean :
	rm *.o analyseur
