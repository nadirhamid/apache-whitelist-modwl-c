#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <regex.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>
/* apache libraries */
#include <string.h>

int main(int argc, char* argv[])
{
    struct hostent* he;
    struct in_addr ipv4addr;
    char* addr = "185.92.26.33";
    //char* addr = "45.77.72.102";
 
    //inet_pton(AF_INET, addr, &ipv4addr);
    inet_aton(addr, &ipv4addr);
    he = gethostbyaddr(&ipv4addr, sizeof(ipv4addr), AF_INET);
    if ( he == NULL ) { 
      printf("could not determine reverse DNS");
      return -1;
    }
    printf("reverse DNS result is: %s",  he->h_name);
    return 0;
}
