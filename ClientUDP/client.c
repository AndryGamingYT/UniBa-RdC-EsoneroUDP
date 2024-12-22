#if defined WIN32
#include <winsock.h>
#else
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#define closesocket close
#endif

#include <stdio.h>
#include <stdlib.h>

#include "protocol.h"

void printmenu() {
    printf(
        "Password Generator Help Menu\n"
        "Commands:\n"
        "    h        : show this help menu\n"
        "    n LENGTH : generate numeric password (digits only)\n"
        "    a LENGTH : generate alphabetic password (lowercase letters)\n"
        "    m LENGTH : generate mixed password (lowercase letters and numbers)\n"
        "    s LENGTH : generate secure password (uppercase, lowercase, numbers, symbols)\n"
        "    u LENGTH : generate unambiguous secure password (no similar-looking characters)\n"
        "    q        : quit application\n\n"
        "    LENGTH must be between 6 and 32 characters\n\n"
        "  Ambiguous characters excluded in 'u' option:\n"
        "    0 O o (zero and letters O)\n"
        "    1 l I i (one and letters l, I)\n"
        "    2 Z z (two and letter Z)\n"
        "    5 S s (five and letter S)\n"
        "    8 B (eight and letter B)\n");
}

void clearwinsock() {
#if defined WIN32
    WSACleanup();
#endif
}

void errorhandler(char *errorMessage) { printf("%s", errorMessage); }

int main(int argc, char *argv[]) {
#if defined WIN32
    // Initialize Winsock
    WSADATA wsa_data;
    int result = WSAStartup(MAKEWORD(2, 2), &wsa_data);
    if (result != NO_ERROR) {
        printf("Error at WSAStartup()\n");
        return 0;
    }
#endif

    // get host address
    char *name = SERVER_HOST;
    int port = SERVER_PORT;
    struct hostent *host = gethostbyname(name);
    if (host == NULL) {
        errorhandler("Error getting host");
        clearwinsock();
        return EXIT_FAILURE;
    }
    printf("Server name: %s (IP: %s, port: %d)\n", name, inet_ntoa(*(struct in_addr *)host->h_addr), port);

    int my_socket;
    struct sockaddr_in server_address;
    unsigned int server_address_size = sizeof(server_address);
    int rcv_msg_size;

    /* create a UDP socket */
    if ((my_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
        errorhandler("Error creating socket");
        clearwinsock();
        return EXIT_FAILURE;
    }

    /* set the server address */
    memset(&server_address, 0, sizeof(server_address));
    server_address.sin_family = AF_INET;
    server_address.sin_port = htons(port);
    server_address.sin_addr = *((struct in_addr *)host->h_addr);

    char *message = "Helo";
    /* send a Helo message to the server */
    if (sendto(my_socket, message, strlen(message), 0, (struct sockaddr *)&server_address, sizeof(server_address)) !=
        strlen(message)) {
        errorhandler("Error sending Helo");
        closesocket(my_socket);
        clearwinsock();
        return EXIT_FAILURE;
    }

    while (1) {
        // get data from user
        password p = {0};

        do {
            fflush(stdin);
            printmenu();
            printf("Choice: ");
            scanf("%c", &p.type);  // get password type

            if (p.type == 'h') {
                continue;
            }

            if (p.type == 'q') {
                break;
            }

            scanf("%d", &p.length);  // get password length
            fflush(stdin);

            if (p.type != 'n' && p.type != 'a' && p.type != 'm' && p.type != 's' && p.type != 'u') {
                printf("\nInvalid password type!\n");
            }

            if (p.length < 6 || p.length > 32) {
                printf("\nInvalid password length! Min. 6 chars and Max 32 chars\n\n");
            }
        } while ((p.type != 'n' && p.type != 'a' && p.type != 'm' && p.type != 's' && p.type != 'u') || p.length < 6 ||
                 p.length > 32);

        // send data to server
        if (sendto(my_socket, (char *)&p, sizeof(password), 0, (struct sockaddr *)&server_address,
                   sizeof(server_address)) != sizeof(password)) {
            errorhandler("Error sending data");
            closesocket(my_socket);
            clearwinsock();
            return EXIT_FAILURE;
        }

        // receive data from server
        memset(&p, 0, sizeof(password));
        if ((rcv_msg_size = recvfrom(my_socket, (char *)&p, sizeof(password), 0, (struct sockaddr *)&server_address,
                                     &server_address_size)) < 0) {
            errorhandler("Error receiving data");
            closesocket(my_socket);
            clearwinsock();
            return EXIT_FAILURE;
        }

        printf("Generated password: %s\n\n", p.password);
    }
}  // main end
