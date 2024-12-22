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

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "generator.h"
#include "protocol.h"

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

    int client_socket;

    /* create a UDP socket */
    if ((client_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
        errorhandler("Error creating socket");
        clearwinsock();
        return EXIT_FAILURE;
    }

    /* set the server address */
    struct sockaddr_in server_address;
    struct sockaddr_in client_address;
    unsigned int client_address_length = sizeof(client_address);
    memset(&server_address, 0, sizeof(server_address));
    server_address.sin_family = AF_INET;
    server_address.sin_port = htons(SERVER_PORT);

    // Resolve the domain name to an IP address.
    struct hostent *host = gethostbyname(SERVER_HOST);
    if (host == NULL) {
        errorhandler("gethostbyname() failed");
        closesocket(client_socket);
        clearwinsock();
        return EXIT_FAILURE;
    }
    server_address.sin_addr.s_addr = *((unsigned long *)host->h_addr_list[0]);

    /* bind the socket to the server address */
    if (bind(client_socket, (struct sockaddr *)&server_address, sizeof(server_address)) < 0) {
        errorhandler("bind() failed");
        closesocket(client_socket);
        clearwinsock();
        return EXIT_FAILURE;
    }

    char buffer[BUFFER_SIZE];
    int rcv_msg_size;

    while (1) {
        puts("Server listening...");
        /* clean buffer */
        memset(buffer, 0, BUFFER_SIZE);
        /* receive message from client */
        if ((rcv_msg_size = recvfrom(client_socket, buffer, BUFFER_SIZE, 0, (struct sockaddr *)&client_address,
                                     &client_address_length)) < 0) {
            errorhandler("recvfrom() Helo failed");
            closesocket(client_socket);
            clearwinsock();
            return EXIT_FAILURE;
        }
        printf("New request from from %s:%d\n", inet_ntoa(client_address.sin_addr), ntohs(client_address.sin_port));

        // while client_socket is connected
        while (1) {
            password p;
            memset(p.password, '\0', 32);

            if ((recvfrom(client_socket, &p, sizeof(password), 0, (struct sockaddr *)&client_address,
                          &client_address_length)) <= 0) {
                errorhandler("recvfrom() failed or connection closed prematurely");
                closesocket(client_socket);
                clearwinsock();
                return -1;
            }

            if (p.type == 'q') {
                printf("Client disconnected.\n");
                break;
            }

            if (p.length < 6 || p.length > 32) {
                printf("Password length must be between 6 and 32 characters.\n");
            } else {
                printf("Password length: %d\n", p.length);

                switch (p.type) {
                    case 'n':
                        printf("Generating numeric password...\n");
                        generate_numeric(p.password, p.length);
                        printf("Generated password: %s\n", p.password);
                        break;
                    case 'a':
                        printf("Generating alphabetic password...\n");
                        generate_alpha(p.password, p.length);
                        printf("Generated password: %s\n", p.password);
                        break;
                    case 'm':
                        printf("Generating mixed password...\n");
                        generate_mixed(p.password, p.length);
                        printf("Generated password: %s\n", p.password);
                        break;
                    case 's':
                        printf("Generating secure password...\n");
                        generate_secure(p.password, p.length);
                        printf("Generated password: %s\n", p.password);
                        break;
                    case 'u':
                        printf("Generating unambiguous password...\n");
                        generate_unambiguous(p.password, p.length);
                        printf("Generated password: %s\n", p.password);
                        break;
                    default:
                        printf("Invalid password type!\n");
                        break;
                }
            }

            if (sendto(client_socket, &p, sizeof(password), 0, (struct sockaddr *)&client_address,
                       sizeof(client_address)) != sizeof(password)) {
                errorhandler("sendto() sent a different number of bytes than expected");
                closesocket(client_socket);
                clearwinsock();
                return EXIT_FAILURE;
            }
        }
    }

}  // main end

// function to generate numeric password
void generate_numeric(char *password, int length) {
    for (int i = 0; i < length; i++) {
        password[i] = (rand() % 10) + '0';
    }
}

// function to generate alphabetic password
void generate_alpha(char *password, int length) {
    for (int i = 0; i < length; i++) {
        password[i] = (rand() % 26) + 'a';
    }
}

// function to generate mixed password
void generate_mixed(char *password, int length) {
    for (int i = 0; i < length; i++) {
        if (rand() % 2 == 0) {
            password[i] = (rand() % 26) + 'a';
        } else {
            password[i] = (rand() % 10) + '0';
        }
    }
}

// function to generate secure password
void generate_secure(char *password, int length) {
    for (int i = 0; i < length; i++) {
        switch (rand() % 4) {
            case 0:
                password[i] = (rand() % 26) + 'a';
                break;
            case 1:
                password[i] = (rand() % 26) + 'A';
                break;
            case 2:
                password[i] = (rand() % 10) + '0';
                break;
            case 3:
                password[i] = (rand() % 15) + '!';
                break;
            default:
                break;
        }
    }
}

// function to generate unambiguous password
void generate_unambiguous(char *password, int length) {
    char unambiguous[] = "0Oo1lIi2Zz5Ss8B";

    for (int i = 0; i < length; i++) {
        char c;
        do {
            switch (rand() % 4) {
                case 0:
                    c = (rand() % 26) + 'a';
                    break;
                case 1:
                    c = (rand() % 26) + 'A';
                    break;
                case 2:
                    c = (rand() % 10) + '0';
                    break;
                case 3:
                    c = (rand() % 15) + '!';
                    break;
                default:
                    break;
            }
        } while (strchr(unambiguous, c) != NULL);
        password[i] = c;
    }
}
