#ifndef PROTOCOL_H_
#define PROTOCOL_H_

#define SERVER_HOST "passwdgen.uniba.it"
#define SERVER_PORT 48000
#define BUFFER_SIZE 64

typedef struct {
	char type;
	int length;
	char password[32];
} password;

#endif /* PROTOCOL_H_ */
