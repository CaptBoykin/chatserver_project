#ifndef __MSGBOARD_FUNCS
#define __MSGBOARD_FUNCS

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

struct configs;
struct ssl_client_list;
void flush_remote(fd);
void prompt_remote(fd);
void flush_remote_all(int *client_sockets,int maxclients);
void prompt_remote_all(int *client_sockets,int maxclients);
void append_msgboard(char **msgboard, char *entry, int fd, char *addr, int port, bool full, struct configs *cfg);
void print_msgboard_unsecured(char **msgboard, int *client_socket, struct configs *cfg);
void print_msgboard_SSL(char **msgboard, int *client_socket, struct ssl_client_list *ssl_clients, struct configs *cfg);
void print_msgboard_fd_unsecured(char **msgboard, int *client_sockets, int fd, struct configs *cfg);
void print_msgboard_fd_SSL(char **msgboard, int *client_sockets, struct ssl_client_list *ssl_clients, int fd, struct configs *cfg);
#endif
