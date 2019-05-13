#ifndef __SSL_SERV
#define __SSL_SERV

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

struct ssl_client_list
{
        SSL *ssl_obj;
        int sd;
        struct ssl_client_list *next;

}ssl_client_list;

struct configs;
int ssl_serv(struct configs *cfg);
SSL *find_SSL_obj(struct ssl_client_list *list, int sd);
#endif
