#ifndef __AUTH
#define __AUTH

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

struct configs;

bool authUser_sqlite(struct configs *cfg, int fd, char *userprompt_reply, char *passprompt_reply);
bool authUser_configs(struct configs *cfg, int fd, char *userprompt_reply, char *passprompt_reply);
bool promptUser(struct configs *cfg, int fd, char *RHOST, int RPORT,int num_attempts, SSL *ssl_obj);

#endif
