#ifndef __U_CRYPTO
#define __U_CRYPTO

struct configs;

unsigned char *hashMe(struct configs *cfg, unsigned char *passphrase);


#endif
