#include <string.h>
#include <stdbool.h>

// for hashing
#include <openssl/sha.h>


// for encryption
#include <openssl/aes.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>


#include "../includes/debug.h"
#include "../includes/misc_funcs.h"
#include "../includes/u_crypto.h"
#include "../includes/config_parser.h"


struct configs;

unsigned char *hashMe(struct configs *cfg, unsigned char *passphrase)
{
	int i;
	int digest_len;
	unsigned char *digest;
	unsigned char *digestHex;

	d_print();
	if( (strcmp(cfg->auth_hash,"SHA1")) == 0)
	{
		d_print();
		digest = SHA1(passphrase,strlen((char *)passphrase),0);
		digest_len = SHA_DIGEST_LENGTH;
		digestHex = calloc((SHA_DIGEST_LENGTH*2)+1,sizeof(char));
	}

	else if( (strcmp(cfg->auth_hash,"SHA224")) == 0)
	{
		d_print();
		digest = SHA224(passphrase,strlen((char *)passphrase),0);
		digest_len = SHA224_DIGEST_LENGTH;
		digestHex = calloc((SHA224_DIGEST_LENGTH*2)+1,sizeof(char));
	}

	else if( (strcmp(cfg->auth_hash,"SHA256")) == 0)
	{
		d_print();
		digest = SHA256(passphrase,strlen((char *)passphrase),0);
		digest_len = SHA256_DIGEST_LENGTH;
		digestHex = calloc((SHA256_DIGEST_LENGTH*2)+1,sizeof(char));
	}

	else if( (strcmp(cfg->auth_hash,"SHA384")) == 0)
	{
		d_print();
		digest = SHA384(passphrase,strlen((char *)passphrase),0);
		digest_len = SHA384_DIGEST_LENGTH;
		digestHex = calloc((SHA384_DIGEST_LENGTH*2)+1,sizeof(char));
	}

	else if( (strcmp(cfg->auth_hash,"SHA512")) == 0)
	{
		d_print();
		digest = SHA512(passphrase,strlen((char *)passphrase),0);
		digest_len = SHA512_DIGEST_LENGTH;
		digestHex = calloc((SHA512_DIGEST_LENGTH*2)+1,sizeof(char));
	}
	else
	{
		error("Hashing error | invalid alg. provided!",__LINE__,__func__);
	}

	d_print();
	for(i=0;i<digest_len;i++)
	{
		sprintf((char *)digestHex+(i*2),"%02x",digest[i]);
	}
	return digestHex;
}
