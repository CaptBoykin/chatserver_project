#ifndef __CONFIG_PARSER
#define __CONFIG_PARSER

// Config struct...nearly everything is a char* and will be changed later
struct configs
{
	char *lhost_addr;
	char *lhost_port;
	char *verbose;
	char *maxhistory;
	char *maxlength;
	char *maxclients;
	char *use_aaa;
	char *use_ssl;
	char *auth_hash;
	int num_attempts;
	int num_endpoints;
	struct ssl_opts
	{
		int num_flags;
		char *ssl_cert_file;
		char *ssl_key_file;
		char *ssl_cipher;
		char **sslflagslist;
		struct ssl_flags
		{
			bool sslv2;
			bool sslv3;
			bool compression;
		}ssl_flags;
	}ssl_opts;
	char **blacklist;
	char **whitelist;
}configs;

struct configs *config_parse(char *filename);

#endif
