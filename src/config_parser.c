#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <ctype.h>

#include "../includes/config_parser.h"
#include "../includes/misc_funcs.h"
#include "../includes/debug.h"

/*
 * Tyler Boykin
 *
 * Implemented from earlier config_parser, sockserv, chat serv projects
 *
 *
 */

// BL = blacklist approach (returns true default) 
// WL = whitelist approach (returns false default)
struct configs *config_parse(char *filename);
struct configs *fillDefaults(struct configs *cfg);
struct configs *loadCfg(char *filename);
bool BL_validate_PORT(char *port);							
bool BL_validate_ADDRESS(char *address);
bool WL_validate_SSLOPTS(struct configs *cfg);
bool WL_validate_VERBOSE(char *verbose);
bool WL_validate_MAXCLIENTS(char *max_clients);
bool WL_validate_MAXLENGTH(char *maxlength);
bool WL_validate_MAXHISTORY(char *maxhistory);
bool BL_validate_FORMAT(struct configs *cfg);
bool BL_validate_CFG(struct configs *cfg);
bool WL_validate_AUTH_HASH(struct configs *cfg);
bool BL_validate_AAA(struct configs *cfg);
void print_loaded(struct configs *cfg);

// SERVER DEFAULTS
const char *defPORT = "9999";
const char *defMAXCLIENTS = "5";
const char *defMAXLENGTH = "128";
const char *defMAXHISTORY = "10";
const char *defUSE_SSL = "true";
const char *defVERBOSE = "3";
const char *defSSL_CERT_FILE = "certs/proxy_certificate.pem";
const char *defSSL_KEY_FILE = "certs/proxy_key.pem";
const char *defUSE_AAA	= "false";
const char *defAUTH_HASH = "SHA1";
//To do... the below
//const char *defSSL_CIPHER =
//const char *defSSL_DIR =

struct configs *fillDefaults(struct configs *cfg)
{
	int len;
	// RATIONALE:  If not previously created with a calloc... create it now and fill it with a default
	if(cfg->verbose == NULL)
	{
		len = strlen(defVERBOSE)+1;
		if(! (cfg->verbose = calloc(len,sizeof(char))))
		{
			error("Allocation failed | Defaults: verbose",__LINE__,__func__);
		}
		strncpy(cfg->verbose,defVERBOSE,len);
	}
	if(cfg->lhost_port == NULL)
	{
		len = strlen(defPORT)+1;
		if(! (cfg->lhost_port = calloc(len,sizeof(char))))
		{
			error("Allocation failed | Defaults: port",__LINE__,__func__);
		}
		strncpy(cfg->lhost_port,defPORT,len);
	}
	if(cfg->maxhistory == NULL)
	{
		len = strlen(defMAXHISTORY)+1;
		if(! (cfg->maxhistory = calloc(len,sizeof(char))))
		{
			error("Allocation failed | Defaults: maxhistory",__LINE__,__func__);
		}
		strncpy(cfg->maxhistory,defMAXHISTORY,len);
	}
	if(cfg->maxlength == NULL)
	{
		len = strlen(defMAXLENGTH)+1;
		if(! (cfg->maxlength = calloc(len,sizeof(char))))
		{
			error("Allocation failed | Defaults: maxlength",__LINE__,__func__);
		}
		strncpy(cfg->maxlength,defMAXLENGTH,len);		
	}
	if(cfg->maxclients == NULL)
	{
		len = strlen(defMAXCLIENTS)+1;
		if(! (cfg->maxclients = calloc(len,sizeof(char))))
		{
			error("Allocation failed | Defaults: maxclients",__LINE__,__func__);
		}
		strncpy(cfg->maxclients,defMAXCLIENTS,len);
	}
	if(cfg->use_ssl == NULL)
	{
		len = strlen(defUSE_SSL)+1;
		if(! (cfg->use_ssl = calloc(len,sizeof(char))))
		{
			error("Allocation failed | Defaults: use_ssl",__LINE__,__func__);
		}
		strncpy(cfg->use_ssl,defUSE_SSL,len);
	}
	if(cfg->ssl_opts.ssl_cert_file == NULL)
	{
		len = strlen(defSSL_CERT_FILE)+1;
		if(! (cfg->ssl_opts.ssl_cert_file = calloc(len,sizeof(char))))
		{
			error("Allocation failed | Defaults: ssl_cert_file",__LINE__,__func__);
		}
		strncpy(cfg->ssl_opts.ssl_cert_file,defSSL_CERT_FILE,len);
	}
	if(cfg->ssl_opts.ssl_key_file == NULL)
	{
		len = strlen(defSSL_KEY_FILE)+1;
		if(! (cfg->ssl_opts.ssl_key_file = calloc(len,sizeof(char))))
		{
			error("Allocation failed | Defaults: ssl_key_file",__LINE__,__func__);
		}
		strncpy(cfg->ssl_opts.ssl_key_file,defSSL_KEY_FILE,len);
	}
	if(cfg->use_aaa == NULL)
	{
		len = strlen(defUSE_AAA)+1;
		if(! (cfg->use_aaa = calloc(len,sizeof(char))))
		{
			error("Allocation failed | Defaults: use_aaa",__LINE__,__func__);
		}
		strncpy(cfg->use_aaa,defUSE_AAA,len);
	}
	if(cfg->auth_hash == NULL)
	{
		len = strlen(defAUTH_HASH)+1;
		if(! (cfg->auth_hash = calloc(len,sizeof(char))))
		{
			error("Allocation failed | Defaults: auth_hash",__LINE__,__func__);
		}
		strncpy(cfg->auth_hash,defAUTH_HASH,len);
	}

	if(cfg->num_attempts == NULL)
	{
		cfg->num_attempts = 1;
	}

	/* we will work on these soon
	if(cfg->ssl_opts.ssl_cipher == NULL)
	{

	}
	if(cfg->ssl_opts.sslflagslist == NULL)
	{

	}
	if(cfg->ssl_opts.ssl_flags.sslv2 == NULL)
	{

	}
	if(cfg->ssl_opts.ssl_flags.sslv3 == NULL)
	{

	}
	if(cfg->ssl_opts.ssl_flags.compression == NULL)
	{

	}
	*/

	return cfg;
}
struct configs *config_parse(char *filename)
{
	struct configs *config_list;
	config_list = malloc(sizeof(struct configs)*sizeof(char *));

	if((config_list = loadCfg(filename)) == NULL)
	{
		error("Please supply a config file",__LINE__,__func__);
		exit(EXIT_FAILURE);
	}

	if(! BL_validate_CFG(config_list))
	{
		error("Invalid Config file!",__LINE__,__func__);
		exit(EXIT_FAILURE);
	}

	config_list = fillDefaults(config_list);
	return config_list;
}

/*
 * i. Opens config file
 * ii. Goes line by line looking for keywords
 * iii. takes those key words and breaks the line up by a delimeter using strtok_r()
 * iv. stores the value in the struct
 *
 * Does not evaluate correctness of data, only basic type checking / error checking.
 */

struct configs *loadCfg(char *filename)
{
	const char *_VERBOSE = "VERBOSE";
	const char *_ADDR = "ADDRESS";
	const char *_PORT = "PORT";
	const char *_USE_SSL = "USE_SSL";
	const char *_SSL_CIPHER = "SSL_CIPHER";
	const char *_SSL_CERT_FILE = "SSL_CERT_FILE";
	const char *_SSL_KEY_FILE = "SSL_KEY_FILE";
	const char *_SSL_FLAGS = "SSL_FLAGS";
	const char *_MAX_HISTORY = "MAX_HISTORY";
	const char *_MAX_LENGTH = "MAX_LENGTH";
	const char *_BLACKLIST = "BLACKLIST";
	const char *_WHITELIST = "WHITELIST";
	const char *_MAX_CLIENTS = "MAX_CLIENTS";
	const char *_USE_AAA = "USE_AAA";
	const char *_NUM_ATTEMPTS = "NUM_ATTEMPTS";
	const char *_AUTH_HASH = "AUTH_HASH";
	int line_no = 1;		// Debug output for syntax
	int i, ii;				// Generic iterators
	int num_endpoints = 0;	// Number of endpoints.
	int num_flags = 0;
	int token_len = 0;		// 'Token' being used with strtok_r()
	char *line_buf = NULL;	// Buffer used for each line entry... space is reallocated for each entry.
	size_t line_buf_size = 0;
	ssize_t line_size = 0;
	FILE *cfg;		// config file FD
	char *tokenA;	// Original strtok_k token ([PARAM]=value -> PARAM=[Value])
	char *tokenB;	// Drills down into [Value](PARAM=[ValueA,ValueB] -> PARAM=[ValueA],ValueB)
	char *saveA;	// strtok_r()
	char *saveB;	// strtok_r()
	char *orig;		// Used to restore original string for tokenB


	// Init. the configs struct
	struct configs *config_list = malloc(sizeof(struct configs));
	if(! (cfg = fopen(filename,"r")) )
	{
		error("Error opening cfg file",__LINE__,__func__);
		exit(EXIT_FAILURE);	
	}

	line_size = getline(&line_buf, &line_buf_size, cfg);
	while(line_size >= 0)
	{
		for(i=0;i<(int)line_buf_size;i++)
		{
			if((line_buf[i] == '#') || (line_buf[i] == '\n'))
			{
				break;
			}
			else if(line_buf[i] == '=')
			{
				/*
				 * Evaluates [PARAM]=value...  basic schema is detailed below
				 */
				// populate the first token with the first [PARAM]
				tokenA = strtok_r(line_buf,"=",&saveA);
				
				// evaluate the [PARAM]
				if( (strcmp(tokenA,_ADDR)) == 0)
				{
					// this shift down to PARAM=[value]
					tokenA = strtok_r(NULL,"=",&saveA);
					token_len = strlen(tokenA)+1;

					// create space in the pointer for [value]
					if(! (config_list->lhost_addr = calloc(token_len,sizeof(char))))
					{
						error("Allocation failed | config_list->address",__LINE__,__func__);
					}
					// copy value into the space
					strncpy(config_list->lhost_addr,tokenA,token_len);
					break;
				}
				else if( (strcmp(tokenA,_PORT)) == 0)
				{
					tokenA = strtok_r(NULL,"=",&saveA);
					token_len = strlen(tokenA)+1;
					if(! (config_list->lhost_port = calloc(token_len,sizeof(char))))
					{
						error("Allocation failed | config_list->port",__LINE__,__func__);
					}
					strncpy(config_list->lhost_port,tokenA,token_len);
					break;
				}
				else if( (strcmp(tokenA,_VERBOSE)) == 0)
				{
					tokenA = strtok_r(NULL,"=",&saveA);
					token_len = strlen(tokenA)+1;
					if(! (config_list->verbose = calloc(token_len,sizeof(char))))
					{
						error("Allocation failed | config_list->verbose",__LINE__,__func__);
					}
					strncpy(config_list->verbose,tokenA,token_len);
					break;
				}
				else if( (strcmp(tokenA,_MAX_HISTORY)) == 0)
				{
					tokenA = strtok_r(NULL,"=",&saveA);
					token_len = strlen(tokenA)+1;
					if(! (config_list->maxhistory = calloc(token_len,sizeof(char))))
					{
						error("Allocation failed | config_list->msghistory",__LINE__,__func__);
					}
					strncpy(config_list->maxhistory,tokenA,strlen(tokenA));
					break;
				}
				else if( (strcmp(tokenA,_MAX_LENGTH)) == 0)
				{
					tokenA = strtok_r(NULL,"=",&saveA);
					token_len = strlen(tokenA)+1;
					if(! (config_list->maxlength = calloc(token_len,sizeof(char))))
					{
						error("Allocation failed | config_list->msglength",__LINE__,__func__);
					}
					strncpy(config_list->maxlength,tokenA,token_len);
					break;

				}
				else if( (strcmp(tokenA,_MAX_CLIENTS)) == 0)
				{
					tokenA = strtok_r(NULL,"=",&saveA);
					token_len = strlen(tokenA)+1;
					if(! (config_list->maxclients = calloc(token_len,sizeof(char))))
					{
						error("Allocation failed | config_list->maxclients",__LINE__,__func__);
					}
					strncpy(config_list->maxclients,tokenA,token_len);
					break;
				}
				else if((strcmp(tokenA,_USE_AAA)) == 0)
				{
					tokenA = strtok_r(NULL,"=",&saveA);
					token_len = strlen(tokenA)+1;
					if(! (config_list->use_aaa = calloc(token_len,sizeof(char))))
					{
						error("Allocation failed | config_list->use_aaa",__LINE__,__func__);
					}
					strncpy(config_list->use_aaa,tokenA,token_len);
					break;
				}
				else if((strcmp(tokenA,_AUTH_HASH)) == 0)
				{
					tokenA = strtok_r(NULL,"=",&saveA);
					token_len = strlen(tokenA)+1;
					if(! (config_list->auth_hash = calloc(token_len,sizeof(char))))
					{
						error("Allocation failed | config_list->auth_hash",__LINE__,__func__);
					}
					strncpy(config_list->auth_hash,tokenA,token_len);
					break;
				}
				else if((strcmp(tokenA,_NUM_ATTEMPTS)) == 0)
				{
					tokenA = strtok_r(NULL,"=",&saveA);
					config_list->num_attempts = atoi(tokenA);
					break;
				}
				else if((strcmp(tokenA,_BLACKLIST)) == 0)
				{
					// Adjust from [PARAM]=Value to PARAM=[Value]
					tokenA = strtok_r(NULL,"=",&saveA);

					// Saving the original place of strtok_r
					orig = calloc(strlen(tokenA)+1,sizeof(char));
					strncpy(orig,tokenA,strlen(tokenA));

					// Drill down into PARAM=[Value]
					tokenB = strtok_r(tokenA,",",&saveB);

					while(tokenB != NULL)
					{
						num_endpoints++;
						tokenB = strtok_r(NULL,",",&saveB);
					}
					config_list->num_endpoints = num_endpoints;

					if(! (config_list->blacklist = calloc(num_endpoints,sizeof(char *))))
					{
						error("Calloc Error | config_list->blacklist",__LINE__,__func__);
					}

					// Restore tokenB to old value (ie 1.1.1.1,2.2.2.2,3.3.3.3)
					tokenB = orig;

					// refer back to itself, when doing the initial strtok_r()
					tokenB = strtok_r(tokenB,",",&saveB);

					for(ii=0;ii<num_endpoints;ii++)
					{
						if(! (config_list->blacklist[ii] = calloc(sizeof(tokenB)+1,sizeof(char))))
						{
							error("Calloc Error | config_list->blacklist",__LINE__,__func__);
						}
						strncpy(config_list->blacklist[ii],tokenB,strlen(tokenB));
						tokenB = strtok_r(NULL,",",&saveB);
					}
				}
				else if( (strcmp(tokenA,_WHITELIST)) == 0)
				{
					// Adjust from [PARAM]=Value to PARAM=[Value]
					tokenA = strtok_r(NULL,"=",&saveA);

					// Saving the original place of strtok_r
					orig = calloc(strlen(tokenA)+1,sizeof(char));
					strncpy(orig,tokenA,strlen(tokenA));

					// Drill down into PARAM=[Value]
					tokenB = strtok_r(tokenA,",",&saveB);

					while(tokenB != NULL)
					{
						num_endpoints++;
						tokenB = strtok_r(NULL,",",&saveB);
					}
					config_list->num_endpoints = num_endpoints;

					if(! (config_list->whitelist = calloc(num_endpoints,sizeof(char *))))
					{
						error("Calloc Error | config_list->whitelist",__LINE__,__func__);
					}
					// Restore tokenB to old value (ie 1.1.1.1,2.2.2.2,3.3.3.3)
					tokenB = orig;

					// refer back to itself, when doing the initial strtok_r()
					tokenB = strtok_r(tokenB,",",&saveB);

					for(ii=0;ii<num_endpoints;ii++)
					{
						if(! (config_list->whitelist[ii] = calloc(sizeof(tokenB)+1,sizeof(char))))
						{
								error("Calloc Error | config_list->whitelist",__LINE__,__func__);
						}
						strncpy(config_list->whitelist[ii],tokenB,strlen(tokenB));
						tokenB = strtok_r(NULL,",",&saveB);
					}
				}
				else if( (strcmp(tokenA,_USE_SSL)) == 0)
				{
					tokenA = strtok_r(NULL,"=",&saveA);
					token_len = strlen(tokenA)+1;
					if(! (config_list->use_ssl = calloc(token_len,sizeof(char))))
					{
						error("Allocation failed | config_list->use_ssl",__LINE__,__func__);
					}
					strncpy(config_list->use_ssl,tokenA,token_len);
					break;	
				}
				else if( (strcmp(config_list->use_ssl,"true")) == 0)
				{
					if( (strcmp(tokenA,_SSL_CERT_FILE)) == 0)
					{
						tokenA = strtok_r(NULL,"=",&saveA);
						token_len = strlen(tokenA)+1;
					
						if(! (config_list->ssl_opts.ssl_cert_file = calloc(token_len,sizeof(char))))
						{
							error("Allocation failed | config_list->ssl_opts->ssl_cert_file",__LINE__,__func__);
						}
						strncpy(config_list->ssl_opts.ssl_cert_file,tokenA,token_len);
						break;
					}
					else if( (strcmp(tokenA,_SSL_KEY_FILE)) == 0)
					{
						tokenA = strtok_r(NULL,"=",&saveA);
						token_len = strlen(tokenA)+1;
						if(! (config_list->ssl_opts.ssl_key_file = calloc(token_len,sizeof(char))))
						{
							error("Allocation failed|  config_list->ssl_opts->ssl_key_file",__LINE__,__func__);
						}
						strncpy(config_list->ssl_opts.ssl_key_file,tokenA,token_len);
						break;
					}
					else if( (strcmp(tokenA,_SSL_CIPHER)) == 0)
					{
						tokenA = strtok_r(NULL,"=",&saveA);
						token_len = strlen(tokenA)+1;
						if(! (config_list->ssl_opts.ssl_cipher = calloc(token_len,sizeof(char))))
						{
							error("Allocation failed | config_list->ssl_opts->ssl_cipher",__LINE__,__func__);
						}
						strncpy(config_list->ssl_opts.ssl_cipher,tokenA,token_len);
						break;
					}
					else if( (strcmp(tokenA,_SSL_FLAGS)) == 0)
					{
						// Adjust from [PARAM]=Value to PARAM=[Value]
						tokenA = strtok_r(NULL,"=",&saveA);

						// Saving the original place of strtok_r
						orig = calloc(strlen(tokenA)+1,sizeof(char));
						strncpy(orig,tokenA,strlen(tokenA));

						// Drill down into PARAM=[Value]
						tokenB = strtok_r(tokenA,",",&saveB);

						while(tokenB != NULL)
						{
							num_flags++;
							tokenB = strtok_r(NULL,",",&saveB);
						}

						if(! (config_list->ssl_opts.sslflagslist = calloc(num_flags,sizeof(char *))))
						{
							error("Calloc Error | config_list->sslflagslist",__LINE__,__func__);
						}

						// Restore tokenB to old value
						tokenB = orig;

						// refer back to itself, when doing the initial strtok_r()
						tokenB = strtok_r(tokenB,",",&saveB);

						for(ii=0;ii<num_flags;ii++)
						{
							if(! (config_list->ssl_opts.sslflagslist[ii] = calloc(sizeof(tokenB)+1,sizeof(char))))
							{
								error("Calloc Error | config_list->sslflagslist",__LINE__,__func__);
							}
							strncpy(config_list->ssl_opts.sslflagslist[ii],tokenB,strlen(tokenB));
							tokenB = strtok_r(NULL,",",&saveB);
						}
					}
				}
			}

		}	
		line_no++;
		line_size = getline(&line_buf, &line_buf_size, cfg);
	}



	//Disqualify if both WHITELIST and BLACKLIST are 'on'
	//
	if((config_list->whitelist != NULL) && (config_list->blacklist != NULL))
	{
		error("Config Error | Cannot have both whitelist and blacklist active!",__LINE__,__func__);
		exit(EXIT_FAILURE);
	}

	//Normalization to morph LF and CR into NULLS
	if(config_list->lhost_addr != NULL)
	{
		for(i=0;i<(int)strlen(config_list->lhost_addr);i++)
		{
			if( (config_list->lhost_addr[i] == '\n') || (config_list->lhost_addr[i] == '\r'))
			{
				config_list->lhost_addr[i] = '\0';
			}
		}
	}
	d_print();
	if(config_list->lhost_port != NULL)
	{
		for(i=0;i<(int)strlen(config_list->lhost_port);i++)
		{	
			if( (config_list->lhost_port[i] == '\n') || (config_list->lhost_port[i] == '\r'))
			{
				config_list->lhost_port[i] = '\0';
			}
		}
	}
	d_print();
	if(config_list->verbose != NULL)
	{
		for(i=0;i<(int)strlen(config_list->verbose);i++)
		{
			if( (config_list->verbose[i] == '\n') || (config_list->verbose[i] == '\r'))
			{
				config_list->verbose[i] = '\0';
			}
		}
	}
    d_print();
	if(config_list->maxhistory != NULL)
	{
		for(i=0;i<(int)strlen(config_list->maxhistory);i++)
    	{
        	if( (config_list->maxhistory[i] == '\n') || (config_list->maxhistory[i] == '\r'))
       		{
        		config_list->maxhistory[i] = '\0';
       		}
    	}
	}
	d_print();
	if(config_list->maxlength != NULL)
	{
		for(i=0;i<(int)strlen(config_list->maxlength);i++)
		{
			if( (config_list->maxlength[i] == '\n') || (config_list->maxlength[i] == '\r'))
			{
				config_list->maxlength[i] = '\0';
			}
		}
	}
	d_print();
	if(config_list->maxclients != NULL)
	{
		for(i=0;i<(int)strlen(config_list->maxclients);i++)
		{
			if( (config_list->maxclients[i] == '\n') || (config_list->maxclients[i] == '\r'))
			{
				config_list->maxclients[i] = '\0';
			}
		}
	}

	d_print();
    if(config_list->whitelist)
	{
		for(i=0;i<num_endpoints;i++)
		{
			for(ii=0;ii<(int)strlen(config_list->whitelist[i]);ii++)
			{
				if( (config_list->whitelist[i][ii] == '\n') || (config_list->whitelist[i][ii] == '\r'))
				{
					config_list->whitelist[i][ii] = '\0';
				}
			}
		}
	}
	else if(config_list->blacklist)
	{
		for(i=0;i<(int)num_endpoints;i++)
		{
			for(ii=0;ii<(int)strlen(config_list->blacklist[i]);ii++)
			{
				if( (config_list->blacklist[i][ii] == '\n') || (config_list->blacklist[i][ii] == '\r'))
				{
					config_list->blacklist[i][ii] = '\0';
				}
			}
		}
	}
	d_print();
	if(config_list->use_aaa != NULL)
	{
		for(i=0;i<(int)strlen(config_list->use_aaa);i++)
		{
			if( (config_list->use_aaa[i] == '\n') || (config_list->use_aaa[i] == '\r'))
			{
				config_list->use_aaa[i] = '\0';
			}
		}
	}
	d_print();
	if(config_list->auth_hash != NULL)
	{
		for(i=0;i<(int)strlen(config_list->auth_hash);i++)
		{
			if( (config_list->auth_hash[i] == '\n') || (config_list->auth_hash[i] == '\r'))
			{
				config_list->auth_hash[i] = '\0';
			}
		}
	}
	d_print();
	if(config_list->use_ssl != NULL)
	{
		for(i=0;i<(int)strlen(config_list->use_ssl);i++)
		{
			if( (config_list->use_ssl[i] == '\n') || (config_list->use_ssl[i] == '\r'))
			{
				config_list->use_ssl[i] = '\0';
			}
		}
	}
	d_print();
	if((strcmp(config_list->use_ssl,"true")) == 0)
	{
		if(config_list->ssl_opts.sslflagslist != NULL)
		{
			for(i=0;i<config_list->ssl_opts.num_flags;i++)
			{
				for(ii=0;i<(int)strlen(config_list->ssl_opts.sslflagslist[i]);ii++)
				{
					if( (config_list->ssl_opts.sslflagslist[i][ii] == '\n') || (config_list->ssl_opts.sslflagslist[i][ii] == '\r'))
					{
						config_list->ssl_opts.sslflagslist[i][ii] = '\0';
					}
				}
			}
		}
		d_print();
		if(config_list->ssl_opts.ssl_cert_file != NULL)
		{
			for(i=0;i<(int)strlen(config_list->ssl_opts.ssl_cert_file);i++)
			{
				if( (config_list->ssl_opts.ssl_cert_file[i] == '\n') || (config_list->ssl_opts.ssl_cert_file[i] == '\r'))
				{
					config_list->ssl_opts.ssl_cert_file[i] = '\0';
				}
			}
		}
		d_print();
		if(config_list->ssl_opts.ssl_key_file != NULL)
		{
			for(i=0;i<(int)strlen(config_list->ssl_opts.ssl_key_file);i++)
			{
				if( (config_list->ssl_opts.ssl_key_file[i] == '\n') || (config_list->ssl_opts.ssl_key_file[i] == '\r'))
				{
					config_list->ssl_opts.ssl_key_file[i] = '\0';
				}
			}
		}

	/*
		for(i=0;i<strlen(config_list->ssl_opts.ssl_cipher);i++)
		{
			if( (config_list->ssl_opts.ssl_cipher[i] == '\n') || (config_list->ssl_opts.ssl_cipher[i] == '\r'))
			{
				config_list->ssl_opts.ssl_cipher[i] = '\0';
			}
		}
		fprintf(stderr,"***DEBUG: Normalization OK! ssl_cipher\n");
	*/
	// TO DO: a proper evaluation of whitelist/blacklist
	}

	d_print();
	free(line_buf);
	line_buf = NULL; 
	fclose(cfg);
	d_print();

	return config_list;
}

/*
 * The below WILL use fprintf() intead of error as everything will exit out anyways once 
 * one of the check's fail
 */


bool BL_validate_PORT(char *port)
{
	int i;
	int len = strlen(port);
	int port_no;
   
	if( (port_no = atoi(port)) == 0)
	{
		fprintf(stderr,"[-][%s] Invalid Port. atoi()\n",__func__);
		return false;
	}
	// 1-65535... anything len 0 or 6+ is invalid
	if( (len <= 0) || (len >= 6) )
	{
		fprintf(stderr,"[-][%s] Invalid Port. Incorrect Length.\n",__func__);
		return false;
	}
	// make sure all digits
	for(i=0;i<len;i++)
	{
		if(isdigit(port[i]) == 0)
		{
			fprintf(stderr,"[-][%s] Invalid Port. Invalid Char.\n",__func__);
			return false;
		}
	}
	// 1-65535
	if(! ((port_no >= 1) && (port_no <= 65535)))
	{
		fprintf(stderr,"[-][%s] Invalid Port. Out of range.\n",__func__);
		return false;
	}
	return true;
}


bool BL_validate_ADDRESS(char *address)
{
	const char *reserved_bcast = "255.255.255.255";
	char *octet;
	char *octet_save;
	char *octet_copy;
	int i, octet_no=0, len=0, dots=0;
	// 
	int octet_value;
	len = strlen(address);

	octet_copy = calloc(strlen(address)+1,sizeof(char));
	strncpy(octet_copy,address,len);

	// are they all digits or .'s
	for(i=0;i<len;i++)
	{
		if( (isdigit(address[i]) == 0) && (address[i] != '.'))
		{
			fprintf(stderr,"[-][%s] Invalid Address.  Invalid character(hex: %x )\n",__func__,address[i]);
			return false;
		}	
	}
	
	// are there too many octets (indicative by more than 3 .'s)
	for(i=0;i<len;i++)
	{
		if(	(address[i] == '.'))
		{
			dots++;
		}
	}
	if(dots >= 4)
	{
		fprintf(stderr,"[-][%s] Invalid Address. Improper number of octets\n",__func__);
		return false;
	}
	// no 255.255.255.255
	if(strncmp(address,reserved_bcast,strlen(reserved_bcast)) == 0)
	{
		fprintf(stderr,"[-][%s] Invalid Address. Broadcast not allowed\n",__func__);
		return false;
	}
	octet = strtok_r(octet_copy,".",&octet_save);
	while(octet != NULL)
	{
		octet_value = atoi(octet);	
		octet_no++;
		// make sure that three digit octets only have 2xx.2xx.2xx.2xx maximum
		if(	( strlen(octet) > 3) || (strlen(octet) < 1) )
		{
			fprintf(stderr,"[-][%s] Invalid Address. Invalid Octet size\n",__func__);
			return false;
		}
		// no 0xx.xxx.xxx.xxx
		if( (octet_value <= 0) && (octet_no == 1) )
		{
			fprintf(stderr,"[-][%s] Invalid Address. Cannot start with 0\n",__func__);
			return false;
		}
		// 1-255,  no 0 or 256+
		if(! ((octet_value >= 0) && (octet_value <= 255)))
		{
			fprintf(stderr,"[-][%s] Invalid Address. Octet range 1-255\n",__func__);
			return false;
		}
		octet = strtok_r(NULL,".",&octet_save);
	}
	return true;
}

bool WL_validate_MAXCLIENTS(char *maxclients)
{
	// TO DO: ...all this
	int amt;

	// First we validate if stuff is numeric only...
	// atoi() returns 0 if no number can be provided (ie...a char/symbol)
	if( (atoi(maxclients)) == 0)
	{
		fprintf(stderr,"[-][%s] Invalid maxclients. Numbers only\n",__func__);
		return false;
	}
	amt = atoi(maxclients);

	// Then we validate the amount given
	if((amt > 1) && (amt < 51))
	{
		return true;
	}
	fprintf(stderr,"[-][%s] Invalid maxclients. Range 2-50\n",__func__);
	return false;
}

bool WL_validate_VERBOSE(char *verbose)
{
	char zero[] = "0";
	char one[] = "1";
	char two[] = "2";
	char three[] = "3";

	if( (strcmp(verbose,zero) == 0) || (strcmp(verbose,one) == 0) || (strcmp(verbose,two) == 0) || (strcmp(verbose,three) == 0))
	{
		return true;
	}
	fprintf(stderr,"[-][%s] Invalid Verbosity. Entry %s\n",__func__,verbose);
	return false;
}

bool WL_validate_MAXHISTORY(char *maxhistory)
{
	// TO DO: Ensure this has a good default
	int history;
   
	if( (atoi(maxhistory)) == 0)
	{
		fprintf(stderr,"[-][%s] Invalid msghistory entry | cfg->msghistory\n",__func__);
		return false;
	}
	history = atoi(maxhistory);
	if((history > 5) && (history < 20))
	{
		return true;
	}
	fprintf(stderr,"[-][%s] Invalid msghistory value (5-20)\n",__func__);
	return false;
}

bool WL_validate_MAXLENGTH(char *maxlength)
{
	int length;
	if( (atoi(maxlength)) == 0)
	{
		fprintf(stderr,"[-][%s] Invalid msglength entry | cfg->msglength\n",__func__);
		return false;
	}
	length = atoi(maxlength);
	if((length > 20) && (length < 512))
	{
		return true;
	}
	fprintf(stderr,"[-][%s] Invalid msglength value (20-512)\n",__func__);
	return false;
}

bool BL_validate_ENDPOINTS(struct configs *cfg)
{
	int i;
	if(cfg->whitelist != NULL)
	{
		for(i=0;i<cfg->num_endpoints;i++)
		{
			if(!(BL_validate_ADDRESS(cfg->whitelist[i])))
			{
				fprintf(stderr,"[-][%s] Invalid Endpoint. Entry %d\n",__func__,i);
				return false;
			}
		}
	}
	else if(cfg->blacklist != NULL)
	{
		for(i=0;i<cfg->num_endpoints;i++)
		{
			if(!(BL_validate_ADDRESS(cfg->blacklist[i])))
			{
				fprintf(stderr,"[-][%s] Invalid Endpoint. Entry %d\n",__func__,i);
				return false;
			}
		}
	}
	return true;
}

bool BL_validate_SSLOPTS(struct configs *cfg)
{
	int i;

	// use_ssl
	if( (strcmp(cfg->use_ssl,"true") != 0) && (strcmp(cfg->use_ssl,"false") != 0))
	{
		fprintf(stderr,"[-][%s] Invalid SSLOPTS entry | cfg->use_ssl. Entry :%s\n",__func__,cfg->use_ssl);
		return false;
	}

	if(cfg->use_ssl)
	{
		// ssl_cert_file
		if(cfg->ssl_opts.ssl_cert_file != NULL)
		{
			FILE *file;
   			if((file = fopen(cfg->ssl_opts.ssl_cert_file,"r")) != NULL)
			{
				fclose(file);
			}
			else
			{
				fprintf(stderr,"[-][%s] Error accessing ssl_cert_file\n",__func__);
				return false;
			}
		}

		//ssl_key_file
		if(cfg->ssl_opts.ssl_key_file != NULL)
		{
			FILE *file;
			if((file = fopen(cfg->ssl_opts.ssl_cert_file,"r")) != NULL)
			{
				fclose(file);
			}
			else
			{
				fprintf(stderr,"[-][%s] Error accessing ssl_key_file\n",__func__);
				return false;
			}
		}

		//ssl_flags
		if(cfg->ssl_opts.sslflagslist != NULL)
		{
			fprintf(stderr,"[%s][%d]\n",__func__,__LINE__);
			for(i=0;i<cfg->ssl_opts.num_flags;i++)
			{
				if(	(strcmp(cfg->ssl_opts.sslflagslist[i],"+sslv3") == 0) )
				{
					cfg->ssl_opts.ssl_flags.sslv3 = true;
				}
				else if( (strcmp(cfg->ssl_opts.sslflagslist[i],"-sslv3") == 0) )
				{	
					cfg->ssl_opts.ssl_flags.sslv3 = false;
				}
				else if( (strcmp(cfg->ssl_opts.sslflagslist[i],"+sslv2") == 0) )
				{
					cfg->ssl_opts.ssl_flags.sslv2 = true;
				}
				else if( (strcmp(cfg->ssl_opts.sslflagslist[i],"-sslv2") == 0) )
				{
					cfg->ssl_opts.ssl_flags.sslv2 = false;
				}
				else if( (strcmp(cfg->ssl_opts.sslflagslist[i], "+compression") == 0) )
				{
					cfg->ssl_opts.ssl_flags.compression = true;
				}
				else if( (strcmp(cfg->ssl_opts.sslflagslist[i], "-compression") == 0) )
				{
					cfg->ssl_opts.ssl_flags.compression = false;
				}
				else
				{
					fprintf(stderr,"[-][%s] Invalid SSL FLAG | %s\n",__func__,cfg->ssl_opts.sslflagslist[i]);
					return false;
				}
			}
		}
	}
	return true;
}

bool BL_validate_AAA(struct configs *cfg)
{
    // use_ssl
    if( (strcmp(cfg->use_aaa,"true") != 0) && (strcmp(cfg->use_aaa,"false") != 0))
	{
		fprintf(stderr,"[-][%s] Invalid USE_AAA entry | cfg->use_aaa Entry :%s\n",__func__,cfg->use_aaa);
		return false;
	}
	return true;
}

bool WL_validate_AUTH_HASH(struct configs *cfg)
{
	if(	(strcmp(cfg->auth_hash,"SHA1") == 0) || (strcmp(cfg->auth_hash,"SHA256") == 0) ||
		(strcmp(cfg->auth_hash,"SHA224") == 0) || (strcmp(cfg->auth_hash,"SHA384") == 0) ||
		(strcmp(cfg->auth_hash,"SHA512") == 0) )
	{
		return true;
	}
	return false;


}

bool BL_validate_CFG(struct configs *cfg)
{
	if(cfg->lhost_port != NULL)
	{
		if(! BL_validate_PORT(cfg->lhost_port))
		{
			return false;
		}
		d_print();
	}
	
	if(cfg->lhost_addr != NULL)
	{
		if(! BL_validate_ADDRESS(cfg->lhost_addr))
		{
			return false;
		}
		d_print();
	}
	
	if(cfg->verbose != NULL)
	{
		if(! WL_validate_VERBOSE(cfg->verbose))
		{
			return false;
		}
		d_print();
	}

	if(cfg->maxclients != NULL)
	{
		if(! WL_validate_MAXCLIENTS(cfg->maxclients))
		{
			return false;
		}
		d_print();
	}

	if(cfg->maxlength != NULL)
	{
		if(! WL_validate_MAXLENGTH(cfg->maxlength))
		{
			return false;
		}
		d_print();
	}

	if(cfg->maxhistory != NULL)
	{
		if(! WL_validate_MAXHISTORY(cfg->maxhistory))
		{
			return false;
		}
		d_print();
	}

	if(cfg->use_ssl != NULL)
	{
		if(! BL_validate_SSLOPTS(cfg))
		{
			return false;
		}
		d_print();
	}

	if((cfg->whitelist != NULL) || (cfg->blacklist != NULL))
	{
		if(! BL_validate_ENDPOINTS(cfg))
		{		
			return false;
		}
		d_print();
	}

	if(cfg->use_aaa != NULL)
	{
		if(! BL_validate_AAA(cfg))
		{
			return false;
		}
		d_print();
	}
	if(cfg->auth_hash != NULL)
	{
		if(! WL_validate_AUTH_HASH(cfg))
		{
			return false;
		}
		d_print();
	}
	return true;
}

void print_loaded(struct configs *cfg)
{
	// to do : all of this
	return;
}
