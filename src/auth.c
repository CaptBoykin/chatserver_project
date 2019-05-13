#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <sqlite3.h>
#include <unistd.h>
#include <ctype.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

#include "../includes/auth.h"
#include "../includes/u_funcs.h"
#include "../includes/misc_funcs.h"
#include "../includes/config_parser.h"
#include "../includes/debug.h"

#define TEST "db/test.db"

struct configs;

// this returns true if the query returns true (thus indicating if the entry exists in the DB
bool authUser_sqlite(struct configs *cfg, int fd, char *userprompt_reply, char *passprompt_reply)
{
	if(u_query(cfg,TEST,userprompt_reply,passprompt_reply,atoi(cfg->verbose)))
	{
		return true;
	}
	return false;
}

// TO DO: something with this
bool authUser_configs(struct configs *cfg, int fd, char *userprompt_reply, char *passprompt_reply)
{
	return true;
}

void free_all(char *banner, char *userprompt, char *passprompt, char *rejected)
{
	free(banner);
	free(userprompt);
	free(passprompt);
	free(rejected);
	return;
}

bool promptUser(struct configs *cfg, int fd, char *RHOST, int RPORT, int num_attempts, SSL *ssl_obj)
{
	
	int verbose = atoi(cfg->verbose);
	int needed;
	char *banner;
	char *userprompt;
	char *passprompt;
	int valread = 0;
	int ctr;
	int i;
	int ii = 0;
	char *rejected;
	char userprompt_reply[1024] = {0};
	char passprompt_reply[1024] = {0};
	int userprompt_reply_len = 0;
	int passprompt_reply_len = 0;

	needed = snprintf(NULL,0,"+===============================+\n"\
							 "| Authentication requred!       |\n"\
							 "+===============================+\n\n");
    banner = calloc(needed+1,sizeof(char));
    snprintf(banner,needed, "+==============================+\n"\
							"| Authentication requred!      |\n"\
							"+==============================+\n\n");

	needed = snprintf(NULL,0,"USERNAME: ");
	userprompt = calloc(needed+1,sizeof(char));
	snprintf(userprompt,needed,"USERNAME: ");

	needed = snprintf(NULL,0,"PASSWORD: ");
	passprompt = calloc(needed+1,sizeof(char));
	snprintf(passprompt,needed,"PASSWORD: ");
	
    needed = snprintf(NULL,0,"\033[31;1m Invalid Username or Password!\033[0m\n\n");
    rejected = calloc(needed+1,sizeof(char));
    snprintf(rejected,needed,"\033[31;1m Invalid Username of Password!\033[0m\n\n");

	if(	(fd != NULL) && (ssl_obj == NULL))
	{
        if(send(fd,banner,strlen(banner),0) <= 0)
        {
			error("send() error - auth pt1",__LINE__,__func__);
        }
        if(verbose > 1)
        {
			printf("[-->] %ld bytes sent to [ %s:%d ]\n",strlen(banner),RHOST,RPORT);
        }

		while(ii < num_attempts)
		{
			// username prompt
			if(send(fd,userprompt,strlen(userprompt),0) <= 0)
			{
				error("send() error - auth pt2",__LINE__,__func__);
			}
			if(verbose > 1)
			{
				printf("[-->] %ld bytes sent to [ %s:%d ]\n",strlen(userprompt),RHOST,RPORT);
			}
			if((valread = read(fd,userprompt_reply,1024)) != 0)
			{	
				userprompt_reply_len = strlen(userprompt_reply);
			}

			// password prompt
			if(send(fd,passprompt,strlen(passprompt),0) <= 0)
			{
				error("send() error - auth pt3",__LINE__,__func__);
			}
			if(verbose > 1)
			{
				printf("[-->] %ld bytes sent to [ %s:%d ]\n",strlen(passprompt),RHOST,RPORT);
			}
			if((valread = read(fd,passprompt_reply,1024)) != 0)
			{
				passprompt_reply_len = strlen(passprompt_reply);
			}


			//normalize the input and NULL terminate
			for(i=0;i<strlen(userprompt_reply);i++)
			{
				if( (userprompt_reply[i] == '\n') || (userprompt_reply[i] == '\r'))
				{
					userprompt_reply[i] = '\0';
				}
			}
			for(i=0;i<strlen(passprompt_reply);i++)
			{
				if( (passprompt_reply[i] == '\n') || (passprompt_reply[i] == '\r'))
				{
					passprompt_reply[i] = '\0';
				}
			}
	
			if(authUser_sqlite(cfg,fd,userprompt_reply,passprompt_reply))
			{
				if(verbose > 1)
				{
					printf("\033[32;1m[<--] Access granted for %s@%s:%d\033[0m\n",userprompt_reply,RHOST,RPORT);
				}
				free_all(banner,userprompt,passprompt,rejected);
				return true;
			}

			if(verbose > 1)
			{
				fprintf(stderr,"\033[31;1m[<-x] Access denied for %s@%s:%d\033[0m\n",userprompt_reply,RHOST,RPORT);
			}
			if(send(fd,rejected,strlen(rejected),0) <= 0)
			{
				error("send() error - rejected",__LINE__,__func__);
			}
			if(verbose > 1)
			{
				printf("[-->] %ld bytes sent to [ %s:%d ]\n",strlen(rejected),RHOST,RPORT);
			}
			ii++;	// incrementing... loop ends when ii >= num_attempts
		}
		free_all(banner,userprompt,passprompt,rejected);
		return false;
	}
	else if((fd == NULL) && (ssl_obj != NULL))
	{
        if(SSL_write(ssl_obj,banner,strlen(banner)) <= 0)
        {
			error("SSL_write() error - auth pt1",__LINE__,__func__);
        }
        if(verbose > 1)
        {
			printf("[-->] %ld bytes sent to [ %s:%d ]\n",strlen(banner),RHOST,RPORT);
        }
		while(ii < num_attempts)
		{
			// username prompt
			if(SSL_write(ssl_obj,userprompt,strlen(userprompt)) <= 0)
			{
				error("SSL_write() error - auth pt2",__LINE__,__func__);
			}
			if(verbose > 1)
			{
				printf("[-->] %ld bytes sent to [ %s:%d ]\n",strlen(userprompt),RHOST,RPORT);
			}
			if((valread = SSL_read(ssl_obj,userprompt_reply,1024)) != 0)
			{
				userprompt_reply_len = strlen(userprompt_reply);
			}

			// password prompt
			if(SSL_write(ssl_obj,passprompt,strlen(passprompt)) <= 0)
			{
				error("SSL_write() error - auth pt3",__LINE__,__func__);
			}
			if(verbose > 1)
			{
				printf("[-->] %ld bytes sent to [ %s:%d ]\n",strlen(passprompt),RHOST,RPORT);
			}
			if((valread = SSL_read(ssl_obj,passprompt_reply,1024)) != 0)
			{
				passprompt_reply_len = strlen(passprompt_reply);
			}


			//normalize the input and NULL terminate
			for(i=0;i<strlen(userprompt_reply);i++)
			{
				if( (userprompt_reply[i] == '\n') || (userprompt_reply[i] == '\r'))
				{
					userprompt_reply[i] = '\0';
				}
			}
			for(i=0;i<strlen(passprompt_reply);i++)
			{
				if( (passprompt_reply[i] == '\n') || (passprompt_reply[i] == '\r'))
				{
					passprompt_reply[i] = '\0';
				}
			}

			if(authUser_sqlite(cfg,ssl_obj,userprompt_reply,passprompt_reply))
			{
				if(verbose > 1)
				{
					printf("\033[32;1m[<--] Access granted for %s@%s:%d\033[0m\n",userprompt_reply,RHOST,RPORT);
				}
				free_all(banner,userprompt,passprompt,rejected);
				return true;
			}
			if(verbose > 1)
			{
				fprintf(stderr,"\033[31;1m[<-x] Access denied for %s@%s:%d\033[0m\n",userprompt_reply,RHOST,RPORT);
			}
			if(SSL_write(ssl_obj,rejected,strlen(rejected)) <= 0)
			{
				error("SSL_write() error - rejected",__LINE__,__func__);
			}
			if(verbose > 1)
			{
				printf("[-->] %ld bytes sent to [ %s:%d ]\n",strlen(rejected),RHOST,RPORT);
			}
			ii++;   // incrementing... loop ends when ii >= num_attempts
		}
		free_all(banner,userprompt,passprompt,rejected);
		return false;
	}
	free_all(banner,userprompt,passprompt,rejected);
	return true;
}
