#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>

#include "../includes/msgboard_funcs.h"
#include "../includes/ssl_serv.h"
#include "../includes/misc_funcs.h"
#include "../includes/config_parser.h"
#include "../includes/debug.h"

#define TRUE 1 
#define FALSE 0 

struct ssl_client_list;
struct configs;


void flush_remote(int fd)
{
	const char flush[] = "\x1b[2J\n";
	if( (send(fd,flush,strlen(flush),0) <= 0))
	{
		error("send() error - flush_remote()",__LINE__,__func__);
	}
	return;
}

void flush_remote_SSL(SSL *ssl_fd)
{

	return;
}

void prompt_remote(int fd)
{
	const char prompt[] = "\x1b[1;1H#> ";
	if( (send(fd,prompt,strlen(prompt),0) <= 0))
	{
		error("send() error = prompt_remote()",__LINE__,__func__);
	}
	return;
}


void prompt_remote_SSL(SSL *ssl_fd)
{

	return;
}

void flush_remote_all(int *client_sockets,int maxclients)
{
	int i;
	for(i=0;i<maxclients;i++)
	{
		if(client_sockets[i] != 0)
		{
			flush_remote(client_sockets[i]);
		}
	}
	return;
}

void prompt_remote_all(int *client_sockets,int maxclients)
{
	int i;
	for(i=0;i<maxclients;i++)
	{
		if(client_sockets[i] != 0)
		{
			prompt_remote(client_sockets[i]);
		}
	}
	return;
}

void flush_remote_all_SSL(struct ssl_clients_list *ssl_clients)
{
	return;
}

void prompt_remote_all_SSL(struct ssl_clients_list *ssl_clients)
{
	return;
}

void append_msgboard(char **msgboard, char *entry, int fd, char *addr, int port, bool full, struct configs *cfg)
{
		int i;
		int needed;
		int msglen;
		int maxhistory = atoi(cfg->maxhistory);
		int maxlength = atoi(cfg->maxlength);
		char *msg;

		// filling the formatted string buffer
		d_print();
		needed = snprintf(NULL,0,"[%d][%s:%d] %s\n",fd,addr,port,entry);
		msg = calloc(needed+1,sizeof(char));
		snprintf(msg,needed,"[%d][%s:%d] %s\n",fd,addr,port,entry);
		d_print();

		msglen = strlen(msg);
		// filling up the message history window (5)...
		if(!full)
		{
			for(i=0;i<maxhistory;i++)
			{
				if(msgboard[i] == 0)
				{
					d_print();
					msgboard[i] = calloc(maxlength+1,sizeof(char));
					memcpy(msgboard[i],msg,msglen);
					d_print();
					return;
				}
			}
		}
		// shifting the message history...
        for(i=0;i<maxhistory-1;i++)
		{
			d_print();
			memcpy(msgboard[i],msgboard[i+1],maxlength);
		}
		// inserting most recent at the 'bottom'.
		d_print();
		memset(msgboard[maxhistory-1],'\0',maxlength);
		memcpy(msgboard[maxhistory-1],msg,msglen+1);
		free(msg);
		d_print();

		return;
}


void print_msgboard_unsecured(char **msgboard, int *client_socket, struct configs *cfg)
{
	int i;
	int ii;
	int maxclients = atoi(cfg->maxclients);
	int maxhistory = atoi(cfg->maxhistory);	
	for(i=0;i<maxclients;i++)
	{
		// iterate over message history 'lines'
		for(ii=0;ii<maxhistory;ii++)
		{
			// both the client socket and msghistory line must have stuff
			if(client_socket[i] != 0 && msgboard[ii] != 0)
			{
				//print message history
				if( send(client_socket[i],msgboard[ii],strlen(msgboard[ii]), 0) != strlen(msgboard[ii]) )
				{
					error("send() error",__LINE__,__func__);
				}
				d_print();
			}
		}
	}
	return;
}

// msgboard : the 2d array of messages
// client_socket : 1d int array of fd()'s ... cross referenced by find_obj()
// ssl_clients : linked list of sd(fd) to SSL object mappings
void print_msgboard_SSL(char **msgboard, int *client_socket, struct ssl_client_list *ssl_clients, struct configs *cfg)
{
	SSL *ssl_fd;
	int i;
	int ii;
	int maxclients = atoi(cfg->maxclients);
	int maxhistory = atoi(cfg->maxhistory);
	for(i=0;i<maxclients;i++)
	{
		for(ii=0;ii<maxhistory;ii++)
		{
			if(client_socket[i] != 0 && msgboard[ii] != 0)
			{
				ssl_fd = find_SSL_obj(ssl_clients,client_socket[i]);
				if( SSL_write(ssl_fd,msgboard[ii],strlen(msgboard[ii])) != strlen(msgboard[ii]))
				{
					error("SSL_write() error",__LINE__,__func__);
				}
				d_print();
			}
		}
	}
	return;
}

void print_msgboard_fd_unsecured(char **msgboard, int *client_sockets, int fd, struct configs *cfg)
{
	int i;
	int ii;
	int maxclients = atoi(cfg->maxclients);
	int maxhistory = atoi(cfg->maxhistory);
	for(i=0; i<maxclients; i++)
	{
		for(ii=0; ii<maxhistory; ii++)
		{
			if( (client_sockets[i] != 0 && msgboard[ii] != 0) && client_sockets[i] == fd)
			{
				if( send(client_sockets[i],msgboard[ii],strlen(msgboard[ii]), 0) != strlen(msgboard[i]) )
				{
					error("send() error",__LINE__,__func__);
				}
				d_print();		
			}
		}
	}
	return;
}

void print_msgboard_fd_SSL(char **msgboard, int *client_sockets, struct ssl_client_list *ssl_clients, int fd, struct configs *cfg)
{
	SSL *ssl_fd;
	int i;
	int ii;
	int maxclients = atoi(cfg->maxclients);
	int maxhistory = atoi(cfg->maxhistory);
	for(i=0; i<maxclients; i++)
	{
		for(ii=0;ii<maxhistory; ii++)
		{
			if( (client_sockets[i] != 0 && msgboard[ii] != 0) && client_sockets[i] == fd)
			{
				ssl_fd = find_SSL_obj(ssl_clients,client_sockets[i]);
				if( SSL_write(ssl_fd,msgboard[ii],strlen(msgboard[ii])) != strlen(msgboard[ii]))
				{
					error("SSL_write() error",__LINE__,__func__);
				}
				d_print();
			}
		}
	}
	return;
}	
