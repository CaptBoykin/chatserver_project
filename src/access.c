#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>


#include "../includes/access.h"
#include "../includes/config_parser.h"
#include "../includes/misc_funcs.h"
#include "../includes/debug.h"

struct configs;
bool hostVerify(struct configs *cfg, char *host, int fd)
{
	int needed;
	int verbose = atoi(cfg->verbose);
	char *message;
	if(cfg->blacklist != NULL)
	{
		if(BL_checkHost(cfg,host))
		{
			needed = snprintf(NULL,0,"\t\t\t\t \033[41;1m [[[ Your address has been denied ]]] \033[0m \n\n");
			message = calloc(needed+1,sizeof(char));
			snprintf(message,needed,"\t\t\t\t \033[41;1m [[[ Your address has been denied ]]] \033[0m \n\n");
			if(send(fd,message,strlen(message),0) <= 0)
			{
				error("send() error",__LINE__,__func__);
			}
			if(verbose > 1)
			{
				printf("\033[41;1m[<-X] Host: [%s](fd: %d)  denied connection! (BLACKLIST)\033[0m\n",host,fd);
				if(verbose > 2)
				{
					printf("\033[41;1m[<-X] Closing fd %d \033[0m\n",fd);
				}
			}
			close(fd);
			return false;
		}
	}
	else if(cfg->whitelist != NULL)
	{
		if(! WL_checkHost(cfg,host))
		{
			needed = snprintf(NULL,0,"\t\t\t\t \033[41;1m [[[ Your address has been denied ]]] \033[0m \n\n");
			message = calloc(needed+1,sizeof(char));
			snprintf(message,needed,"\t\t\t\t \033[41;1m [[[ Your address has been denied ]]] \033[0m \n\n");
			if(send(fd,message,strlen(message),0) <= 0)
			{
				error("send() error",__LINE__,__func__);
			}
			if(verbose > 1)
			{
				printf("\033[41;1m[<-X] Host: [%s](fd: %d) denied connection! (WHITELIST)\033[0m\n",host,fd);
				if(verbose > 2)
				{
					printf("\033[41;1m[<-X] Closing fd %d \033[0m\n",fd);
				}
			}
			close(fd);
			return false;
		}
		return true;
	}
	return true;
}

bool WL_checkHost(struct configs *cfg, char *host)
{
	int i;
	for(i=0;i<cfg->num_endpoints;i++)
	{
		if( (strcmp(host,cfg->whitelist[i]) == 0))
		{
			return true;
		}
	}
	return false;
}

bool BL_checkHost(struct configs *cfg, char *host)
{
	int i;
	for(i=0;i<cfg->num_endpoints;i++)
	{
		if(	(strcmp(host,cfg->blacklist[i]) == 0))
		{
			return true;
		}
	}
	return false;
}
