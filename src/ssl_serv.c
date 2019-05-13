#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <stdbool.h>
#include <unistd.h>
#include <ctype.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <string.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

#include "../includes/config_parser.h"
#include "../includes/misc_funcs.h"
#include "../includes/msgboard_funcs.h"
#include "../includes/ssl_serv.h"
#include "../includes/main.h"
#include "../includes/access.h"
#include "../includes/debug.h"

#define TRUE 1 
#define FALSE 0 



struct configs;
void delete_SSL_client(struct ssl_client_list **list, int sd);
void append_SSL_client(struct ssl_client_list **list, SSL *obj, int sd);
SSL *find_SSL_obj(struct ssl_client_list *list, int sd);
void InitializeSSL();
void DestroySSL();
void ShutdownSSL(SSL *sslctx);
SSL_CTX *create_context();
void configure_context(SSL_CTX *ctx, struct configs *cfg);


int ssl_serv(struct configs *cfg) 
{
    struct ssl_client_list *ssl_clients = NULL;
	struct sockaddr_in server, client;
	char newline_check[2] = {0};			// this is for keeping black [ENTER]s from filling the msgboard
	char newlines[] = "\n";
	char returns[] = "\r";
	char **msgboard = {0};					// msgboard 2D char poitner array
	char buffer[1025];
	char errorstring[] = "** Message too long (256 max). Try again! **\n";
	char *message;							// greeting message
	char *greet_ssl;						// greeting message notifying user of secure connection
	char *LHOST;							// Local host (server) address
	char *RHOST;							// Remote host (client) address
	int opt = TRUE;							// while() loop below
	int	master_socket;		
	int addrlen;						// len of addr struct
	int new_socket;
	int activity;							
	int i;									// generic iterator
	int valread;							// value amt read
	int sd; 
	int max_sd;
	int *client_socket;	// array storing currently connected clients
	int buffer_strlen = 0;					// length of buffer msg to to client socket
	int needed = 0;							// used with snprintf() to find exact amt needed for it
	int LPORT;
	int RPORT;								// Remote (client) source port
	int maxlength = atoi(cfg->maxlength);
	int maxhistory = atoi(cfg->maxhistory);
	int maxclients = atoi(cfg->maxclients);
	int errorlen = strlen(errorstring);
	int verbose = atoi(cfg->verbose);
	bool historyfull = false; // if 5 lines are reached
	SSL_CTX *sslctx;
	SSL *ssl_fd;

	// init and zero client_socket
	client_socket = calloc(maxclients,sizeof(int));

	// zero out client_socket
	memset(client_socket,0,atoi(cfg->maxclients));

	// initialize SSL stuff
	InitializeSSL();
	sslctx = create_context();
	if(verbose > 2)
	{
		printf("[*] SSL Cert file: %s\n",cfg->ssl_opts.ssl_cert_file);
		printf("[*] SSL Key  file: %s\n",cfg->ssl_opts.ssl_key_file);
	}
	configure_context(sslctx,cfg);

	//initializing msgboard
	msgboard = calloc(maxhistory,sizeof(char *));

	//set of socket descriptors 

	fd_set readfds;

	//create a master socket 
	if( (master_socket = socket(AF_INET , SOCK_STREAM , 0)) == 0) 
	{ 
		error("socket() failed",__LINE__,__func__); 
		exit(EXIT_FAILURE); 
	} 
	
	//set master socket to allow multiple connections , 
	//this is just a good habit, it will work without this 
	if(setsockopt(master_socket,SOL_SOCKET,SO_REUSEADDR | SO_REUSEPORT,&opt, sizeof(opt)))
	{
		error("Setsockopt error",__LINE__,__func__);
	}
	if(verbose > 1)
	{
		printf("[+] Setsockopt sucessful!\n");
	}

	//type of socket created 
	server.sin_family = AF_INET; 
    if(cfg->lhost_addr)
    {
    	server.sin_addr.s_addr = inet_addr(cfg->lhost_addr);
    }
    else    // default to 0.0.0.0 INADDR_ANY
    {
        server.sin_addr.s_addr = INADDR_ANY;
    }
    server.sin_port = htons( atoi(cfg->lhost_port) );
	LPORT = atoi(cfg->lhost_port);
    
	LHOST = inet_ntoa(server.sin_addr);	

	//bind the socket to localhost port 8888 
	if(bind(master_socket, (struct sockaddr *)&server, sizeof(server))<0)
	{
		error("bind error",__LINE__,__func__);
	}
	if(verbose > 1)
	{
		printf("[+] Bound to address [ %s:%d ]\n",LHOST,LPORT);
	}	

	//try to specify maximum of 3 pending connections for the master socket 
	if(listen(master_socket, 3) < 0)
	{
		error("Listen error",__LINE__,__func__);
	}
	if(verbose > 0)
	{
		printf("[+] Listening on [ %s:%d ]\n",LHOST,LPORT);
	}

	//accept the incoming connection 
	addrlen = sizeof(client);
	if(verbose > 1)
	{
		printf("[*] Waiting for connections ...\n"); 
	}
	while(TRUE) 
	{

		//clear the socket set 
		FD_ZERO(&readfds); 

		//add master socket to set 
		FD_SET(master_socket, &readfds); 
		max_sd = master_socket; 
			
		//add child sockets to set 
		for ( i = 0 ; i < maxclients ; i++) 
		{ 
			//socket descriptor 
			sd = client_socket[i]; 

			//if valid socket descriptor then add to read list 
			if(sd > 0)
			{ 
				FD_SET( sd , &readfds); 
			}
	
			//highest file descriptor number, need it for the select function 
			if(sd > max_sd)
			{
				max_sd = sd;
			}	
		} 
	
		//wait for an activity on one of the sockets , timeout is NULL , 

		//so wait indefinitely 
		activity = select(max_sd + 1 , &readfds , NULL , NULL , NULL); 
	
		if ((activity < 0) && (errno!=EINTR)) 
		{ 
			error("select error()",__LINE__,__func__);
		} 
			
		//If something happened on the master socket , 
		//then its an incoming connection 
		if (FD_ISSET(master_socket, &readfds)) 
		{ 
			if ((new_socket = accept(master_socket,(struct sockaddr *)&client, (socklen_t*)&addrlen))<0) 
			{ 
				error("accept error",__LINE__,__func__); 
				exit(EXIT_FAILURE); 
			} 
			
			RHOST = inet_ntoa(client.sin_addr);
			RPORT = ntohs(client.sin_port);

             // before we continue, we see if hostVerification is necessary....
             if(! hostVerify(cfg,RHOST,new_socket))
             {
			 	close(sd);
				client_socket[i] = 0;
				continue;
             }

			// this creates SSL structure when it's time...
			if(!(ssl_fd = SSL_new(sslctx)))
			{
				error("Error creating SSL structure failed!",__LINE__,__func__);
			}
			if(verbose > 2)
			{
				printf("[+] SSL structure created!\n");
			}

			// After the connection is establish + structure is made... make hte socket fd
			// into an SSL one...
			if(SSL_set_fd(ssl_fd,new_socket) != 1)
			{
				error("Error setting fd as TLS/SSL fd",__LINE__,__func__);
			}
			if(verbose > 2)
			{
				printf("[+] TLS/SSL fd set!\n");
			}

			// now accept on the ssl socket fd
			if(SSL_accept(ssl_fd) <= 0)
			{
				ERR_print_errors_fp(stderr);
				error("Connection was attempted witouth SSL",__LINE__,__func__);
			}
			if(verbose > 1)
			{
				printf("[<-] Accepted TLS/SSL connection from [ %s:%d ]\n",RHOST,RPORT);
			}

			if(cfg->use_aaa)
			{
				if(! promptUser(cfg,NULL,RHOST,RPORT,cfg->num_attempts,ssl_fd))
				{
					fprintf(stderr,"\033[31;1m[<-x] Excess failed attempts. Kicking [%s:%d]\033[0m\n",RHOST,RPORT);
					close(new_socket);
					continue;
				}
				else
				{
					if(verbose > 1)
					{
						printf("\033[32;1m[<--] Authentication successful from [%s:%d]\033[0m\n",RHOST,RPORT);
					}
				}
			}


			//inform server of socket number - used in send and receive commands 
			if(verbose > 0)
			{
					printf("[+] New connection , socket fd is %d , ip is : %s , port : %d \n" ,
					new_socket , inet_ntoa(client.sin_addr) , ntohs 
					(client.sin_port)); 
			}
			// big flashy welcome banner to the client ...,
			needed = snprintf(NULL,0,	"\t\t\t\t====[ Welcome to Chat Server ]====\n" \
										"\t\t\t| CONNECTED FROM: %s:%d -> %s:%d |\n\n",
										RHOST,RPORT,LHOST,LPORT);
			message = calloc(needed+1,sizeof(char));
			snprintf(message,needed,	"\t\t\t\t====[ Welcome to Chat Server ]====\n" \
							 			"\t\t\t| CONNECTED FROM: %s:%d -> %s:%d |\n\n",
										RHOST,RPORT,LHOST,LPORT);
						   				

			// This extra flashy bit tells them that it's over SSL :)
			needed = snprintf(NULL,0,"\t\t\t\t\033[42;1m \033[30;1m ----[ Connected Secure ]---- \033[0m \033[0m \n\n\r");

			greet_ssl = calloc(needed+1,sizeof(char));
			snprintf(greet_ssl,needed, "\t\t\t\t\033[42;1m \033[30;1m ----[ Connected Secure ]---- \033[0m \033[0m \n\n\r");

			// SSL_write is the SSL equiv to send()
			if(SSL_write(ssl_fd,message,strlen(message)) <= 0)
			{
				error("Error sending greeting in SSL",__LINE__,__func__);
			}
			if(verbose > 1)
			{
				printf("[->] %ld bytes sent to [ %s:%d ]\n",strlen(message),RHOST,RPORT);
			}
			if(SSL_write(ssl_fd,greet_ssl,strlen(greet_ssl)) <= 0)
			{
				error("Error sending greeting in SSL",__LINE__,__func__);
			}
			if(verbose > 1)
			{
				printf("[->] %ld bytes sent to [ %s:%d ]\n",strlen(greet_ssl),RHOST,RPORT);
			}
			

			//add new socket to array of sockets 
			for (i = 0; i < maxclients; i++) 
			{ 
				//if position is empty 
				if( client_socket[i] == 0 ) 
				{ 
					// instead of this below, we use ssl_fd
					client_socket[i] = SSL_get_fd(ssl_fd);
					if(verbose > 2)
					{
						printf("[*] Adding to list of sockets as [%d]: %d\n",i,SSL_get_fd(ssl_fd)); 
					}

					// storing ssl_obj : ssl_fd mapping
					append_SSL_client(&ssl_clients,ssl_fd,SSL_get_fd(ssl_fd));	
					if(verbose > 2)
					{
						printf("[*] Adding to LL of SSL_obj -> SSL_fd mappings\n");
					}
					break; 
				} 
			} 
		}
		//else its some IO operation on some other socket 
		for (i = 0; i < maxclients; i++) 
		{ 
			sd = client_socket[i];
			if (FD_ISSET( sd , &readfds)) 
			{
	
				//Check if it was for closing , and also read the 
				//incoming message 

				//**FIRST**.. fetch the SSL obj
				ssl_fd = find_SSL_obj(ssl_clients,sd);	

				if ((valread = SSL_read( ssl_fd , buffer, 1024)) == 0) 
				{
					//Somebody disconnected , get his details and print 
					getpeername(sd , (struct sockaddr*)&client ,(socklen_t*)&addrlen);
				   	if(verbose > 1)
					{	
						printf("[*] Host disconnected , ip %s , port %d \n", RHOST,RPORT);
					}

					//Close the socket and mark as 0 in list for reuse 
					d_print();
					close( sd ); 
					client_socket[i] = 0; 
				 	d_print();
				}
				//Echo back the message that came in 
				else
				{ 
					//set the string terminating NULL byte on the end 
					//of the data read in order to get strlen 
					d_print();
					buffer[valread] = '\0';
					buffer_strlen = strlen(buffer);
					strncpy(newline_check,buffer,1);
					d_print();

					//preventing standalone carriage returns from cluttering feed
					if(buffer_strlen == 1 && ( (strncmp(newline_check,newlines,1) == 0) || (strncmp(newline_check,returns,1) == 0) ) )
					{
						//void print_msgboard_fd_secure(char **msgboard, int *client_sockets, struct ssl_client_list *ssl_clients, int fd);
						print_msgboard_fd_SSL(msgboard,client_socket,ssl_clients,sd,cfg);
						continue;
					}

					// make sure we don't handle to much user input...
					if(buffer_strlen > maxlength)
					{
						if( SSL_write(ssl_fd,errorstring,errorlen) != errorlen)
						{
							error("error SSL_write()",__LINE__,__func__);
						}
						break;
					}

					// print to STDOUT on server end...
					if(verbose > 0)
					{
						printf("[%d][%s:%d] %s",sd, RHOST, RPORT, buffer);
					}

					d_print();
					append_msgboard(msgboard,buffer,sd,inet_ntoa(client.sin_addr),ntohs(client.sin_port),historyfull,cfg);
					print_msgboard_SSL(msgboard,client_socket,ssl_clients,cfg);
					d_print();
				} 
			}
		}
	}
	// Deletes the disconnected clients from the ssl_clients linkedlist
	d_print();
	delete_SSL_client(&ssl_clients,SSL_get_fd(ssl_fd));
	SSL_free(ssl_fd);
	close(master_socket);
	d_print();

	return 0; 
}

// Purpose:  Keep ssl_client list from overflowing with entries
void delete_SSL_client(struct ssl_client_list **list, int sd)
{
	struct ssl_client_list *temp = *list, *prev;

	if(temp != NULL && temp->sd == sd)
	{
		*list = temp->next;
		free(temp);
		return;
	}

	while(temp != NULL && temp->sd != sd)
	{
		prev = temp;
		temp = temp->next;
	}

	if(temp == NULL)
	{
		return;
	}
	prev->next = temp->next;
	free(temp);
}

// Purpose:  Appends the ssl_client list with fd() : ssl object mappings
void append_SSL_client(struct ssl_client_list **list, SSL *obj, int sd)
{
	struct ssl_client_list *new = malloc(sizeof(struct ssl_client_list));
	struct ssl_client_list *last = *list;

	new->sd = sd;
	new->ssl_obj = obj;
	new->next = NULL;

	if(*list == NULL)
	{
		*list = new;
		return;
	}

	while(last->next != NULL)
	{
		last = last->next;
	}

	last->next = new;
	return;
}

SSL *find_SSL_obj(struct ssl_client_list *list, int sd)
{
	struct ssl_client_list *current = list;
	while(current != NULL)
	{
		if(sd == current->sd)
		{
			return current->ssl_obj;
		}
		current = current->next;
	}
	exit(EXIT_FAILURE);
}

// Singly linked list for mapping SSL fd to SSL objects and
// being able to references those
void InitializeSSL()
{
	SSL_load_error_strings();
	SSL_library_init();
	OpenSSL_add_all_algorithms();
}

void DestroySSL()
{
	ERR_free_strings();
	EVP_cleanup();
}

void ShutdownSSL(SSL *sslctx)
{
	if(SSL_shutdown(sslctx) < 0)
	{
		error("Error shutting down SSL connection!",__LINE__,__func__);
	}
	SSL_free(sslctx);
}



SSL_CTX *create_context()
{
	const SSL_METHOD *method;
	SSL_CTX *ctx;

	method = SSLv23_server_method();

	ctx = SSL_CTX_new(method);
	if (!ctx)
	{
		error("Unable to create SSL context",__LINE__,__func__);
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}
	return ctx;
}

void configure_context(SSL_CTX *ctx, struct configs *cfg)
{
	SSL_CTX_set_ecdh_auto(ctx, 1);

	/* Set the key and cert */
	if (SSL_CTX_use_certificate_file(ctx,cfg->ssl_opts.ssl_cert_file, SSL_FILETYPE_PEM) <= 0)
	{
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}

	if (SSL_CTX_use_PrivateKey_file(ctx,cfg->ssl_opts.ssl_key_file, SSL_FILETYPE_PEM) <= 0 )

	{
	ERR_print_errors_fp(stderr);
	exit(EXIT_FAILURE);
	}
}

