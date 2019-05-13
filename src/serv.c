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
#include "signal.h"

#include "../includes/config_parser.h"
#include "../includes/msgboard_funcs.h"
#include "../includes/misc_funcs.h"
#include "../includes/serv.h"
#include "../includes/main.h"
#include "../includes/access.h"
#include "../includes/auth.h"
#include "../includes/debug.h"

#define TRUE 1 
#define FALSE 0 


struct configs;
int serv(struct configs *cfg) 
{ 
	struct sockaddr_in server, client;
	char newline_check[2] = {0};			// this is for keeping black [ENTER]s from filling the msgboard
	char newlines[] = "\n";
	char returns[] = "\r";
	char **msgboard = {0};					// msgboard 2D char poitner array
	char buffer[1025];
	char errorstring[] = "** Message too long (128 max). Try again! **\n";
	char *message;							// greeting messsage
	char *LHOST;							// Local host (server) address
	char *RHOST;							// Remote host (client) address
	char *insecure_greet;					// insecure (no ssl) notification
	char *insecure_greet2;
	int opt = TRUE;							// while() loop below
	int master_socket;
	int maxlength = atoi(cfg->maxlength);
	int maxclients = atoi(cfg->maxclients);
	int addrlen;						// len of addr struct
	int new_socket;
	int *client_socket;
	int activity;							
	int i;									// generic iterator
	int valread;							// value amt read
	int sd; 
	int max_sd;
	int buffer_strlen = 0;					// length of buffer msg to to client socket
	int needed = 0;							// used with snprintf() to find exact amt needed for it
	int RPORT;								// Remote (client) source port
	int LPORT;								// local port actually being used
	int errorlen = strlen(errorstring);
	int verbose = atoi(cfg->verbose);
	bool historyfull = false; 				// if 5 lines 	are reached

	// init and zero out client_socket
	client_socket = calloc(maxclients,sizeof(int));

	//initializing msgboard, 
	msgboard = calloc(atoi(cfg->maxhistory),sizeof(char *));

	//set of socket descriptors 
	fd_set readfds; 
		
	//create a master socket 
	if((master_socket = socket(AF_INET,SOCK_STREAM,0)) == 0)
	{
		error("Socket creation failed",__LINE__,__func__);
	}
	if(verbose > 1)
	{
		printf("[+] Socket created!\n");
	}

	//set master socket to allow multiple connections , 
	//this is just a good habit, it will work without this 
	if(setsockopt(master_socket,SOL_SOCKET,SO_REUSEADDR | SO_REUSEPORT,&opt, sizeof(opt)))
	{
            {
            	printf("[-->] %ld bytes sent to [ %s:%d ]\n",strlen(message),RHOST,RPORT);
            }
		error("Setsockopt error",__LINE__,__func__);
	}
	if(verbose > 1)
	{
		printf("[+] Setsockopt sucessful!\n");
	}


	//type of socket created 
	server.sin_family = AF_INET;

	if(cfg->lhost_addr)	// Config file
	{
		server.sin_addr.s_addr = inet_addr(cfg->lhost_addr);
	}
	else	// default to 0.0.0.0 INADDR_ANY
	{
		server.sin_addr.s_addr = INADDR_ANY;
	}
	LPORT = atoi(cfg->lhost_port);
	server.sin_port = htons( atoi(cfg->lhost_port) );
	LHOST = cfg->lhost_addr;	

	//bind the socket to localhost port 8888 
	if(bind(master_socket, (struct sockaddr *)&server, sizeof(server))<0)
	{
		error("Bind() error",__LINE__,__func__);
	}
	if(verbose > 1)
	{
		printf("[+] Bound to address [ %s:%d ]\n",LHOST,LPORT);
	}	

	//try to specify maximum of 3 pending connections for the master socket 
	if(listen(master_socket, 3) < 0)
	{
		error("Listen() error",__LINE__,__func__);
	}
	if(verbose > 0)
	{
		printf("[*] Listening on [ %s:%d ]\n",LHOST,LPORT);
	}	

	// ignore broken pipe
	signal(SIGPIPE,SIG_IGN);

	//accept the incoming connection 
	addrlen = sizeof(client); 
	if(verbose > 0)
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
		activity = select( max_sd + 1 , &readfds , NULL , NULL , NULL); 
		if ((activity < 0) && (errno!=EINTR)) 
		{ 
			error("select() error",__LINE__,__func__); 
		} 
		//If something happened on the master socket , 
		//then its an incoming connection 
		if (FD_ISSET(master_socket, &readfds)) 
		{ 
			if ((new_socket = accept(master_socket,(struct sockaddr *)&client, (socklen_t*)&addrlen))<0) 
			{ 
				error("accept()",__LINE__,__func__); 
			} 

			RHOST = inet_ntoa(client.sin_addr);
			RPORT = ntohs(client.sin_port);

			// before we continue, we see if hostVerification is necessary....	
			if(! hostVerify(cfg,RHOST,new_socket))
			{
				close(new_socket);
				client_socket[i] = 0;
				continue;
			}

			if((strcmp(cfg->use_aaa,"true")) == 0)
			{
				if(! promptUser(cfg,new_socket,RHOST,RPORT,cfg->num_attempts,NULL))
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

			//inform user of socket number - used in send and receive commands 
			if(verbose > 1)
			{
				printf("\033[32;1m[<--] New connection! FD:[%d], IP:[%s], PORT:[%d]\n\033[0m",
						new_socket , inet_ntoa(client.sin_addr) , ntohs (client.sin_port)); 
			}
			needed = snprintf(NULL,0,	"\t\t\t\t\t====[ Welcome to Chat Server ]====\n" \
										"\t\t\t| CONNECTED FROM: %s:%d -> %s:%d |\n\n",
										RHOST,RPORT,LHOST,LPORT);
			message = calloc(needed+1,sizeof(char));
			snprintf(message,needed,	"\t\t\t\t====[ Welcome to Chat Server ]====\n" \
							 			"\t\t\t| CONNECTED FROM: %s:%d -> %s:%d |\n\n",
										RHOST,RPORT,LHOST,LPORT);
								
			// This extra flashy bit tells them that no ssl :(
			needed = snprintf(NULL,0,"\t\t\t\t \033[41;1m \033[30;1m ----[ Connected Insecure ]---- \033[0m \033[0m \n\n\r");
			insecure_greet = calloc(needed+1,sizeof(char));
			snprintf(insecure_greet,needed, "\t\t\t\t \033[41;1m \033[30;1m ----[ Connected Insecure ]---- \033[0m \033[0m \n\n\r");

			
            if(send(new_socket,message,strlen(message),0) <= 0)
            {
            	error("send() error - greeting pt1",__LINE__,__func__);
            }
            if(verbose > 1)
            {
            	printf("[-->] %ld bytes sent to [ %s:%d ]\n",strlen(message),RHOST,RPORT);
            }
            if(send(new_socket,insecure_greet,strlen(insecure_greet),0) <= 0)
            {
            	error("send() error - greeting pt2",__LINE__,__func__);
            }
            if(verbose > 1)
            {
            	printf("[-->] %ld bytes sent to [ %s:%d ]\n",strlen(insecure_greet),RHOST,RPORT);
            }	

			d_print();
			free(insecure_greet);
			free(message);
			d_print();
	

			// "Press [[[ Enter to continue ]]] "
			needed = snprintf(NULL,0,"\t\t\t\t [[[ Press ENTER to continue... ]]] \n\n\r");
			insecure_greet2 = calloc(needed+1,sizeof(char));
			snprintf(insecure_greet2,needed, "\t\t\t\t [[[ Press ENTER to continue... ]]] \n\n\r");

			if(send(new_socket,insecure_greet2,strlen(insecure_greet2),0) <= 0)
			{
				error("send() error - hit enter thingy",__LINE__,__func__);
			}
			if(verbose > 1)
			{
				printf("[-->] %ld bytes sent to [ %s:%d ]\n",strlen(insecure_greet2),RHOST,RPORT);
			}

			// this basically ignores all input except for [ENTER]...continues once [ENTER] is detected
			while(1)
			{
				if((valread = read(new_socket,buffer,1024)) <= 0)
				{
					error("read() error - hit entry thingy",__LINE__,__func__);
				}
				else if((valread = read(new_socket,buffer,1024)) > 0 )
				{
					buffer_strlen = strlen(buffer);
					strncpy(newline_check,buffer,1);
					if(buffer[0] == '\n')
					{
						break;	
					}
				}
				else
				{
					continue;
				}
			}
			

				
			
			// on connect, clear the terminal and set the prompt
			d_print();
			flush_remote(new_socket);
			prompt_remote(new_socket);
			d_print();

			//add new socket to array of sockets 
			for (i = 0; i < maxclients; i++) 
			{ 
				//if position is empty 
				if( client_socket[i] == 0 ) 
				{ 
					client_socket[i] = new_socket; 
					if(verbose > 1)
					{
						printf("[*] Adding to list of sockets as %d\n" , i); 
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
				if ((valread = read( sd , buffer, 1024)) == 0) 
				{ 
					//Somebody disconnected , get his details and print 
					getpeername(sd , (struct sockaddr*)&client ,(socklen_t*)&addrlen); 
					if(verbose > 0)
					{
						printf("[*] Host disconnected , ip %s , port %d \n", RHOST,RPORT);
					}

					//Close the socket and mark as 0 in list for reuse 
					d_print();
					close( sd ); 
					client_socket[i] = 0; 
					d_print();
				} 
				//implicit else... 
				//set the string terminating NULL byte on the end 
				//of the data read in order to get strlen
				d_print(); 
				buffer[valread] = '\0';
				buffer_strlen = strlen(buffer);
				strncpy(newline_check,buffer,1);
				if(verbose > 2)
				{
					printf("[*] %d bytes stored into buffer\n",buffer_strlen);
				}
				d_print();
				
				//preventing standalone carriage returns from cluttering feed
				if(buffer_strlen == 1 && ( (strncmp(newline_check,newlines,1) == 0) || (strncmp(newline_check,returns,1) == 0) ) )
				{
					d_print();
					flush_remote_all(client_socket,maxclients);
					print_msgboard_fd_unsecured(msgboard,client_socket,sd,cfg);
					prompt_remote_all(client_socket,maxclients);
					d_print();
				}
				
				// make sure we don't handle to much user input...
				if(buffer_strlen > maxlength)
				{
					error("Msg too long!",__LINE__,__func__);
					if( send(sd,errorstring,errorlen,0) != errorlen)
					{
						error("send() error",__LINE__,__func__);
					}
					break;
				}

				// print to STDOUT on server end...
				if(verbose > 2)
				{
					printf("[%d][%s:%d] %s",sd, RHOST, RPORT, buffer);
				}
				d_print();
				append_msgboard(msgboard,buffer,sd,inet_ntoa(client.sin_addr),ntohs(client.sin_port),historyfull,cfg);
				flush_remote_all(client_socket,maxclients);
				print_msgboard_unsecured(msgboard,client_socket,cfg);
				prompt_remote_all(client_socket,maxclients);
				d_print();
		    }
		}
	}
	
	return 0; 
} 
