#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <sqlite3.h>

#include "../includes/serv.h"
#include "../includes/ssl_serv.h"
#include "../includes/config_parser.h"
#include "../includes/u_funcs.h"
#include "../includes/auth.h"
#include "../includes/misc_funcs.h"

#ifdef DEBUG
# define debug(x) printf x
#else
# define debug(x) do {} while (0)
#endif

#define TEST "db/test.db"

int main(int argc, char *argv[])
{
	struct configs *conf; // = malloc(sizeof(struct configs));
	conf = config_parse(argv[1]);

	u_add(conf,TEST,"test","test1234",3);
	u_add(conf,TEST,"test2","AAAAA",3);

	if( (strcmp(conf->use_ssl,"true")) == 0)
	{
		printf("[*] SSL Server Selected\n");
		ssl_serv(conf);
	}
	else
	{
		printf("[*] Unsecured Server Selected\n");
		serv(conf);
	}

	return 0;
}
