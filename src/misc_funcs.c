#include <stdio.h>
#include <stdlib.h>

#include "../includes/misc_funcs.h"

#ifdef DEBUG
# define debug(x) printf x
#else
# define debug(x) do {} while (0)
#endif

void error(char *msg, int line, const char *func)
{
	fprintf(stderr,"[-][Line: %d][Func: %s] - %s\n",line,func,msg);
	exit(-1);
}
