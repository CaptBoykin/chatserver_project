#ifdef _DEBUG
	#define d_print() fprintf(stderr,"*** DEBUG: %s %s %d\n",__FILE__,__func__,__LINE__)
#else
	#define d_print()
#endif
