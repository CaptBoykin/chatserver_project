#ifndef __U_FUNCS
#define __U_FUNCS


struct configs;
int u_add(struct configs *cfg, char *filename, char *username, char *pwd, int verbose);
int u_delete(struct configs *cfg, char *filename, char *username, int verbose);
int u_passwd(struct configs *cfg, char *filename, char *username, char *mods, int verbose);
bool u_query(struct configs *cfg, char *filename, char *username, char *pwd, int verbose);
#endif
