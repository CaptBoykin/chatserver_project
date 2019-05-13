#ifndef __ACCESS
#define __ACCESS

struct configs;
bool hostVerify(struct configs *cfg, char *host, int fd);
bool WL_checkHost(struct configs *cfg, char *host);
bool BL_checkHost(struct configs *cfg, char *host);

#endif
