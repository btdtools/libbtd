#ifndef LIBBTD_H
#define LIBBTD_H

#include <netdb.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdbool.h>

//Connection
struct addrinfo *btd_get_addrinfo(char *address);
void btd_free_addrinfo(struct addrinfo *ai);
char *pprint_address(struct addrinfo *ai);

//Paths
char *btd_get_config_path();
char *btd_get_data_path();

//Misc
void perrordie(char *prg);
void die(char *msg, ...);
void *safe_realloc(void *p, unsigned long int s);
void *safe_calloc(unsigned long int nm, unsigned long int s);
void *safe_malloc(unsigned long int s);
void safe_free(int count, ...);
FILE *safe_fopen(char *p, char *mode);
void safe_fclose(FILE *f);
char *safe_strcat(int count, ...);
char *safe_strdup(const char *s);
void safe_fputs(FILE *f, char *m);
void safe_fprintf(FILE *f, char *m, ...);
bool path_exists(const char *path);
char *resolve_tilde(const char *path);

//Logging
int get_btd_log_level();
void btd_init_log();
void btd_log(int lvl, char *msg, ...);
void btd_decr_log();
void btd_incr_log();

#endif
