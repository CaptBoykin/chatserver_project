#include <stdio.h>
#include <string.h>
#include <sqlite3.h>
#include <stdbool.h>
#include <stdlib.h>

#include "../includes/u_funcs.h"
#include "../includes/misc_funcs.h"
#include "../includes/config_parser.h"
#include "../includes/debug.h"
#include "../includes/u_crypto.h"

#define DEMO "db/test.db"

/*
 * create table
 * add user
 * del user
 * modify user
 * db_encrypt
 * db_decrypt
 * db_open
 * - check if table exists
 *   if not
 *   	create table and return db handle
 *   if so
 *   	open table and return db handle
 *
 */

struct configs;

// Callbacks tailored for conditionals and other purposes...these all take the same args but return differently.

// returns 0 unconditionally, good for no manipulation of results is needed
static int generic_callback(void *NotUsed, int columnCount, char **row_fields, char **column_names)
{
	return 0;
}

static int countType_callback_inverse(void *NotUsed, int columnCount, char **row_fields, char **column_names)
{
	int num = atoi(row_fields[0]);
	if(num > 0)
	{
		return 0;
	}
	return 1;
}

// returns the results from COUNT(TYPE)... query below
static int countType_callback(void *NotUsed, int columnCount, char **row_fields, char **column_names)
{
	int num = atoi(row_fields[0]);
	if(num > 0)
	{
		return 1;
	}
	return 0;
}

sqlite3 *db_open(char *file, int verbose)
{
	sqlite3 *db;

	d_print();
	if( (sqlite3_open(file,&db)) != SQLITE_OK)
	{	
		error("Error opening db file",__LINE__,__func__);
		sqlite3_close(db);
		exit(EXIT_FAILURE);
	}
	if(verbose > 1)
	{
		d_print();
		printf("[+] DB file opened successfully!\n");
	}
	return(db);

}

sqlite3 *table_create(sqlite3 *db, int verbose)
{
	char *query;
	char *zErrMsg = 0;
	query = sqlite3_mprintf(	"CREATE TABLE USERS("\
								"ID INTEGER PRIMARY KEY AUTOINCREMENT,"\
								"USERNAME TEXT NOT NULL UNIQUE,"\
								"PASSWORD TEXT NOT NULL);");
	if( (sqlite3_exec(db,query,generic_callback,0,&zErrMsg)) != 0)
	{
		error(zErrMsg,__LINE__,__func__);
	}
	if(verbose > 1)
	{
		printf("[+] Table USERS created!\n");
	}
	return(db);
}

int u_add(struct configs *cfg, char *filename, char *username, char *pwd, int verbose)
{

	char *query;
	char *zErrMsg = 0;
	unsigned char *md;
	sqlite3 *db;
	
	d_print();
	db = db_open(filename,verbose);
	
	// First seeing if table 'USERS' exists...
    query = sqlite3_mprintf("SELECT COUNT(TYPE) FROM sqlite_master WHERE TYPE='table' AND NAME='USERS';");
    if( (sqlite3_exec(db,query,countType_callback,0,&zErrMsg)) == 0)
    {
		if(verbose > 1)
		{
			printf("[*] Table 'USERS' does not exist... creating it now!\n");
		}
		d_print();
		db = table_create(db,2);
	}

	//Now that 'USERS' exists... we need to hash the *pwd and provide the SQL statement with a hex digest...
	d_print();
	md = hashMe(cfg,(unsigned char *)pwd);

	d_print();
	query = sqlite3_mprintf("INSERT INTO USERS VALUES(NULL,'%q','%q');",username,md);
	if( (sqlite3_exec(db,query,generic_callback,0,&zErrMsg)) != SQLITE_OK)
	{
		error(zErrMsg,__LINE__,__func__);
	}
	if(verbose > 1)
	{
		printf("[+] User added to table!\n");
	}
	
	d_print();
	free(zErrMsg);

	d_print();	
	sqlite3_close(db);

	return 0;
}

int u_delete(struct configs *cfg, char *filename, char *username, int verbose)
{
	char *query;
	char *zErrMsg = 0;
	sqlite3 *db;
	db = db_open(filename,verbose);

	// First seeing if table 'USERS' exists...
    query = sqlite3_mprintf("SELECT COUNT(TYPE) FROM sqlite_master WHERE TYPE='table' AND NAME='USERS';");

    if( (sqlite3_exec(db,query,countType_callback,0,&zErrMsg)) == 0)
    {
		if(verbose > 1)
		{
			printf("[*] Table 'USERS' does not exist... creating it now!\n");
		}
		db = table_create(db,2);
		//obviously if we just made the table, it's impossible that this function is useful
		sqlite3_close(db);
		error("Table was just created and is empty. Populate it first",__LINE__,__func__);
	}

	query = sqlite3_mprintf("DELETE FROM USERS WHERE USERNAME='%q';",username);
	if( (sqlite3_exec(db,query,generic_callback,0,&zErrMsg)) != SQLITE_OK)
	{
		error(zErrMsg,__LINE__,__func__);
	}
	if(verbose > 1)
	{
		printf("[+] User deleted from table!\n");
	}

	free(zErrMsg);
	sqlite3_close(db);
	return 0;
}

int u_passwd(struct configs *cfg, char *filename, char *username, char *pwd, int verbose)
{
	char *query;
	char *zErrMsg = 0;
	sqlite3 *db;
   	db = db_open(filename,verbose);

	// First seeing if table 'USERS' exists...
    query = sqlite3_mprintf("SELECT COUNT(TYPE) FROM sqlite_master WHERE TYPE='table' AND NAME='USERS';");

    if( (sqlite3_exec(db,query,countType_callback,0,&zErrMsg)) == 0)
    {
		if(verbose > 1)
		{
			printf("[*] Table 'USERS' does not exist... creating it now!\n");
		}
		db = table_create(db,2);

		//obviously if we just made the table, it's impossible that this function is useful
		sqlite3_close(db);
		error("Table was just created and is empty. Populate it first",__LINE__,__func__);
	}

	query = sqlite3_mprintf("UPDATE USERS SET PASSWORD = '%q' WHERE USERNAME= '%q';",pwd,username);
	if( (sqlite3_exec(db,query,generic_callback,0,&zErrMsg)) != SQLITE_OK)
	{
		error(zErrMsg,__LINE__,__func__);
	}
	if(verbose > 1)
	{
		printf("[+] User password updated!\n");
	}
	free(zErrMsg);
	sqlite3_close(db);
	return 0;
}

bool u_query(struct configs *cfg, char *filename, char *username, char *pwd, int verbose)
{
	char *query;
	char *zErrMsg = 0;
	unsigned char *md;
	sqlite3	*db;

	d_print();
	db = db_open(filename,verbose);

	// First seeing if table 'USERS' exists...
    query = sqlite3_mprintf("SELECT COUNT(TYPE) FROM sqlite_master WHERE TYPE='table' AND NAME='USERS';");
	if( (sqlite3_exec(db,query,countType_callback,0,&zErrMsg)) == 0)
    {
		if(verbose > 1)
		{
			printf("[*] Table 'USERS' does not exist... creating it now!\n");
		}
		d_print();
		db = table_create(db,2);

		//obviously if we just made the table, it's impossible that this function is useful
		sqlite3_close(db);
		error("Table was just created and is empty. Populate it first",__LINE__,__func__);
	}
	if(verbose > 1)
	{
		printf("[*] Table 'USERS' exists. Skipping....\n");
	}

	// get the md from pwd
	d_print();
	md = hashMe(cfg,(unsigned char *)pwd);

	query = sqlite3_mprintf("SELECT COUNT(*) FROM USERS WHERE USERNAME='%q' AND PASSWORD='%q';",username,md);
	if( (sqlite3_exec(db,query,countType_callback_inverse,0,&zErrMsg)) == 0)
	{
		if(verbose > 1)
		{
			printf("[*] Query for %s: pwd:[%s] md:[%s] --- FOUND\n",username,pwd,md);
		}
		return true;
	}
	else
	{
		if(verbose > 1)
		{
			fprintf(stderr,"[*] Query for %s: pwd:[%s] md:[%s] --- NOT FOUND\n",username,pwd,md);
		}
		return false;
	}
	return true;
}
