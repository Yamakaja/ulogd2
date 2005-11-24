/* ulogd_MYSQL.c, Version $Revision$
 *
 * ulogd output plugin for logging to a MySQL database
 *
 * (C) 2000-2005 by Harald Welte <laforge@gnumonks.org>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 
 *  as published by the Free Software Foundation
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 * 
 * $Id$
 *
 * 15 May 2001, Alex Janssen <alex@ynfonatic.de>:
 *      Added a compability option for older MySQL-servers, which
 *      don't support mysql_real_escape_string
 *
 * 17 May 2001, Alex Janssen <alex@ynfonatic.de>:
 *      Added the --with-mysql-log-ip-as-string feature. This will log
 *      IP's as string rather than an unsigned long integer to the database.
 *	See ulogd/doc/mysql.table.ipaddr-as-string as an example.
 *	BE WARNED: This has _WAY_ less performance during table searches.
 *
 * 09 Feb 2005, Sven Schuster <schuster.sven@gmx.de>:
 * 	Added the "port" parameter to specify ports different from 3306
 *
 * 12 May 2005, Jozsef Kadlecsik <kadlec@blackhole.kfki.hu>
 *	Added reconnecting to lost mysql server.
 *
 * 15 Oct 2005, Harald Welte <laforge@netfilter.org>
 * 	Port to ulogd2 (@ 0sec conference, Bern, Suisse)
 */

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <arpa/inet.h>

#include <ulogd/ulogd.h>
#include <ulogd/conffile.h>

#include <mysql/mysql.h>

#define DEBUG_MYSQL

#ifdef DEBUG_MYSQL
#define DEBUGP(x, args...)	fprintf(stderr, x, ## args)
#else
#define DEBUGP(x, args...)
#endif

struct mysql_instance {
	/* the database handle we are using */
	MYSQL *dbh;

	/* buffer for our insert statement */
	char *stmt;

	/* pointer to the beginning of the "VALUES" part */
	char *stmt_val;

	/* pointer to current inser position in statement */
	char *stmt_ins;

	/* Attempt to reconnect if connection is lost */
	time_t reconnect;
};
#define TIME_ERR		((time_t)-1)	/* Be paranoid */

/* our configuration directives */
static struct config_keyset mysql_kset = {
	.num_ces = 8,
	.ces = {
		{
			.key = "db", 
			.type = CONFIG_TYPE_STRING,
			.options = CONFIG_OPT_MANDATORY,
		},
		{
			.key = "host", 
			.type = CONFIG_TYPE_STRING,
			.options = CONFIG_OPT_MANDATORY,
		},
		{
			.key = "user", 
			.type = CONFIG_TYPE_STRING,
			.options = CONFIG_OPT_MANDATORY,
		},
		{
			.key = "pass", 
			.type = CONFIG_TYPE_STRING,
			.options = CONFIG_OPT_MANDATORY,
		},
		{
			.key = "table", 
			.type = CONFIG_TYPE_STRING,
			.options = CONFIG_OPT_MANDATORY,
		},
		{
			.key = "port",
			.type = CONFIG_TYPE_INT,
		},
		{
			.key = "reconnect",
			.type = CONFIG_TYPE_INT,
		},
		{
			.key = "connect_timeout",
			.type = CONFIG_TYPE_INT,
		},
		{
			.key = "ip_as_string",
			.type = CONFIG_TYPE_INT,
		},
	},
};
#define db_ce(x)	(x->ces[0])
#define	host_ce(x)	(x->ces[1])
#define user_ce(x)	(x->ces[2])
#define pass_ce(x)	(x->ces[3])
#define table_ce(x)	(x->ces[4])
#define port_ce(x)	(x->ces[5])
#define reconnect_ce(x)	(x->ces[6])
#define timeout_ce(x)	(x->ces[7])
#define asstring_ce(x)	(x->ces[8])

static struct ulogd_plugin mysql_plugin;

// FIXME static int _mysql_init_db(ulog_iret_t *result);

/* our main output function, called by ulogd */
static int interp_mysql(struct ulogd_pluginstance *upi)
{
	struct mysql_instance *mi = (struct mysql_instance *) &upi->private;
	struct ulogd_key *res;
	char *tmpstr;		/* need this for --log-ip-as-string */
	struct in_addr addr;
	int i;

	mi->stmt_ins = mi->stmt_val;

	for (i = 0; i < upi->input.num_keys; i++) { 
		res = upi->input.keys[i].u.source;

		if (!res)
			ulogd_log(ULOGD_NOTICE, "no result for %s ?!?\n",
				  upi->input.keys[i].name);
			
		if (!res || !IS_VALID(*res)) {
			/* no result, we have to fake something */
			sprintf(mi->stmt_ins, "NULL,");
			mi->stmt_ins = mi->stmt + strlen(mi->stmt);
			continue;
		}
		
		switch (res->type) {
		case ULOGD_RET_INT8:
			sprintf(mi->stmt_ins, "%d,", res->u.value.i8);
			break;
		case ULOGD_RET_INT16:
			sprintf(mi->stmt_ins, "%d,", res->u.value.i16);
			break;
		case ULOGD_RET_INT32:
			sprintf(mi->stmt_ins, "%d,", res->u.value.i32);
			break;
		case ULOGD_RET_INT64:
			sprintf(mi->stmt_ins, "%lld,", res->u.value.i64);
			break;
		case ULOGD_RET_UINT8:
			sprintf(mi->stmt_ins, "%u,", res->u.value.ui8);
			break;
		case ULOGD_RET_UINT16:
			sprintf(mi->stmt_ins, "%u,", res->u.value.ui16);
			break;
		case ULOGD_RET_IPADDR:
			if (asstring_ce(upi->config_kset).u.value) {
				memset(&addr, 0, sizeof(addr));
				addr.s_addr = ntohl(res->u.value.ui32);
				*(mi->stmt_ins++) = '\'';
				tmpstr = inet_ntoa(addr);
#ifdef OLD_MYSQL
				mysql_escape_string(mi->stmt_ins, tmpstr,
						    strlen(tmpstr));
#else
				mysql_real_escape_string(mi->dbh, mi->stmt_ins,
							 tmpstr,
						 	strlen(tmpstr));
#endif /* OLD_MYSQL */
                                mi->stmt_ins = mi->stmt + strlen(mi->stmt);
				sprintf(mi->stmt_ins, "',");
				break;
			}
			/* fallthrough when logging IP as u_int32_t */
		case ULOGD_RET_UINT32:
			sprintf(mi->stmt_ins, "%u,", res->u.value.ui32);
			break;
		case ULOGD_RET_UINT64:
			sprintf(mi->stmt_ins, "%llu,", res->u.value.ui64);
			break;
		case ULOGD_RET_BOOL:
			sprintf(mi->stmt_ins, "'%d',", res->u.value.b);
			break;
		case ULOGD_RET_STRING:
			*(mi->stmt_ins++) = '\'';
#ifdef OLD_MYSQL
			mysql_escape_string(mi->stmt_ins, res->u.value.ptr,
				strlen(res->u.value.ptr));
#else
			mysql_real_escape_string(mi->dbh, mi->stmt_ins,
				res->u.value.ptr, strlen(res->u.value.ptr));
#endif
			mi->stmt_ins = mi->stmt + strlen(mi->stmt);
			sprintf(mi->stmt_ins, "',");
			break;
		case ULOGD_RET_RAW:
			ulogd_log(ULOGD_NOTICE,
				"%s: type RAW not supported by MySQL\n",
				upi->input.keys[i].name);
			break;
		default:
			ulogd_log(ULOGD_NOTICE,
				"unknown type %d for %s\n",
				res->type, upi->input.keys[i].name);
			break;
		}
	mi->stmt_ins = mi->stmt + strlen(mi->stmt);
	}
	*(mi->stmt_ins - 1) = ')';
	DEBUGP("stmt=#%s#\n", mi->stmt);

	/* now we have created our statement, insert it */

	if (mysql_real_query(mi->dbh, mi->stmt, strlen(mi->stmt))) {
		ulogd_log(ULOGD_ERROR, "sql error during insert: %s\n",
			  mysql_error(mi->dbh));

		// FIXME return _mysql_init_db(upi);
	}

	return 0;
}

/* no connection, plugin disabled */
static int mysql_output_disabled(struct ulogd_pluginstance *upi)
{
	return 0;
}

#define MYSQL_INSERTTEMPL   "insert into X (Y) values (Z)"
#define MYSQL_VALSIZE	100

/* create the static part of our insert statement */
static int mysql_createstmt(struct ulogd_pluginstance *upi)
{
	struct mysql_instance *mi = (struct mysql_instance *) upi->private;
	struct _field *f;
	unsigned int size;
	char buf[ULOGD_MAX_KEYLEN];
	char *underscore;
	int i;

	if (mi->stmt)
		free(mi->stmt);

	/* caclulate the size for the insert statement */
	size = strlen(MYSQL_INSERTTEMPL) + 
				strlen(table_ce(upi->config_kset).u.string);

	for (i = 0; i < upi->input.num_keys; i++) {
		/* we need space for the key and a comma, as well as
		 * enough space for the values */
		size += strlen(upi->input.keys[i].name) + 1 + MYSQL_VALSIZE;
	}	

	ulogd_log(ULOGD_DEBUG, "allocating %u bytes for statement\n", size);

	mi->stmt = (char *) malloc(size);
	if (!mi->stmt) {
		ulogd_log(ULOGD_ERROR, "OOM!\n");
		return -ENOMEM;
	}

	sprintf(mi->stmt, "insert into %s (",
		table_ce(upi->config_kset).u.string);
	mi->stmt_val = mi->stmt + strlen(mi->stmt);

	for (i = 0; i < upi->input.num_keys; i++) {
		strncpy(buf, upi->input.keys[i].name, ULOGD_MAX_KEYLEN);	
		while ((underscore = strchr(buf, '.')))
			*underscore = '_';
		sprintf(mi->stmt_val, "%s,", buf);
		mi->stmt_val = mi->stmt + strlen(mi->stmt);
	}
	*(mi->stmt_val - 1) = ')';

	sprintf(mi->stmt_val, " values (");
	mi->stmt_val = mi->stmt + strlen(mi->stmt);

	ulogd_log(ULOGD_DEBUG, "stmt='%s'\n", mi->stmt);

	return 0;
}

/* find out which columns the table has */
static int mysql_get_columns(struct ulogd_pluginstance *upi)
{
	struct mysql_instance *mi = (struct mysql_instance *) upi->private;
	MYSQL_RES *result;
	MYSQL_FIELD *field;
	struct ulogd_key *f, *f2;
	int i;

	if (!mi->dbh) 
		return -1;

	result = mysql_list_fields(mi->dbh, 
				   table_ce(upi->config_kset).u.string, NULL);
	if (!result)
		return -1;

	/* Thea idea here is that we can create a pluginstance specific input
	 * key array by not specifyling a plugin input key list.  ulogd core
	 * will then set upi->input to NULL.  Yes, this creates a memory hole
	 * in case the core just calls ->configure() and then aborts (and thus
	 * never free()s the memory we allocate here.  FIXME. */

	/* Cleanup before reconnect */
	if (upi->input.keys) {
		free(upi->input.keys);
		upi->input.keys = NULL;
		upi->input.num_keys = 0;
	}

	upi->input.num_keys = mysql_field_count(mi->dbh);
	upi->input.keys = malloc(sizeof(struct ulogd_key) * 
						upi->input.num_keys);
	if (!upi->input.keys) {
		upi->input.num_keys = 0;
		return -ENOMEM;
	}

	i = 0;
	while ((field = mysql_fetch_field(result))) {
		char buf[ULOGD_MAX_KEYLEN+1];
		char *underscore;
		int id;

		/* replace all underscores with dots */
		strncpy(buf, field->name, ULOGD_MAX_KEYLEN);
		while ((underscore = strchr(buf, '_')))
			*underscore = '.';

		DEBUGP("field '%s' found: ", buf);

		/* add it u list of input keys */
		strncpy(upi->input.keys[i].name, buf, ULOGD_MAX_KEYLEN);
		i++;
	}

	mysql_free_result(result);
	return 0;
}

/* make connection and select database */
static int open_db(struct ulogd_pluginstance *upi, char *server,
		   int port, char *user, char *pass, char *db)
{
	struct mysql_instance *mi = (struct mysql_instance *) upi->private;
	unsigned int connect_timeout = timeout_ce(upi->config_kset).u.value;

	mi->dbh = mysql_init(NULL);
	if (!mi->dbh)
		return -1;

	if (connect_timeout)
		mysql_options(mi->dbh, MYSQL_OPT_CONNECT_TIMEOUT, 
			      (const char *) &connect_timeout);

	if (!mysql_real_connect(mi->dbh, server, user, pass, db, port, NULL, 0))
		return -1;

	return 0;
}

#if 0
static int init_reconnect(struct ulogd_pluginstance *upi)
{
	struct mysql_instance *mi = (struct mysql_instance *) upi->private;
	if (reconnect_ce(upi->config_kset).u.value) {
		mi->reconnect = time(NULL);
		if (mi->reconnect != TIME_ERR) {
			ulogd_log(ULOGD_ERROR, "no connection to database, "
					       "attempting to reconnect "
					       "after %u seconds\n",
					       reconnect_ce(upi).u.value);
			mi->reconnect += reconnect_ce(upi).u.value;
			mysql_plugin.interp = &_mysql_init_db;
			return -1;
		}
	}
	/* Disable plugin permanently */
	mysql_plugin.interp = &mysql_output_disabled;
	
	return 0;
}

static int _mysql_init_db(struct ulogd_pluginstance *upi)
{
	struct mysql_instance *mi = (struct mysql_instance *) upi->private;
	if (mi->reconnect && mi->reconnect > time(NULL))
		return 0;
	
	if (open_db(upi, host_ce(upi->config_kset).u.string,
		    port_ce(upi->config_kset).u.value,
		    user_ce(upi->config_kset).u.string, 
		    pass_ce(upi->config_kset).u.string,
		    db_ce(upi->config_kset).u.string)) {
		ulogd_log(ULOGD_ERROR, "can't establish database connection\n");
		return init_reconnect(upi);
	}

#if 0
	/* read the fieldnames to know which values to insert */
	if (mysql_get_columns(table_ce.u.string)) {
		ulogd_log(ULOGD_ERROR, "unable to get mysql columns\n");
		return init_reconnect();
	}
	mysql_createstmt();
#endif	
	/* enable plugin */
	mysql_plugin.output = &mysql_output;

	mi->reconnect = 0;

	return mysql_output(result);
}
#endif

static void signal_mysql(struct ulogd_pluginstance *upi,
			 int signal)
{
}

static int configure_mysql(struct ulogd_pluginstance *upi,
			   struct ulogd_pluginstance_stack *stack)
{
	struct mysql_instance *mi = (struct mysql_instance *) upi->private;
	int ret;

	/* First: Parse configuration file section for this instance */
	ret = config_parse_file(upi->id, upi->config_kset);
	if (ret < 0)
		return ret;

	/* Second: Open Database */
	ret = open_db(upi, host_ce(upi->config_kset).u.string,
		      port_ce(upi->config_kset).u.value,
		      user_ce(upi->config_kset).u.string,
		      pass_ce(upi->config_kset).u.string,
		      db_ce(upi->config_kset).u.string);
	if (ret < 0)
		return ret;
	
	/* Third: Determine required input keys for given table */
	ret = mysql_get_columns(upi);
	
	/* Close database, since ulogd core could just call configure
	 * but abort during input key resolving routines.  configure
	 * doesn't have a destructor... */
	mysql_close(mi->dbh);
	
	return ret;
}

static int start_mysql(struct ulogd_pluginstance *upi)
{
	struct mysql_instance *mi = (struct mysql_instance *) upi->private;
	int ret;

	ret = open_db(upi, host_ce(upi->config_kset).u.string,
		      port_ce(upi->config_kset).u.value,
		      user_ce(upi->config_kset).u.string,
		      pass_ce(upi->config_kset).u.string,
		      db_ce(upi->config_kset).u.string);
	if (ret < 0)
		return ret;
	
	ret = mysql_createstmt(upi);
	if (ret < 0)
		mysql_close(mi->dbh);

	return ret;
}

static int stop_mysql(struct ulogd_pluginstance *upi)
{
	struct mysql_instance *mi = (struct mysql_instance *) upi->private;
	mysql_close(mi->dbh);

	/* try to free our dynamically allocated input key array */
	if (upi->input.keys) {
		free(upi->input.keys);
		upi->input.keys = NULL;
	}
	return 0;
}

static struct ulogd_plugin mysql_plugin = {
	.name = "MYSQL",
	.input = {
		.keys = NULL,
		.num_keys = 0,
		.type = ULOGD_DTYPE_PACKET | ULOGD_DTYPE_FLOW, 
	},
	.output = {
		.type = ULOGD_DTYPE_SINK,
	},
	.config_kset = &mysql_kset,
	.priv_size = sizeof(struct mysql_instance),
	.configure = &configure_mysql,
	.start	   = &start_mysql,
	.stop	   = &stop_mysql,
	.signal	   = &signal_mysql,
	.interp	   = &interp_mysql,
	.version   = ULOGD_VERSION,
};

void __attribute__ ((constructor)) init(void);

void init(void) 
{
	ulogd_register_plugin(&mysql_plugin);
}