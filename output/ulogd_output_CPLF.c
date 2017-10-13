/* ulogd_CPLF.c
 *
 * ulogd output target for syslog logging emulation
 *
 * This target produces a file which looks the same like the syslog-entries
 * of the LOG target.
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
 */
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <ulogd/ulogd.h>
#include <ulogd/conffile.h>

#ifndef ULOGD_CPLF_DEFAULT
#define ULOGD_CPLF_DEFAULT	"/var/log/packets.cplf"
#endif

#ifndef ULOGD_CPLF_SYNC_DEFAULT
#define ULOGD_CPLF_SYNC_DEFAULT	0
#endif

static struct ulogd_key cplf_inp[] = {
	{
		.type = ULOGD_RET_STRING,
		.name = "print",
	},
	{
		.type = ULOGD_RET_UINT32,
		.flags = ULOGD_KEYF_OPTIONAL,
		.name = "oob.time.sec",
	},
};

static struct config_keyset cplf_kset = {
	.num_ces = 2,
	.ces = {
		{
			.key 	 = "file",
			.type	 = CONFIG_TYPE_STRING,
			.options = CONFIG_OPT_NONE,
			.u	 = { .string = ULOGD_CPLF_DEFAULT },
		},
		{
			.key	 = "sync",
			.type	 = CONFIG_TYPE_INT,
			.options = CONFIG_OPT_NONE,
			.u	 = { .value = ULOGD_CPLF_SYNC_DEFAULT },
		},
	},
};

struct cplf_instance {
	FILE *of;
};

static int _output_cplf(struct ulogd_pluginstance *upi)
{
	struct cplf_instance *li = (struct cplf_instance *) &upi->private;
	struct ulogd_key *res = upi->input.keys;

	if (res[0].u.source->flags & ULOGD_RETF_VALID) {
		char *timestr;
		char *tmp;
		time_t now;

		if (res[1].u.source && (res[1].u.source->flags & ULOGD_RETF_VALID))
			now = (time_t) res[1].u.source->u.value.ui32;
		else
			now = time(NULL);
        
		fprintf(li->of, "%d %s", now, (char *) res[0].u.source->u.value.ptr);

		if (upi->config_kset->ces[1].u.value)
			fflush(li->of);
	}

	return ULOGD_IRET_OK;
}

static void signal_handler_cplf(struct ulogd_pluginstance *pi, int signal)
{
	struct cplf_instance *li = (struct cplf_instance *) &pi->private;
	FILE *old = li->of;

	switch (signal) {
	case SIGHUP:
		ulogd_log(ULOGD_NOTICE, "syscplf: reopening logfile\n");
		li->of = fopen(pi->config_kset->ces[0].u.string, "a");
		if (!li->of) {
			ulogd_log(ULOGD_ERROR, "can't reopen syscplf: %s\n",
				  strerror(errno));
			li->of = old;
		} else {
			fclose(old);
		}
		break;
	default:
		break;
	}
}
		

static int start_cplf(struct ulogd_pluginstance *pi)
{
	struct cplf_instance *li = (struct cplf_instance *) &pi->private;
	char *tmp;

	ulogd_log(ULOGD_DEBUG, "starting cplf\n");

#ifdef DEBUG_CPLF
	li->of = stdout;
#else
	ulogd_log(ULOGD_DEBUG, "opening file: %s\n",
		  pi->config_kset->ces[0].u.string);
	li->of = fopen(pi->config_kset->ces[0].u.string, "a");
	if (!li->of) {
		ulogd_log(ULOGD_FATAL, "can't open syscplf: %s\n", 
			  strerror(errno));
		return -errno;
	}		
#endif
	return 0;
}

static int fini_cplf(struct ulogd_pluginstance *pi) {
	struct cplf_instance *li = (struct cplf_instance *) &pi->private;

	if (li->of != stdout)
		fclose(li->of);

	return 0;
}

static int configure_cplf(struct ulogd_pluginstance *pi,
			    struct ulogd_pluginstance_stack *stack)
{
	ulogd_log(ULOGD_DEBUG, "parsing config file section %s\n", pi->id);
	return config_parse_file(pi->id, pi->config_kset);
}

static struct ulogd_plugin cplf_plugin = { 
	.name = "CPLF",
	.input = {
		.keys = cplf_inp,
		.num_keys = ARRAY_SIZE(cplf_inp),
		.type = ULOGD_DTYPE_PACKET | ULOGD_DTYPE_FLOW,
	},
	.output = {
		.type = ULOGD_DTYPE_SINK,
	},
	.config_kset 	= &cplf_kset,
	.priv_size 	= sizeof(struct cplf_instance),

	.configure	= &configure_cplf,
	.start	 	= &start_cplf,
	.stop	 	= &fini_cplf,

	.interp 	= &_output_cplf, 
	.signal 	= &signal_handler_cplf,
	.version	= VERSION,
};

void __attribute__ ((constructor)) init(void);

void init(void)
{
	ulogd_register_plugin(&cplf_plugin);
}
