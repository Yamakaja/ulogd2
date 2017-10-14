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
#include <arpa/inet.h>
#include <ulogd/ulogd.h>
#include <errno.h>
#include <time.h>
#include <ulogd/conffile.h>
#include <netinet/if_ether.h>
#include <linux/in.h>

#ifndef ULOGD_CPLF_DEFAULT
#define ULOGD_CPLF_DEFAULT	"/var/log/packets.cplf"
#endif

#ifndef ULOGD_CPLF_SYNC_DEFAULT
#define ULOGD_CPLF_SYNC_DEFAULT	0
#endif

#ifndef ULOGD_CPLF_GUARD
#define ULOGD_CPLF_GUARD

#define ULOGD_CPLF_ICMP         0b000001
#define ULOGD_CPLF_TCP          0b000010
#define ULOGD_CPLF_UDP          0b000011
#define ULOGD_CPLF_MASK         0b000011

#define ULOGD_CPLF_ICMP_PING    0b000100
#define ULOGD_CPLF_ICMP_OTHER   0b001000

// define ULOGD_CPLF_TCP_SYN    0b000100
// define ULOGD_CPLF_TCP_ACK    0b001000
// define ULOGD_CPLF_TCP_PSH    0b010000
// define ULOGD_CPLF_TCP_RST    0b100000

#define ICMP_ECHO               8

#endif

enum input_keys {
    KEY_TIME,

    KEY_OOB_FAMILY,
    KEY_OOB_PROTOCOL,

    KEY_IP_SADDR,
    KEY_IP_PROTOCOL,

    KEY_TCP_DPORT,
    KEY_TCP_SYN,
    KEY_TCP_PSH,
    KEY_TCP_ACK,
    KEY_TCP_RST,
    KEY_TCP_FIN,

    KEY_UDP_DPORT,

    KEY_ICMP_TYPE
};

static struct ulogd_key cplf_input[] = {
    [KEY_TIME] = {
        .type   = ULOGD_RET_UINT32,
        .flags  = ULOGD_RETF_NONE,
        .name   = "oob.time.sec"
    },
    [KEY_OOB_FAMILY] = {
        .type   = ULOGD_RET_UINT8,
        .flags  = ULOGD_RETF_NONE,
        .name   = "oob.family"
    },
    [KEY_OOB_PROTOCOL] = {
        .type   = ULOGD_RET_UINT16,
        .flags  = ULOGD_RETF_NONE,
        .name   = "oob.protocol"
    },
    [KEY_IP_SADDR] = {
        .type   = ULOGD_RET_IPADDR,
        .flags  = ULOGD_RETF_NONE,
        .name   = "ip.saddr"
    },
    [KEY_IP_PROTOCOL] = {
        .type   = ULOGD_RET_UINT8,
        .flags  = ULOGD_RETF_NONE,
        .name   = "ip.protocol",
        .ipfix = {
            .vendor     = IPFIX_VENDOR_IETF,
            .field_id   = IPFIX_protocolIdentifier
        }
    },
    [KEY_TCP_DPORT] = {
        .type   = ULOGD_RET_UINT16,
        .flags  = ULOGD_RETF_NONE,
        .name   = "tcp.dport",
        .ipfix  = {
            .vendor     = IPFIX_VENDOR_IETF,
            .field_id   = IPFIX_tcpDestinationPort
        }
    },
    [KEY_TCP_SYN] = {
        .type   = ULOGD_RET_BOOL,
        .flags  = ULOGD_RETF_NONE,
        .name   = "tcp.syn"
    },
    [KEY_TCP_ACK] = {
        .type   = ULOGD_RET_BOOL,
        .flags  = ULOGD_RETF_NONE,
        .name   = "tcp.ack"
    },
    [KEY_TCP_PSH] = {
        .type   = ULOGD_RET_BOOL,
        .flags  = ULOGD_RETF_NONE,
        .name   = "tcp.psh"
    },
    [KEY_TCP_RST] = {
        .type   = ULOGD_RET_BOOL,
        .flags  = ULOGD_RETF_NONE,
        .name   = "tcp.rst"
    },
    [KEY_TCP_FIN] = {
        .type   = ULOGD_RET_BOOL,
        .flags  = ULOGD_RETF_NONE,
        .name   = "tcp.fin"
    },
    [KEY_UDP_DPORT] = {
        .type   = ULOGD_RET_UINT16,
        .flags  = ULOGD_RETF_NONE,
        .name   = "udp.dport",
        .ipfix  = {
            .vendor     = IPFIX_VENDOR_IETF,
            .field_id   = IPFIX_udpDestinationPort
        }
    },
    [KEY_ICMP_TYPE] = {
        .type   = ULOGD_RET_UINT8,
        .flags  = ULOGD_RETF_NONE,
        .name   = "icmp.type",
        .ipfix  = {
            .vendor     = IPFIX_VENDOR_IETF,
            .field_id   = IPFIX_icmpTypeIPv4
        }
    }
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
    struct cplf_instance *plugin_data = (struct cplf_instance *) &upi->private;
    struct ulogd_key *input = upi->input.keys;

    uint8_t family = input[KEY_OOB_FAMILY].u.source->u.value.ui8;
    uint8_t convfamily = family;

    if (family == AF_BRIDGE) {
        if (!pp_is_valid(input, KEY_OOB_PROTOCOL)) {
            ulogd_log(ULOGD_NOTICE, "No protocol inside AF_BRIDGE packet\n");
            return ULOGD_IRET_ERR;
        }

        switch (input[KEY_OOB_PROTOCOL].u.source->u.value.ui16) {
            case ETH_P_IP:
            case ETH_P_ARP:
                convfamily = AF_INET;
                break;

            default:
                return ULOGD_IRET_OK;
        }
    }

    if (convfamily != AF_INET) {
        ulogd_log(ULOGD_NOTICE, "Encountered IPv6");
        return ULOGD_IRET_OK;
    }

    uint32_t ip = input[KEY_IP_SADDR].u.source->u.value.ui32;
    uint32_t time = input[KEY_TIME].u.source->u.value.ui32;
    uint8_t proto = input[KEY_IP_PROTOCOL].u.source->u.value.ui8;

    uint8_t data[11];

    *((uint32_t*) (data + 1)) = time;
    *((uint32_t*) (data + 5)) = ip;

    switch (proto) {
        uint8_t icmp_type;

        case IPPROTO_ICMP:
        icmp_type = input[KEY_ICMP_TYPE].u.source->u.value.ui8;
        data[0] = ULOGD_CPLF_ICMP | (icmp_type == ICMP_ECHO ? ULOGD_CPLF_ICMP_PING : ULOGD_CPLF_ICMP_OTHER);
        break;

        case IPPROTO_TCP:
        data[0] = ULOGD_CPLF_TCP | (
                input[KEY_TCP_SYN].u.source->u.value.i8 << 2 |
                input[KEY_TCP_ACK].u.source->u.value.i8 << 3 |
                input[KEY_TCP_PSH].u.source->u.value.i8 << 4 |
                input[KEY_TCP_RST].u.source->u.value.i8 << 5 |
                input[KEY_TCP_FIN].u.source->u.value.i8 << 6);
        *((uint16_t*) (data + 9)) = input[KEY_TCP_DPORT].u.source->u.value.ui16;
        break;

        case IPPROTO_UDP:
        data[0] = ULOGD_CPLF_UDP;
        *((uint16_t*) (data + 9)) = input[KEY_UDP_DPORT].u.source->u.value.ui16;
        break;

        default:
            return ULOGD_IRET_OK;
    }

    fwrite(data, (proto == IPPROTO_ICMP ? 9 : 11), 1, plugin_data->of);

    if (upi->config_kset->ces[1].u.value)
        fflush(plugin_data->of);

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

    ulogd_log(ULOGD_DEBUG, "starting cplf\n");
    ulogd_log(ULOGD_DEBUG, "opening file: %s\n",
            pi->config_kset->ces[0].u.string);

    li->of = fopen(pi->config_kset->ces[0].u.string, "a");
    if (!li->of) {
        ulogd_log(ULOGD_FATAL, "can't open syscplf: %s\n", 
                strerror(errno));
        return -errno;
    }		
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
        .keys = cplf_input,
        .num_keys = ARRAY_SIZE(cplf_input),
        .type = ULOGD_DTYPE_PACKET | ULOGD_DTYPE_FLOW | ULOGD_DTYPE_SUM,
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
