/*******************************************************************************
*                                                                              *
*                 Copyright (C) 2016, MindBricks Technologies                  *
*                  Rajmohan Banavi (rajmohan@mindbricks.com)                   *
*                            All Rights Reserved.                              *
*                                                                              *
********************************************************************************
*                                                                              *
* This document contains information that is confidential and proprietary to   *
* xxxxxxxxxxxxxxxxxxxxxxx. No part of this document may be reproduced in any   *
* form whatsoever without prior written approval from xxxxxxxxxxxxxxxxxxxxxxx. *
*                                                                              *
*******************************************************************************/

#ifdef __cplusplus
extern "C" {
#endif

/******************************************************************************/

#include <errno.h>
#include <limits.h>   // INT_MAX

#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-features.h>
#include <net-snmp/types.h>

#include <net-snmp/net-snmp-includes.h>

#include <net-snmp/library/fd_event_manager.h>
#include <net-snmp/library/large_fd_set.h>

#include <net-snmp/agent/snmp_agent.h>

#include <gateway.h>


const char *app_name = "gateway";

//TODO: following need to be relooked into
struct timeval  starttime;
static struct timeval starttimeM;
//TODO: end



void gateway_loop(void);
int gateway_setup(void);
static int gateway_start_snmp_server(void);
static int gateway_handle_snmp_packet(int op, 
        netsnmp_session * session, int reqid, netsnmp_pdu *pdu, void *magic);
static int gateway_check_packet(netsnmp_session * session,
                           netsnmp_transport *transport,
                           void *transport_data, int transport_data_length);
static int gateway_check_parse(
        netsnmp_session * session, netsnmp_pdu *pdu, int result);


int gateway_init(void) {

    snmp_log(LOG_INFO, "SNMP Gateway initializing ...\n");
    snmp_log(LOG_INFO, "NET-SNMP version %s\n", netsnmp_get_version());

    if (!gateway_setup()) {
        snmp_log(LOG_INFO, "Error when setting up the gateway... aborting\n");
        return 1;
    }

    init_snmp(app_name);

    if (gateway_start_snmp_server()) {
        snmp_log(LOG_INFO, "Starting of snmp server failed... Aborting\n");
        return 1;
    }

    snmp_store(app_name);

    /* TODO: send coldstart trap if possible */

    /* loop forever, listening for packets */
    gateway_loop();

    return 1;
}


int gateway_shutdown(void) {

    snmp_log(LOG_INFO, "Shutting down snmp gateway ...\n");

    return 1;
}

// TODO: globals!!!
typedef struct _agent_nsap {
    int             handle;
    netsnmp_transport *t;
    void           *s;          /*  Opaque internal session pointer.  */
    struct _agent_nsap *next;
} agent_nsap;

static agent_nsap *agent_nsap_list = NULL;
static netsnmp_session *main_session = NULL;
// TODO: end


/*
 * Set up an agent session on the given transport.  Return a handle
 * which may later be used to de-register this transport.  A return
 * value of -1 indicates an error.  
 */

int
netsnmp_register_agent_nsap(netsnmp_transport *t)
{
    netsnmp_session *s, *sp = NULL;
    agent_nsap     *a = NULL, *n = NULL, **prevNext = &agent_nsap_list;
    int             handle = 0;
    void           *isp = NULL;

    if (t == NULL) {
        return -1;
    }

    DEBUGMSGTL(("netsnmp_register_agent_nsap", "fd %d\n", t->sock));

    n = (agent_nsap *) malloc(sizeof(agent_nsap));
    if (n == NULL) {
        return -1;
    }
    s = (netsnmp_session *) malloc(sizeof(netsnmp_session));
    if (s == NULL) {
        SNMP_FREE(n);
        return -1;
    }
    memset(s, 0, sizeof(netsnmp_session));
    snmp_sess_init(s);

    /*
     * Set up the session appropriately for an agent.  
     */

    s->version = SNMP_DEFAULT_VERSION;
    s->callback = gateway_handle_snmp_packet;
    s->authenticator = NULL;
#if 0
    s->flags = netsnmp_ds_get_int(NETSNMP_DS_APPLICATION_ID, 
				  NETSNMP_DS_AGENT_FLAGS);
#endif
    s->flags = 0; // TODO: what's the significance of these flags?
    s->isAuthoritative = SNMP_SESS_AUTHORITATIVE;

    /* Optional supplimental transport configuration information and
       final call to actually open the transport */
    if (netsnmp_sess_config_transport(s->transport_configuration, t)
        != SNMPERR_SUCCESS) {
        SNMP_FREE(s);
        SNMP_FREE(n);
        return -1;
    }


    if (t->f_open)
        t = t->f_open(t);

    if (NULL == t) {
        SNMP_FREE(s);
        SNMP_FREE(n);
        return -1;
    }

    t->flags |= NETSNMP_TRANSPORT_FLAG_OPENED;

    sp = snmp_add(s, t, gateway_check_packet, gateway_check_parse);
    if (sp == NULL) {
        SNMP_FREE(s);
        SNMP_FREE(n);
        return -1;
    }

    isp = snmp_sess_pointer(sp);
    if (isp == NULL) {          /*  over-cautious  */
        SNMP_FREE(s);
        SNMP_FREE(n);
        return -1;
    }

    n->s = isp;
    n->t = t;

    if (main_session == NULL) {
        main_session = snmp_sess_session(isp);
    }

    for (a = agent_nsap_list; a != NULL && handle + 1 >= a->handle;
         a = a->next) {
        handle = a->handle;
        prevNext = &(a->next);
    }

    if (handle < INT_MAX) {
        n->handle = handle + 1;
        n->next = a;
        *prevNext = n;
        SNMP_FREE(s);
        return n->handle;
    } else {
        SNMP_FREE(s);
        SNMP_FREE(n);
        return -1;
    }
}


void netsnmp_deregister_agent_nsap(int handle)
{
    agent_nsap     *a = NULL, **prevNext = &agent_nsap_list;
    int             main_session_deregistered = 0;

    DEBUGMSGTL(("netsnmp_deregister_agent_nsap", "handle %d\n", handle));

    for (a = agent_nsap_list; a != NULL && a->handle < handle; a = a->next) {
        prevNext = &(a->next);
    }

    if (a != NULL && a->handle == handle) {
        *prevNext = a->next;
	if (snmp_sess_session_lookup(a->s)) {
            if (main_session == snmp_sess_session(a->s)) {
                main_session_deregistered = 1;
            }
            snmp_close(snmp_sess_session(a->s));
            /*
             * The above free()s the transport and session pointers.  
             */
        }
        SNMP_FREE(a);
    }

    /*
     * If we've deregistered the session that main_session used to point to,
     * then make it point to another one, or in the last resort, make it equal
     * to NULL.  Basically this shouldn't ever happen in normal operation
     * because main_session starts off pointing at the first session added by
     * init_master_agent(), which then discards the handle.  
     */

    if (main_session_deregistered) {
        if (agent_nsap_list != NULL) {
            DEBUGMSGTL(("snmp_agent",
			"WARNING: main_session ptr changed from %p to %p\n",
                        main_session, snmp_sess_session(agent_nsap_list->s)));
            main_session = snmp_sess_session(agent_nsap_list->s);
        } else {
            DEBUGMSGTL(("snmp_agent",
			"WARNING: main_session ptr changed from %p to NULL\n",
                        main_session));
            main_session = NULL;
        }
    }
}



static int gateway_start_snmp_server(void)
{
    netsnmp_transport *transport;
    char           *cptr;
    char           *buf = NULL;
    char           *st;

    /* default transport */
    buf = strdup("");

    DEBUGMSGTL(("snmp_agent", "final port spec: \"%s\"\n", buf));
    st = buf;
    do {
        /*
         * Specification format: 
         * 
         * NONE:                      (a pseudo-transport)
         * UDP:[address:]port        (also default if no transport is specified)
         * TCP:[address:]port         (if supported)
         * Unix:pathname              (if supported)
         * AAL5PVC:itf.vpi.vci        (if supported)
         * IPX:[network]:node[/port] (if supported)
         * 
         */

	cptr = st;
	st = strchr(st, ',');
	if (st)
	    *st++ = '\0';

        DEBUGMSGTL(("snmp_agent", "installing master agent on port %s\n",
                    cptr));

        if (strncasecmp(cptr, "none", 4) == 0) {
            DEBUGMSGTL(("snmp_agent",
                        "init_master_agent; pseudo-transport \"none\" "
			"requested\n"));
            break;
        }
        transport = netsnmp_transport_open_server("snmp", cptr);

        if (transport == NULL) {
            snmp_log(LOG_ERR, "Error opening specified endpoint \"%s\"\n",
                     cptr);
            return 1;
        }

        if (netsnmp_register_agent_nsap(transport) == 0) {
            snmp_log(LOG_ERR,
                     "Error registering specified transport \"%s\" as an "
		     "agent NSAP\n", cptr);
            return 1;
        } else {
            DEBUGMSGTL(("snmp_agent",
                        "init_master_agent; \"%s\" registered as an agent "
			"NSAP\n", cptr));
        }
    } while(st && *st != '\0');
    SNMP_FREE(buf);

    return 0;
}


void gateway_loop(void) {

    int             numfds;
    netsnmp_large_fd_set readfds, writefds, exceptfds;
    struct timeval  timeout, *tvp = &timeout;
    int             count, block;

    netsnmp_large_fd_set_init(&readfds, FD_SETSIZE);
    netsnmp_large_fd_set_init(&writefds, FD_SETSIZE);
    netsnmp_large_fd_set_init(&exceptfds, FD_SETSIZE);

    /*
     * Loop-forever: execute message handlers for sockets with data
     */
    while (1) {

        snmp_log(LOG_INFO, "Entering loop ...\n");

        /*
         * default to sleeping for a really long time. INT_MAX
         * should be sufficient (eg we don't care if time_t is
         * a long that's bigger than an int).
         */
        tvp = &timeout;
        tvp->tv_sec = INT_MAX;
        tvp->tv_usec = 0;

        numfds = 0;
        NETSNMP_LARGE_FD_ZERO(&readfds);
        NETSNMP_LARGE_FD_ZERO(&writefds);
        NETSNMP_LARGE_FD_ZERO(&exceptfds);
        block = 0;
        snmp_select_info2(&numfds, &readfds, tvp, &block);
        if (block == 1) {
            tvp = NULL;         /* block without timeout */
	    }

        // snmp_log(LOG_INFO, "Stage 1. numfds =%d\n", numfds);

        DEBUGMSGTL(("snmpd/select", "select( numfds=%d, ..., tvp=%p)\n",
                    numfds, tvp));
        if (tvp)
            DEBUGMSGTL(("timer", "tvp %ld.%ld\n", (long) tvp->tv_sec,
                        (long) tvp->tv_usec));
        count = netsnmp_large_fd_set_select(
                numfds, &readfds, &writefds, &exceptfds, tvp);
        DEBUGMSGTL(("snmpd/select", "returned, count = %d\n", count));

        if (count > 0) {
            if (count > 0) {
              snmp_read2(&readfds);
            }
        } else {
            switch (count) {
            case 0:
                snmp_timeout();
                break;
            case -1:
                DEBUGMSGTL(("snmpd/select", "  errno = %d\n", errno));
                if (errno == EINTR) {
                    /*
                     * likely that we got a signal. Check our special signal
                     * flags before retrying select.
                     */
                    continue;
                } else {
                    snmp_log_perror("select");
                }
                return;
            default:
                snmp_log(LOG_ERR, "select returned %d\n", count);
                return;
            }                   /* endif -- count>0 */

            /*
             * see if persistent store needs to be saved
             */
            snmp_store_if_needed();

            /*
             * run requested alarms 
             */
            run_alarms();
        }
    }

    netsnmp_large_fd_set_cleanup(&readfds);
    netsnmp_large_fd_set_cleanup(&writefds);
    netsnmp_large_fd_set_cleanup(&exceptfds);

    snmp_log(LOG_INFO, "Received TERM or STOP signal...  shutting down...\n");
}


void gateway_starttime(void)
{
    gettimeofday(&starttime, NULL);
    netsnmp_get_monotonic_clock(&starttimeM);
}


// TODO: globals!!!
int callback_master_num = -1; 
netsnmp_session *callback_master_sess = NULL;



int gateway_handle_request(netsnmp_agent_session *asp, int status) {

    netsnmp_variable_list *var_ptr;

    switch (asp->pdu->command) {
    case SNMP_MSG_GET:
        snmp_log(LOG_DEBUG, "  GET message\n");
        break;
    case SNMP_MSG_GETNEXT:
        snmp_log(LOG_DEBUG, "  GETNEXT message\n");
        break;
    case SNMP_MSG_RESPONSE:
        snmp_log(LOG_DEBUG, "  RESPONSE message\n");
        break;
    case SNMP_MSG_SET:
        snmp_log(LOG_DEBUG, "  SET message\n");
        break;
    case SNMP_MSG_TRAP:
        snmp_log(LOG_DEBUG, "  TRAP message\n");
        break;
    case SNMP_MSG_GETBULK:
        snmp_log(LOG_DEBUG, "  GETBULK message, non-rep=%ld, max_rep=%ld\n",
                 asp->pdu->errstat, asp->pdu->errindex);
        break;
    case SNMP_MSG_INFORM:
        snmp_log(LOG_DEBUG, "  INFORM message\n");
        break;
    case SNMP_MSG_TRAP2:
        snmp_log(LOG_DEBUG, "  TRAP2 message\n");
        break;
    case SNMP_MSG_REPORT:
        snmp_log(LOG_DEBUG, "  REPORT message\n");
        break;

    default:
        snmp_log(LOG_DEBUG, "  UNKNOWN message, type=%02X\n",
                 asp->pdu->command);
        snmp_increment_statistic(STAT_SNMPINASNPARSEERRS);
        return 0;
    }

    for (var_ptr = asp->pdu->variables; var_ptr != NULL;
         var_ptr = var_ptr->next_variable) {
        size_t          c_oidlen = 256, c_outlen = 0;
        u_char         *c_oid = (u_char *) malloc(c_oidlen);

        if (c_oid) {
            if (!sprint_realloc_objid
                (&c_oid, &c_oidlen, &c_outlen, 1, var_ptr->name,
                 var_ptr->name_length)) {
                snmp_log(LOG_DEBUG, "    -- %s [TRUNCATED]\n",
                         c_oid);
            } else {
                snmp_log(LOG_DEBUG, "    -- %s\n", c_oid);
            }
            SNMP_FREE(c_oid);
        }
    }

    return 1;
}



netsnmp_agent_session * init_agent_snmp_session(
        netsnmp_session * session, netsnmp_pdu *pdu)
{
    netsnmp_agent_session *asp = (netsnmp_agent_session *)
        calloc(1, sizeof(netsnmp_agent_session));

    if (asp == NULL) {
        return NULL;
    }

    DEBUGMSGTL(("snmp_agent","agent_sesion %8p created\n", asp));
    asp->session = session;
    asp->pdu = snmp_clone_pdu(pdu);
    asp->orig_pdu = snmp_clone_pdu(pdu);
    asp->rw = READ;
    asp->exact = TRUE;
    asp->next = NULL;
    asp->mode = RESERVE1;
    asp->status = SNMP_ERR_NOERROR;
    asp->index = 0;
    asp->oldmode = 0;
    asp->treecache_num = -1;
    asp->treecache_len = 0;
    asp->reqinfo = SNMP_MALLOC_TYPEDEF(netsnmp_agent_request_info);
    DEBUGMSGTL(("verbose:asp", "asp %p reqinfo %p created\n",
                asp, asp->reqinfo));

    return asp;
}


NETSNMP_INLINE void netsnmp_free_agent_request_info(
                netsnmp_agent_request_info *ari) {

    if (ari) {
        if (ari->agent_data) {
            netsnmp_free_all_list_data(ari->agent_data);
	}
        SNMP_FREE(ari);
    }
}


void netsnmp_free_request_data_sets(netsnmp_request_info *request) {

    if (request && request->parent_data) {
        netsnmp_free_all_list_data(request->parent_data);
        request->parent_data = NULL;
    }
}


void free_agent_snmp_session(netsnmp_agent_session *asp) {

    if (!asp)
        return;

    DEBUGMSGTL(("snmp_agent","agent_session %8p released\n", asp));

    DEBUGMSGTL(("verbose:asp", "asp %p reqinfo %p freed\n",
                asp, asp->reqinfo));
    if (asp->orig_pdu)
        snmp_free_pdu(asp->orig_pdu);
    if (asp->pdu)
        snmp_free_pdu(asp->pdu);
    if (asp->reqinfo)
        netsnmp_free_agent_request_info(asp->reqinfo);
    SNMP_FREE(asp->treecache);
    SNMP_FREE(asp->bulkcache);
    if (asp->requests) {
        int             i;
        for (i = 0; i < asp->vbcount; i++) {
            netsnmp_free_request_data_sets(&asp->requests[i]);
        }
        SNMP_FREE(asp->requests);
    }
    SNMP_FREE(asp);
}


static int gateway_handle_snmp_packet(int op, 
        netsnmp_session * session, int reqid, netsnmp_pdu *pdu, void *magic)
{
    netsnmp_agent_session *asp;
    int  status, rc;

    // snmp_log(LOG_INFO, "gateway_handle_snmp_packet callback\n");

    /*
     * We only support receiving here.  
     */
    if (op != NETSNMP_CALLBACK_OP_RECEIVED_MESSAGE) {
        return 1;
    }

    /*
     * RESPONSE messages won't get this far, but TRAP-like messages
     * might.  
     */
    if (pdu->command == SNMP_MSG_TRAP || pdu->command == SNMP_MSG_INFORM ||
        pdu->command == SNMP_MSG_TRAP2) {
        DEBUGMSGTL(("snmp_agent", "received trap-like PDU (%02x)\n",
                    pdu->command));
        pdu->command = SNMP_MSG_TRAP2;
        snmp_increment_statistic(STAT_SNMPUNKNOWNPDUHANDLERS);
        return 1;
    }

    /*
     * send snmpv3 authfail trap.
     */
    if (pdu->version  == SNMP_VERSION_3 && 
        session->s_snmp_errno == SNMPERR_USM_AUTHENTICATIONFAILURE) {
           // TODO:
           //send_easy_trap(SNMP_TRAP_AUTHFAIL, 0);
           return 1;
    } 
	
    if (magic == NULL) {
        asp = init_agent_snmp_session(session, pdu);
        status = SNMP_ERR_NOERROR;
    } else {
        asp = (netsnmp_agent_session *) magic;
        status = asp->status;
    }

    rc = gateway_handle_request(asp, status);

    /*
     * done 
     */
    DEBUGMSGTL(("snmp_agent", "end of handle_snmp_packet, asp = %8p\n",
                asp));
    return rc;
}


static int gateway_check_packet(netsnmp_session * session,
                           netsnmp_transport *transport,
                           void *transport_data, int transport_data_length)
{
    char  *addr_string = NULL;

    // snmp_log(LOG_INFO, "gateway_check_packet callback\n");

    /*
     * Log the message and/or dump the message.
     * Optionally cache the network address of the sender.
     */

    if (transport != NULL && transport->f_fmtaddr != NULL) {
        /*
         * Okay I do know how to format this address for logging.  
         */
        addr_string = transport->f_fmtaddr(transport, transport_data,
                                           transport_data_length);
        /*
         * Don't forget to free() it.  
         */
    }

    snmp_increment_statistic(STAT_SNMPINPKTS);

    return 1;
}


static int gateway_check_parse(
        netsnmp_session * session, netsnmp_pdu *pdu, int result)
{
    // snmp_log(LOG_INFO, "gateway_check_parse callback\n");

    return 1;                   /* XXX: does it matter what the return value
                                 * is?  Yes: if we return 0, then the PDU is
                                 * dumped.  */
}


int gateway_setup(void) {

    gateway_starttime();

    // gateway_callback_transport();

    netsnmp_container_init_list();

    return 1;
}


/******************************************************************************/

#ifdef __cplusplus
}
#endif

/******************************************************************************/
