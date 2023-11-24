/*
	Profeanu Ioana - 343C1
	Tema 1 SPRC
	- the modified svc file for the server; it was modified to
	support command line arguments and database initialization
*/

#include "rpc_auth_app.h"
#include <stdio.h>
#include <stdlib.h>
#include <rpc/pmap_clnt.h>
#include <string.h>
#include <memory.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include "rpc_server_database.h"

#ifndef SIG_PF
#define SIG_PF void(*)(int)
#endif

static reply_authorization *
_func_authorization_1 (request_authorization  *argp, struct svc_req *rqstp)
{
	return (func_authorization_1_svc(*argp, rqstp));
}

static reply_access_token *
_func_access_token_1 (request_access_token  *argp, struct svc_req *rqstp)
{
	return (func_access_token_1_svc(*argp, rqstp));
}

static reply_validate_delegated_action *
_func_validate_delegated_action_1 (request_validate_delegated_action  *argp, struct svc_req *rqstp)
{
	return (func_validate_delegated_action_1_svc(*argp, rqstp));
}

static reply_token_approval *
_func_token_approval_1 (request_token_approval  *argp, struct svc_req *rqstp)
{
	return (func_token_approval_1_svc(*argp, rqstp));
}

static reply_access_token *
_func_renew_access_token_1 (request_renew_access_token  *argp, struct svc_req *rqstp)
{
	return (func_renew_access_token_1_svc(*argp, rqstp));
}

// removed the register keyword, as it is obsolete in C++
static void
auth_app_1(struct svc_req *rqstp, SVCXPRT *transp)
{
	union {
		request_authorization func_authorization_1_arg;
		request_access_token func_access_token_1_arg;
		request_validate_delegated_action func_validate_delegated_action_1_arg;
		request_token_approval func_token_approval_1_arg;
		request_renew_access_token func_renew_access_token_1_arg;
	} argument;
	char *result;
	xdrproc_t _xdr_argument, _xdr_result;
	char *(*local)(char *, struct svc_req *);

	switch (rqstp->rq_proc) {
	case NULLPROC:
		(void) svc_sendreply (transp, (xdrproc_t) xdr_void, (char *)NULL);
		return;

	case func_authorization:
		_xdr_argument = (xdrproc_t) xdr_request_authorization;
		_xdr_result = (xdrproc_t) xdr_reply_authorization;
		local = (char *(*)(char *, struct svc_req *)) _func_authorization_1;
		break;

	case func_access_token:
		_xdr_argument = (xdrproc_t) xdr_request_access_token;
		_xdr_result = (xdrproc_t) xdr_reply_access_token;
		local = (char *(*)(char *, struct svc_req *)) _func_access_token_1;
		break;

	case func_validate_delegated_action:
		_xdr_argument = (xdrproc_t) xdr_request_validate_delegated_action;
		_xdr_result = (xdrproc_t) xdr_reply_validate_delegated_action;
		local = (char *(*)(char *, struct svc_req *)) _func_validate_delegated_action_1;
		break;

	case func_token_approval:
		_xdr_argument = (xdrproc_t) xdr_request_token_approval;
		_xdr_result = (xdrproc_t) xdr_reply_token_approval;
		local = (char *(*)(char *, struct svc_req *)) _func_token_approval_1;
		break;

	case func_renew_access_token:
		_xdr_argument = (xdrproc_t) xdr_request_renew_access_token;
		_xdr_result = (xdrproc_t) xdr_reply_access_token;
		local = (char *(*)(char *, struct svc_req *)) _func_renew_access_token_1;
		break;

	default:
		svcerr_noproc (transp);
		return;
	}
	memset ((char *)&argument, 0, sizeof (argument));
	if (!svc_getargs (transp, (xdrproc_t) _xdr_argument, (caddr_t) &argument)) {
		svcerr_decode (transp);
		return;
	}
	result = (*local)((char *)&argument, rqstp);
	if (result != NULL && !svc_sendreply(transp, (xdrproc_t) _xdr_result, result)) {
		svcerr_systemerr (transp);
	}
	if (!svc_freeargs (transp, (xdrproc_t) _xdr_argument, (caddr_t) &argument)) {
		fprintf (stderr, "%s", "unable to free arguments");
		exit (1);
	}
	return;
}

int
main (int argc, char **argv)
{
	// main function modification to accept command line arguments

	// check the number of arguments
	if (argc < 4 || argc > 5) {
        fprintf(stderr, "Usage: %s userIDs_file resources_file approvals_file [token_lifetime]\n", argv[0]);
        exit(1);
    }

	// extract the file names
    char *userIDs_file = argv[1];
    char *resources_file = argv[2];
    char *approvals_file = argv[3];
    
	// check if the token validity was specified
	token_validity = 1;
	if (argc == 5) {
    	token_validity = atoi(argv[4]);
	}

	// parse the files and initialize the database
	read_usersIDs(userIDs_file);
	read_resources(resources_file);
	read_permissions(approvals_file);

	// the end of the main file modification
	
	// removed register keyword, as it is obsolete in C++
	SVCXPRT *transp;

	pmap_unset (AUTH_APP, AUTH_APP_VERS);

	transp = svcudp_create(RPC_ANYSOCK);
	if (transp == NULL) {
		fprintf (stderr, "%s", "cannot create udp service.");
		exit(1);
	}
	if (!svc_register(transp, AUTH_APP, AUTH_APP_VERS, auth_app_1, IPPROTO_UDP)) {
		fprintf (stderr, "%s", "unable to register (AUTH_APP, AUTH_APP_VERS, udp).");
		exit(1);
	}

	transp = svctcp_create(RPC_ANYSOCK, 0, 0);
	if (transp == NULL) {
		fprintf (stderr, "%s", "cannot create tcp service.");
		exit(1);
	}
	if (!svc_register(transp, AUTH_APP, AUTH_APP_VERS, auth_app_1, IPPROTO_TCP)) {
		fprintf (stderr, "%s", "unable to register (AUTH_APP, AUTH_APP_VERS, tcp).");
		exit(1);
	}

	svc_run ();
	fprintf (stderr, "%s", "svc_run returned");
	fout.close();
	exit (1);
	/* NOTREACHED */
}
