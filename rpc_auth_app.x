/*
	Profeanu Ioana - 343C1
	Tema 1 SPRC
*/

/*
	- structures for the authorization resource access request
*/

/* the client authorization request structure */
struct request_authorization {
	/* the user id string */
	string userID<>;
};

/* the server authorization reply structure */
struct reply_authorization {
	/* error message (if any error is encountered; value is null in case of no error) */
	string error_message<>;
	/* the authorization token */
	string token_authorize_access<>;
};

/*
	structures for resource access token request
*/

/* the client request access token structure */
struct request_access_token {
	/* the user id string */
	string userID<>;
	/* the authorization token signed by the user (the server will verify if it is really signed) */
	string token_authorize_access_signed<>;
	/* takes thhe value of 0 for no refresh, 1 for refresh */
	int use_refresh_token;
};

/* the server access token reply structure */
struct reply_access_token {
	/* error message (if any error is encountered; value is null in case of no error) */
	string error_message<>;
	/* the the resource access token */
	string token_resource_access<>;
	/* the refresh token (null if no refresh) */
	string token_refresh<>;
	/* the validity of the access token */
	int validity;
};

/*
	structures for validating a delegated action
*/
/* the client validate delegated action structure */
struct request_validate_delegated_action {
	/* the the resource access token */
	string token_resource_access<>;
	/* the accessed resource */
	string accessed_resource<>;
	/* the operation type */
	string operation_type<>;
};

/* the server validate delegated action structure */
struct reply_validate_delegated_action {
	string error_message<>;
	string success_message<>;
};

/*
	structure for token request token approval
	the server emulates the end user
*/
/* the client token approval structure */
struct request_token_approval {
	string token_authorize_access<>;
};

/* the server token approval structure */
struct reply_token_approval {
	/* the token can either be signed or not */
	string token_authorize_access_signed<>;
};

/*
	structure for requesting new access token
	the structure used by the server is reply_access_token
*/
/* the client renew access token request structure */
struct request_renew_access_token {
	/* the authorization token */
	string token_resource_access_expired<>;
};

program AUTH_APP {
    version AUTH_APP_VERS {
		/* the function for requesting authorization */
        reply_authorization func_authorization(request_authorization) = 1;

		/* the function for requesting access token */
        reply_access_token func_access_token(request_access_token) = 2;

		/* function for validating delegated action */
		reply_validate_delegated_action func_validate_delegated_action(request_validate_delegated_action) = 3;

		/* function for requesting token approval */
		reply_token_approval func_token_approval(request_token_approval) = 4;

		/* function for renewing the access token */
		reply_access_token func_renew_access_token(request_renew_access_token) = 5;
    } = 1;
} = 0x33445566;
