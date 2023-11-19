/*
 *  de modificat de facut cpp
 */

#include "rpc_auth_app.h"
#include "rpc_server_database.h"
#include "token.h"

using namespace std;

reply_authorization *
func_authorization_1_svc(request_authorization arg1,  struct svc_req *rqstp)
{
	static reply_authorization result;

	string user_id = arg1.userID;
	// TODO ar treebui afisat in server.out!!!!!!!
	cout << "BEGIN " << user_id << " AUTHZ\n";
	auto it = usersID_active_tokens.find(user_id);
    if (it != usersID_active_tokens.end()) {
        // if the user is found
		char* token_authorize_access = generate_access_token(&user_id[0]);
		string token_authorize_access_string(token_authorize_access);

		// TODO asta poate fac doar dupa daca semnez token ul?
		// update the user's token
		usersID_active_tokens[user_id] = token_authorize_access_string;
		// update the database
		Database_Value new_database_value = initialize_server_database_entry(token_authorize_access_string);
		server_database[token_authorize_access_string] = new_database_value;

		result.token_authorize_access = strdup(token_authorize_access);
		result.error_message = strdup("");

		if (result.token_authorize_access == NULL) {
			cerr << "Error: Memory allocation failed for token_authorize_access" << endl;
			// Handle the error, possibly by exiting or taking appropriate actions
			exit(1);
		}
		cout << "RequestToken = " << token_authorize_access_string << endl;
    } else {
        result.error_message = new char[strlen("USER_NOT_FOUND") + 1];
		strcpy(result.error_message, "USER_NOT_FOUND");
		result.token_authorize_access = new char[strlen(NO_TOKEN) + 1];
    }

	cout << result.error_message << endl;
	cout << result.token_authorize_access << endl;

	return &result;
}

reply_access_token *
func_access_token_1_svc(request_access_token arg1,  struct svc_req *rqstp)
{
	static reply_access_token  result;

	/*
	 * insert server code here
	 */

	return &result;
}

reply_validate_delegated_action *
func_validate_delegated_action_1_svc(request_validate_delegated_action arg1,  struct svc_req *rqstp)
{
	static reply_validate_delegated_action  result;

	/*
	 * insert server code here
	 */

	return &result;
}

reply_token_approval *
func_token_approval_1_svc(request_token_approval arg1,  struct svc_req *rqstp)
{
	static reply_token_approval  result;

	/*
	 * insert server code here
	 */

	return &result;
}

reply_access_token *
func_renew_access_token_1_svc(request_renew_access_token arg1,  struct svc_req *rqstp)
{
	static reply_access_token  result;

	/*
	 * insert server code here
	 */

	return &result;
}
