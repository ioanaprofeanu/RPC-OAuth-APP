/*
	Profeanu Ioana - 343C1
	Tema 1 SPRC
	- the file contains the client side of the application
*/

#include "rpc_auth_app.h"
#include <rpc/rpc.h>
#include <iostream>
#include <fstream>
#include <string>
#include <unordered_map>
#include <vector>
#include <queue>
#include <sstream>
#include "rpc_client_utils.h"
using namespace std;

void
auth_app_1(char *host)
{
	CLIENT *clnt;
	ofstream fout("client.out");

	clnt = clnt_create (host, AUTH_APP, AUTH_APP_VERS, "udp");
	if (clnt == NULL) {
		clnt_pcreateerror (host);
		exit (1);
	}

	// iterate through the client input queue and process each command
    while (!client_input.empty()) {
        string currentElement = client_input.front();
		Command_Parameters command_parameters =
			extract_commands_parameters(currentElement);

		// if the command is REQUEST
		if (command_parameters.command == "REQUEST") {
			// erase the user from the client database,
			// in case it already exists
			client_database.erase(command_parameters.user_id);

			// make the authorization call to the server;
			// give the current user id as parameter
			request_authorization func_authorization_1_arg1;
			func_authorization_1_arg1.userID =
				strdup(command_parameters.user_id.c_str());
			reply_authorization *result_authorization =
				func_authorization_1(func_authorization_1_arg1, clnt);

			// if the call fails, print the error
			if (result_authorization == (reply_authorization *) NULL) {
				free_result_authorization(result_authorization);
				free_func_authorization_1_arg1(&func_authorization_1_arg1);
				clnt_perror (clnt, "call failed");
				exit(1);
			}

			free_func_authorization_1_arg1(&func_authorization_1_arg1);

			// if the user is found in the server database,
			// no error is returned
			if (strcmp(result_authorization->error_message, EMPTY) == 0) {
				// make an end-user call to sign the token; give
				// the previously received authorization token as parameter
				request_token_approval func_token_approval_1_arg1;
				func_token_approval_1_arg1.token_authorize_access =
					strdup(result_authorization->token_authorize_access);
				reply_token_approval  *result_token_approval =
					func_token_approval_1(func_token_approval_1_arg1, clnt);

				// if the call fails, print the error
				if (result_token_approval == (reply_token_approval *) NULL) {
					free_result_token_approval(result_token_approval);
					free_func_token_approval_1_arg1
						(&func_token_approval_1_arg1);
					clnt_perror (clnt, "call failed");
					exit(1);
				}

				free_func_token_approval_1_arg1(&func_token_approval_1_arg1);

				// if no error occured, give the server the signed or unsinged
				// token, the user id and the refresh token flag
				request_access_token func_access_token_1_arg1;
				func_access_token_1_arg1.token_authorize_access_signed =
				strdup(result_token_approval->token_authorize_access_signed);
				func_access_token_1_arg1.userID =
					strdup(command_parameters.user_id.c_str());
				func_access_token_1_arg1.use_refresh_token =
					atoi(command_parameters.parameter.c_str());
				reply_access_token *result_access_token =
					func_access_token_1(func_access_token_1_arg1, clnt);

				// if the call fails, print the error
				if (result_access_token == (reply_access_token *) NULL) {
					free_result_access_token(result_access_token);
					free_func_access_token_1_arg1(&func_access_token_1_arg1);
					clnt_perror (clnt, "call failed");
					exit(1);
				}

				free_func_access_token_1_arg1(&func_access_token_1_arg1);

				// is no error message is returned, it means
				// the access request was successful
				if (strcmp(result_access_token->error_message, EMPTY) == 0) {
					// retrieve the tokens from the server response
					// and add them to the client database
					Tokens user_tokens;
					user_tokens.token_authorize_access =
						result_authorization->token_authorize_access;
					user_tokens.token_resource_access =
						result_access_token->token_resource_access;
					user_tokens.token_refresh =
						result_access_token->token_refresh;
					user_tokens.validity = result_access_token->validity;
					client_database[command_parameters.user_id] = user_tokens;

					// print the tokens
					if (user_tokens.token_refresh == EMPTY) {
						fout << user_tokens.token_authorize_access <<
						" -> " << user_tokens.token_resource_access << endl;
					} else {
						fout << user_tokens.token_authorize_access <<
						" -> " << user_tokens.token_resource_access << "," <<
						user_tokens.token_refresh << endl;
					}
				} else {
					// if an error message is returned, it means the
					// access request was not successful
					fout << result_access_token->error_message << endl;
				}

				// free responses
				free_result_authorization(result_authorization);
				free_result_access_token(result_access_token);
				free_result_token_approval(result_token_approval);

			} else {
				// if the user is not found in the server
				// database, print the error
				fout << result_authorization->error_message << endl;
				free_result_authorization(result_authorization);

			}
		// if the command is a resource access request
		} else {
			// first, check if the user has requested a refresh
			// token and if the validity of the access token is 0
			if (client_database[command_parameters.user_id].token_refresh
				!= EMPTY && client_database[command_parameters.user_id]
				.validity == 0) {
				// make a request for the a new access and refresh token,
				// by giving the old access token as parameter
				request_renew_access_token func_renew_access_token_1_arg1;
				func_renew_access_token_1_arg1.token_resource_access_expired =
					strdup(client_database[command_parameters.user_id].
					token_resource_access.c_str());
				reply_access_token *result_renew_access_token =
					func_renew_access_token_1
					(func_renew_access_token_1_arg1, clnt);

				// if the call fails, print the error
				if (result_renew_access_token == (reply_access_token *) NULL) {
					free_result_renew_access_token(result_renew_access_token);
					free_func_renew_access_token_1_arg1
						(&func_renew_access_token_1_arg1);
					clnt_perror (clnt, "call failed");
					exit(1);
				}

				free_func_renew_access_token_1_arg1
					(&func_renew_access_token_1_arg1);

				// if no error message is returned, it means the access
				// refresh token request was successful
				if (strcmp(result_renew_access_token->error_message,
					EMPTY) == 0) {
					// update the client database with the
					// new tokens and validity
					client_database[command_parameters.user_id].
						token_resource_access = result_renew_access_token
						->token_resource_access;
					client_database[command_parameters.user_id].
						token_refresh = result_renew_access_token
						->token_refresh;
					client_database[command_parameters.user_id].
						validity = result_renew_access_token->validity;
				} else {
					// print error message in case the
					// request was not successful
					fout << result_renew_access_token->error_message << endl;
				}

				free_result_renew_access_token(result_renew_access_token);
			}

			// make a request to validate the delegated action,
			// by giving the access token and the resource as parameters
			request_validate_delegated_action
				func_validate_delegated_action_1_arg1;
			func_validate_delegated_action_1_arg1.token_resource_access =
				strdup(client_database[command_parameters.user_id].
				token_resource_access.c_str());
			func_validate_delegated_action_1_arg1.accessed_resource =
				strdup(command_parameters.parameter.c_str());
			func_validate_delegated_action_1_arg1.operation_type =
				strdup(command_parameters.command.c_str());
			// decrease the validity of the access token
			client_database[command_parameters.user_id].validity--;
			// make call
			reply_validate_delegated_action *result_validate_delegated_action
				= func_validate_delegated_action_1
				(func_validate_delegated_action_1_arg1, clnt);

			// if the call fails, print the error
			if (result_validate_delegated_action ==
				(reply_validate_delegated_action *) NULL) {
				free_result_validate_delegated_action
					(result_validate_delegated_action);
				free_func_validate_delegated_action_1_arg1
					(&func_validate_delegated_action_1_arg1);
				clnt_perror (clnt, "call failed");
				exit(1);
			}

			free_func_validate_delegated_action_1_arg1
				(&func_validate_delegated_action_1_arg1);
			
			// if no error message is returned, it means
			// the delegated action was successful
			if (strcmp(result_validate_delegated_action->error_message,
				 EMPTY) == 0) {
				fout << result_validate_delegated_action->success_message
					<< endl;
			} else {
				// the delegated action was not successful
				fout << result_validate_delegated_action->error_message
					<< endl;
			}

			free_result_validate_delegated_action
				(result_validate_delegated_action);
		}

		// pop the current element from the queue
        client_input.pop();
    }

	fout.close();
	clnt_destroy (clnt);
}


int
main (int argc, char *argv[])
{
	char *host;

	if (argc < 2) {
		printf ("usage: %s server_host\n", argv[0]);
		exit (1);
	}

	// read the client input
	read_client_input(argv[2]);
	
	host = argv[1];
	auth_app_1 (host);
exit (0);
}
