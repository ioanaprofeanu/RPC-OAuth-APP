/*
 de modificat! facut cpp
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
using namespace std;

// Structure for tokens
struct Tokens {
    std::string token_authorize_access;
    std::string token_resource_access;
    std::string token_refresh;
    int validity;
};

queue<string> client_input;
// the client database contains the user id and the asociated tokens
unordered_map<string, Tokens> client_database;

void read_client_input(const string& filename) {
    ifstream file(filename);

    if (!file.is_open()) {
        cerr << "Error: Unable to open file " << filename << endl;
        return;
    }

    string line;

    // Clear the queue
    while (!client_input.empty()) {
        client_input.pop();
    }

    // Read all lines until the end of the file
    while (getline(file, line)) {
        client_input.push(line);
    }

    file.close();
}

struct Command_Parameters {
    string user_id;
    string command;
    string parameter; // is either a resource name or number 
};

Command_Parameters extract_commands_parameters(const string& input) {
    istringstream stream_input(input);
    string token;

    Command_Parameters result;

    // Extract user_id
    if (getline(stream_input, token, ','))
        result.user_id = token;

    // Extract command
    if (getline(stream_input, token, ','))
        result.command = token;

    // Extract parameter
    if (getline(stream_input, token, ','))
        result.parameter = token;

    return result;
}

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

	// Iterate through the queue, process each element, and pop it
    while (!client_input.empty()) {
        // Access the front element
        string currentElement = client_input.front();

		Command_Parameters command_parameters = extract_commands_parameters(currentElement);
		// autorizare si semnare si cerere acces (pentru operatia de REQUEST)
		if (command_parameters.command == "REQUEST") {
			// erase the user from the client database, in case it already exists
			client_database.erase(command_parameters.user_id);
			// fac cerere autorizare, primesc un token
			request_authorization func_authorization_1_arg1;
			func_authorization_1_arg1.userID = strdup(command_parameters.user_id.c_str());

			reply_authorization *result_1 = func_authorization_1(func_authorization_1_arg1, clnt);
			if (result_1 == (reply_authorization *) NULL) {
				clnt_perror (clnt, "call failed");
				exit(1);
			}

			// if the user is found in the server database
			if (strcmp(result_1->error_message, "") == 0) {
				// make an end-user call to sign the token
				request_token_approval func_token_approval_1_arg1;
				func_token_approval_1_arg1.token_authorize_access = strdup(result_1->token_authorize_access);
				reply_token_approval  *result_4 = func_token_approval_1(func_token_approval_1_arg1, clnt);
				if (result_4 == (reply_token_approval *) NULL) {
					clnt_perror (clnt, "call failed");
					exit(1);
				}

				// request access token
				request_access_token func_access_token_1_arg1;
				func_access_token_1_arg1.token_authorize_access_signed = strdup(result_4->token_authorize_access_signed);
				func_access_token_1_arg1.userID = strdup(command_parameters.user_id.c_str());
				func_access_token_1_arg1.use_refresh_token = atoi(command_parameters.parameter.c_str());
				reply_access_token *result_2 = func_access_token_1(func_access_token_1_arg1, clnt);
				if (result_2 == (reply_access_token *) NULL) {
					clnt_perror (clnt, "call failed");
					exit(1);
				}

				// if the token is signed, print the access token
				if (strcmp(result_2->error_message, "") == 0) {
					Tokens user_tokens;
					user_tokens.token_authorize_access = result_1->token_authorize_access;
					user_tokens.token_resource_access = result_2->token_resource_access;
					user_tokens.token_refresh = result_2->token_refresh;
					user_tokens.validity = result_2->validity;
					client_database[command_parameters.user_id] = user_tokens;
					if (user_tokens.token_refresh == "") {
						fout << user_tokens.token_authorize_access << " -> " << user_tokens.token_resource_access << endl;
					} else {
						fout << user_tokens.token_authorize_access << " -> " << user_tokens.token_resource_access << "," << user_tokens.token_refresh << endl;
					}
				} else {
					// if the token is not signed, the access is denied, so print the error
					fout << result_2->error_message << endl;
				}
			} else {
				// if the user is not found in the server database, print the error
				fout << result_1->error_message << endl;
			}

		} else {
			// tbd
			// AICI FAC IF IN CAZ CA AM REFRESH TOKEN
			if (client_database[command_parameters.user_id].token_refresh != "" && client_database[command_parameters.user_id].validity == 0) {
				request_renew_access_token func_renew_access_token_1_arg1;
				func_renew_access_token_1_arg1.userID = strdup(command_parameters.user_id.c_str());
				// TODO: AICI ARGUMENTUL AR TREBUI SA SE NUMEASCA token_resource_access
				func_renew_access_token_1_arg1.token_resource_access_expired = strdup(client_database[command_parameters.user_id].token_resource_access.c_str());
				reply_access_token *result_5 = func_renew_access_token_1(func_renew_access_token_1_arg1, clnt);
				if (result_5 == (reply_access_token *) NULL) {
					clnt_perror (clnt, "call failed");
					exit(1);
				}
				if (strcmp(result_5->error_message, "") == 0) {
					client_database[command_parameters.user_id].token_resource_access = result_5->token_resource_access;
					client_database[command_parameters.user_id].token_refresh = result_5->token_refresh;
					client_database[command_parameters.user_id].validity = result_5->validity;
				} else {
					fout << result_5->error_message << endl;
				}
			}
			request_validate_delegated_action func_validate_delegated_action_1_arg1;
			func_validate_delegated_action_1_arg1.token_resource_access = strdup(client_database[command_parameters.user_id].token_resource_access.c_str());
			func_validate_delegated_action_1_arg1.accessed_resource = strdup(command_parameters.parameter.c_str());
			func_validate_delegated_action_1_arg1.operation_type = strdup(command_parameters.command.c_str());
			client_database[command_parameters.user_id].validity--;

			reply_validate_delegated_action *result_3 = func_validate_delegated_action_1(func_validate_delegated_action_1_arg1, clnt);
			if (result_3 == (reply_validate_delegated_action *) NULL) {
				clnt_perror (clnt, "call failed");
				exit(1);
			}
			if (strcmp(result_3->error_message, "") == 0) {
				fout << result_3->success_message << endl;
			} else {
				fout << result_3->error_message << endl;
			}
		}
		// Pop the front element to remove it from the queue
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

	read_client_input(argv[2]);
	
	host = argv[1];
	auth_app_1 (host);
exit (0);
}
