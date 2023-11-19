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

queue<string> client_input;

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
	reply_access_token  *result_2;
	request_access_token func_access_token_1_arg1;
	reply_validate_delegated_action  *result_3;
	request_validate_delegated_action func_validate_delegated_action_1_arg1;
	reply_token_approval  *result_4;
	request_token_approval func_token_approval_1_arg1;
	reply_access_token  *result_5;
	request_renew_access_token func_renew_access_token_1_arg1;

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
		cout << "user_id = " << command_parameters.user_id << endl;
		// autorizare si semnare si cerere acces (pentru operatia de REQUEST)
		if (command_parameters.command == "REQUEST") {
			// fac cerere autorizare, primesc un token
			request_authorization func_authorization_1_arg1;
			func_authorization_1_arg1.userID = strdup(command_parameters.user_id.c_str());
			if (func_authorization_1_arg1.userID == NULL) {
				cerr << "Error: Memory allocation failed for user ID" << endl;
				// Handle the error, possibly by exiting or taking appropriate actions
				exit(1);
			}

			reply_authorization *result_1 = func_authorization_1(func_authorization_1_arg1, clnt);
			if (result_1 == (reply_authorization *) NULL) {
				perror("RPC client call failed");
				exit(1);
			}
			cout << "RequestToken = " << result_1->token_authorize_access << endl;
			// fac cerere semnare de catre utilizator
			// trimit cererea semnata (sau poate nesemnata) catre server
			// serverul verifica daca tokenul este valid si imi da raspuns. in functie de raspuns, afisez mesajul corespunzator

        
		} else {
			// tbd
			cout << "recource access command: " << command_parameters.command << endl;
		}
		// Pop the front element to remove it from the queue
        client_input.pop();
    }

	// result_1 = func_authorization_1(func_authorization_1_arg1, clnt);
	// if (result_1 == (reply_authorization *) NULL) {
	// 	clnt_perror (clnt, "call failed");
	// }
	// result_2 = func_access_token_1(func_access_token_1_arg1, clnt);
	// if (result_2 == (reply_access_token *) NULL) {
	// 	clnt_perror (clnt, "call failed");
	// }
	// result_3 = func_validate_delegated_action_1(func_validate_delegated_action_1_arg1, clnt);
	// if (result_3 == (reply_validate_delegated_action *) NULL) {
	// 	clnt_perror (clnt, "call failed");
	// }
	// result_4 = func_token_approval_1(func_token_approval_1_arg1, clnt);
	// if (result_4 == (reply_token_approval *) NULL) {
	// 	clnt_perror (clnt, "call failed");
	// }
	// result_5 = func_renew_access_token_1(func_renew_access_token_1_arg1, clnt);
	// if (result_5 == (reply_access_token *) NULL) {
	// 	clnt_perror (clnt, "call failed");
	// }

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
