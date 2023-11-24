/*
	Profeanu Ioana - 343C1
	Tema 1 SPRC
	- the file contains the implementations of the functions and
	initialization of global variables used by the client 
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

// queue containing the client input
queue<string> client_input;
// the client database contains the user id and the asociated tokens
unordered_map<string, Tokens> client_database;

// function that reads the client input from a file
void read_client_input(const string& filename) {
    ifstream file(filename);

    if (!file.is_open()) {
        cerr << "Unable to open file: " << filename << endl;
        return;
    }

    string line;

    // clear the queue if it is not empty
    while (!client_input.empty()) {
        client_input.pop();
    }

    // read the file line by line and push each line in the queue
    while (getline(file, line)) {
        client_input.push(line);
    }

    file.close();
}

// function that extracts the user id, command and parameter from a line
Command_Parameters extract_commands_parameters(const string& input) {
    istringstream stream_input(input);
    string current_string;

    Command_Parameters result;

    // extract the user id
    if (getline(stream_input, current_string, ','))
        result.user_id = current_string;

    // extract the command
    if (getline(stream_input, current_string, ','))
        result.command = current_string;

    // extract the parameter
    if (getline(stream_input, current_string, ','))
        result.parameter = current_string;

    return result;
}

void free_result_authorization(reply_authorization *result_authorization)
{
	free(result_authorization->error_message);
	free(result_authorization->token_authorize_access);
}

void free_result_access_token(reply_access_token *result_access_token)
{
	free(result_access_token->error_message);
	free(result_access_token->token_resource_access);
	free(result_access_token->token_refresh);
}

void free_result_validate_delegated_action
	(reply_validate_delegated_action *result_validate_delegated_action)
{
	free(result_validate_delegated_action->error_message);
	free(result_validate_delegated_action->success_message);
}

void free_result_token_approval(reply_token_approval *result_token_approval)
{
	free(result_token_approval->token_authorize_access_signed);
}

void free_result_renew_access_token
	(reply_access_token *result_renew_access_token)
{
	free(result_renew_access_token->error_message);
	free(result_renew_access_token->token_resource_access);
	free(result_renew_access_token->token_refresh);
}

void free_func_authorization_1_arg1(request_authorization *arg1)
{
	free(arg1->userID);
}

void free_func_access_token_1_arg1(request_access_token *arg1)
{
	free(arg1->userID);
	free(arg1->token_authorize_access_signed);
}

void free_func_validate_delegated_action_1_arg1
	(request_validate_delegated_action *arg1)
{
	free(arg1->token_resource_access);
	free(arg1->accessed_resource);
	free(arg1->operation_type);
}

void free_func_token_approval_1_arg1(request_token_approval *arg1)
{
	free(arg1->token_authorize_access);
}

void free_func_renew_access_token_1_arg1(request_renew_access_token *arg1)
{
	free(arg1->token_resource_access_expired);
}
