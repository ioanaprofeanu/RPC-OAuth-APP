#include "rpc_auth_app.h"
#include <rpc/rpc.h>
#include <iostream>
#include <fstream>
#include <string>
#include <unordered_map>
#include <vector>
#include <queue>
#include <sstream>
#include "rpc_client_commands.h"

using namespace std;

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

void free_result_1 (reply_authorization *result_1)
{
	free(result_1->error_message);
	free(result_1->token_authorize_access);
}

void free_result_2 (reply_access_token *result_2)
{
	free(result_2->error_message);
	free(result_2->token_resource_access);
	free(result_2->token_refresh);
}

void free_result_3 (reply_validate_delegated_action *result_3)
{
	free(result_3->error_message);
	free(result_3->success_message);
}

void free_result_4 (reply_token_approval *result_4)
{
	free(result_4->token_authorize_access_signed);
}

void free_result_5 (reply_access_token *result_5)
{
	free(result_5->error_message);
	free(result_5->token_resource_access);
	free(result_5->token_refresh);
}

void free_func_authorization_1_arg1 (request_authorization *arg1)
{
	free(arg1->userID);
}

void free_func_access_token_1_arg1 (request_access_token *arg1)
{
	free(arg1->userID);
	free(arg1->token_authorize_access_signed);
}

void free_func_validate_delegated_action_1_arg1 (request_validate_delegated_action *arg1)
{
	free(arg1->token_resource_access);
	free(arg1->accessed_resource);
	free(arg1->operation_type);
}

void free_func_token_approval_1_arg1 (request_token_approval *arg1)
{
	free(arg1->token_authorize_access);
}

void free_func_renew_access_token_1_arg1 (request_renew_access_token *arg1)
{
	free(arg1->token_resource_access_expired);
}