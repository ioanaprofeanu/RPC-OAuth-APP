/*
	Profeanu Ioana - 343C1
	Tema 1 SPRC
	- the header file contains the structures and function signatures
	used within the client implementation
*/

#ifndef RPC_CLIENT_UTILS_H
#define RPC_CLIENT_UTILS_H

#include "rpc_auth_app.h"
#include <rpc/rpc.h>
#include <iostream>
#include <fstream>
#include <string>
#include <unordered_map>
#include <vector>
#include <queue>
#include <sstream>

#define EMPTY ""

// structure that contains the user's tokens
struct Tokens {
    std::string token_authorize_access;
    std::string token_resource_access;
    std::string token_refresh;
    int validity;
};

// structure that contains the user id, command and parameter
// from the client input
struct Command_Parameters {
    std::string user_id;
    std::string command;
    std::string parameter;
};

// queue containing the client input
extern std::queue<std::string> client_input;
// the client database contains the user id and the asociated tokens
extern std::unordered_map<std::string, Tokens> client_database;

void read_client_input(const std::string& filename);
Command_Parameters extract_commands_parameters(const std::string& input);

void free_result_authorization(reply_authorization *result_1);

void free_result_access_token(reply_access_token *result_access_token);

void free_result_validate_delegated_action
	(reply_validate_delegated_action *result_validate_delegated_action);

void free_result_token_approval(reply_token_approval *result_token_approval);

void free_result_renew_access_token
	(reply_access_token *result_renew_access_token);

void free_func_authorization_1_arg1(request_authorization *arg1);

void free_func_access_token_1_arg1(request_access_token *arg1);

void free_func_validate_delegated_action_1_arg1
	(request_validate_delegated_action *arg1);

void free_func_token_approval_1_arg1(request_token_approval *arg1);

void free_func_renew_access_token_1_arg1(request_renew_access_token *arg1);

#endif // RPC_CLIENT_UTILS_H

