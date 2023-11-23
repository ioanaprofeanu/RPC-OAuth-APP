#ifndef RPC_CLIENT_COMMANDS_H
#define RPC_CLIENT_COMMANDS_H

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

// Structure for tokens
struct Tokens {
    std::string token_authorize_access;
    std::string token_resource_access;
    std::string token_refresh;
    int validity;
};

struct Command_Parameters {
    std::string user_id;
    std::string command;
    std::string parameter; // is either a resource name or number 
};

extern std::queue<std::string> client_input;
// the client database contains the user id and the asociated tokens
extern std::unordered_map<std::string, Tokens> client_database;

void read_client_input(const std::string& filename);
Command_Parameters extract_commands_parameters(const std::string& input);

void free_result_1 (reply_authorization *result_1);

void free_result_2 (reply_access_token *result_2);

void free_result_3 (reply_validate_delegated_action *result_3);

void free_result_4 (reply_token_approval *result_4);

void free_result_5 (reply_access_token *result_5);

void free_func_authorization_1_arg1 (request_authorization *arg1);

void free_func_access_token_1_arg1 (request_access_token *arg1);

void free_func_validate_delegated_action_1_arg1 (request_validate_delegated_action *arg1);

void free_func_token_approval_1_arg1 (request_token_approval *arg1);

void free_func_renew_access_token_1_arg1 (request_renew_access_token *arg1);

#endif // RPC_CLIENT_COMMANDS_H

