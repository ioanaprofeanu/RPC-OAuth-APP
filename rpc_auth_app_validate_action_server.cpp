#include "rpc_auth_app.h"
#include "rpc_server_database.h"
#include <iostream>
#include <fstream>
#include <string>
#include <unordered_map>
#include <vector>
#include <queue>
#include <sstream>
#include <algorithm>

using namespace std;

reply_validate_delegated_action* error_validate_delegated_action(string error_message, string operation_type, string accessed_resource, string token_resource_access, int tokens_validity)
{
	static reply_validate_delegated_action result;
	result.error_message = new char[error_message.length() + 1];
	strcpy(result.error_message, error_message.c_str());
	result.success_message = new char[strlen(EMPTY) + 1];
	strcpy(result.success_message, EMPTY);
	fout << "DENY (" << operation_type << "," << accessed_resource << "," << token_resource_access << "," << tokens_validity << ")" << endl;
	return &result;
}

reply_validate_delegated_action *
func_validate_delegated_action_1_svc(request_validate_delegated_action arg1,  struct svc_req *rqstp)
{
	static reply_validate_delegated_action result;

	string token_resource_access = arg1.token_resource_access;
	string accessed_resource = arg1.accessed_resource;
	string operation_type = arg1.operation_type;

	auto it_server_database = server_database.find(token_resource_access);
	auto it_resources = find(resources.begin(), resources.end(), accessed_resource);

	if (it_server_database == server_database.end()) {
		return error_validate_delegated_action("PERMISSION_DENIED", operation_type, accessed_resource, "", 0);
	}

	if (server_database[token_resource_access].tokens.validity <= 0) {
		return error_validate_delegated_action("TOKEN_EXPIRED", operation_type, accessed_resource, "", server_database[token_resource_access].tokens.validity); 
	}
	if (it_resources == resources.end()) {
		// decrease the validity of the token
		server_database[token_resource_access].tokens.validity--;
		return error_validate_delegated_action("RESOURCE_NOT_FOUND", operation_type, accessed_resource, token_resource_access, server_database[token_resource_access].tokens.validity); 
	}

	if (operation_type == "READ") {
        if (server_database[token_resource_access].permissionsResources[accessed_resource].Read == false) {
			// decrease the validity of the token
			server_database[token_resource_access].tokens.validity--;
			return error_validate_delegated_action("OPERATION_NOT_PERMITTED", operation_type, accessed_resource, token_resource_access, server_database[token_resource_access].tokens.validity); 
		}
    } else if (operation_type == "INSERT") {
		if (server_database[token_resource_access].permissionsResources[accessed_resource].Insert == false) {
			// decrease the validity of the token
			server_database[token_resource_access].tokens.validity--;
			return error_validate_delegated_action("OPERATION_NOT_PERMITTED", operation_type, accessed_resource, token_resource_access, server_database[token_resource_access].tokens.validity); 
		}
        // Code for INSERT operation
    } else if (operation_type == "MODIFY") {
		if (server_database[token_resource_access].permissionsResources[accessed_resource].Modify == false) {
			// decrease the validity of the token
			server_database[token_resource_access].tokens.validity--;
			return error_validate_delegated_action("OPERATION_NOT_PERMITTED", operation_type, accessed_resource, token_resource_access, server_database[token_resource_access].tokens.validity); 
		}
        // Code for MODIFY operation
    } else if (operation_type == "DELETE") {
		if (server_database[token_resource_access].permissionsResources[accessed_resource].Delete == false) {
			// decrease the validity of the token
			server_database[token_resource_access].tokens.validity--;
			return error_validate_delegated_action("OPERATION_NOT_PERMITTED", operation_type, accessed_resource, token_resource_access, server_database[token_resource_access].tokens.validity); 
		}
        // Code for DELETE operation
    } else if (operation_type == "EXECUTE") {
		if (server_database[token_resource_access].permissionsResources[accessed_resource].Execute == false) {
			// decrease the validity of the token
			server_database[token_resource_access].tokens.validity--;
			return error_validate_delegated_action("OPERATION_NOT_PERMITTED", operation_type, accessed_resource, token_resource_access, server_database[token_resource_access].tokens.validity); 
		}
		// Code for EXECUTE operation
	} else {
		// if the operation is not recognized, deny access
		server_database[token_resource_access].tokens.validity--;
		return error_validate_delegated_action("OPERATION_NOT_PERMITTED", operation_type, accessed_resource, token_resource_access, server_database[token_resource_access].tokens.validity); 
	}

	// if the operation is permitted, return success

	// decrease the validity of the token
	server_database[token_resource_access].tokens.validity--;
	fout << "PERMIT (" << operation_type << "," << accessed_resource << "," << token_resource_access << "," << server_database[token_resource_access].tokens.validity << ")" << endl;
	
	result.error_message = new char[strlen(EMPTY) + 1];
	strcpy(result.error_message, EMPTY);
	result.success_message = new char[strlen("PERMISSION_GRANTED") + 1];
	strcpy(result.success_message, "PERMISSION_GRANTED");

	return &result;
}