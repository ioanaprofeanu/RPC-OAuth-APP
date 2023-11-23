/*
 *  de modificat de facut cpp
 */

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

reply_authorization *
func_authorization_1_svc(request_authorization arg1,  struct svc_req *rqstp)
{
	static reply_authorization result;
	
	string user_id = arg1.userID;
	fout << "BEGIN " << user_id << " AUTHZ" << endl;
	
	// check if the user is in the database
	auto it = usersID_active_tokens.find(user_id);
    if (it != usersID_active_tokens.end()) {
		// if a token is already active for the user, delete it from the database
		if (usersID_active_tokens[user_id] != EMPTY) {
			server_database.erase(usersID_active_tokens[user_id]);
			usersID_active_tokens[user_id] = EMPTY;
		}
        // if the user is found, generate token
		char* user_id_char = strdup(user_id.c_str());
		char* token_authorize_access = generate_access_token(user_id_char);
		string token_authorize_access_string(token_authorize_access);

		// TODO asta poate fac doar dupa daca semnez token ul?
		// update the user's token - the current active token will be the authorization token
		usersID_active_tokens[user_id] = token_authorize_access_string;
		// update the database - add the new token and the current active token is the authorization token
		Database_Value new_database_value = initialize_server_database_entry(token_authorize_access_string);
		server_database[token_authorize_access_string] = new_database_value;

		// add token to result
		result.token_authorize_access = strdup(token_authorize_access);
		result.error_message = strdup("");

		fout << "  RequestToken = " << token_authorize_access_string << endl;
    } else {
		// if the user is not found, return error
        result.error_message = new char[strlen("USER_NOT_FOUND") + 1];
		strcpy(result.error_message, "USER_NOT_FOUND");
		result.token_authorize_access = new char[strlen(EMPTY) + 1];
		strcpy(result.token_authorize_access, EMPTY);
    }

	return &result;
}

reply_access_token *
func_access_token_1_svc(request_access_token arg1,  struct svc_req *rqstp)
{
	static reply_access_token  result;

	string signed_token_authorize_access = arg1.token_authorize_access_signed;
	string user_id = arg1.userID;
	int use_refresh_token = arg1.use_refresh_token;

	// check if the token is signed
	if (signed_token_authorize_access.compare(0, sizeof(SIGNATURE) - 1, SIGNATURE) == 0) {
		// extract the unsigned token
		string unsigned_authorization_token = signed_token_authorize_access.substr(sizeof(SIGNATURE) - 1);
		// check if the unsigned token is the current active token
		if (unsigned_authorization_token == usersID_active_tokens[user_id]) {
			// if the token is signed and corresponds to the user, generate access token
			char* unsigned_authorization_token_char = strdup(unsigned_authorization_token.c_str());
			char* token_resource_access = generate_access_token(unsigned_authorization_token_char);
			string token_resource_access_string(token_resource_access);
			fout << "  AccessToken = " << token_resource_access_string << endl;
			
			// generate refresh token, if requested
			char* token_refresh = new char[1]{ '\0' };
			if (use_refresh_token == 1) {
				// if the user wants to use the refresh token
				char* token_resource_access_string_char = strdup(token_resource_access_string.c_str());
				token_refresh = generate_access_token(&token_resource_access_string_char[0]);
				fout << "  RefreshToken = " << token_refresh << endl;
			}
			string token_refresh_string(token_refresh);

			// update the database
			usersID_active_tokens[user_id] = token_resource_access_string;
			server_database[token_resource_access_string] = server_database[unsigned_authorization_token];
			server_database[token_resource_access_string].tokens.token_resource_access = token_resource_access_string;
			server_database[token_resource_access_string].tokens.token_refresh = token_refresh_string;
			server_database[token_resource_access_string].tokens.validity = token_validity;
			server_database.erase(unsigned_authorization_token);
		
			result.token_resource_access = strdup(token_resource_access);
			result.token_refresh = strdup(token_refresh);
			result.error_message = strdup("");
			result.validity = token_validity;
		}
    } else {
		// if the token is not signed, deny access
        result.error_message = new char[strlen("REQUEST_DENIED") + 1];
		strcpy(result.error_message, "REQUEST_DENIED");
		result.token_refresh = new char[strlen(EMPTY) + 1];
		strcpy(result.token_refresh, EMPTY);
		result.token_resource_access = new char[strlen(EMPTY) + 1];
		strcpy(result.token_resource_access, EMPTY);
		result.validity = 0;
    }
	return &result;
}

reply_access_token *
func_renew_access_token_1_svc(request_renew_access_token arg1,  struct svc_req *rqstp)
{
	static reply_access_token  result;

	string token_resource_access_expired = arg1.token_resource_access_expired;
	string refresh_token = server_database[token_resource_access_expired].tokens.token_refresh;
	string user_id = "";
	// find in usersID_active_tokens, the key that has the value equal to token_resource_access_expired
	for (const auto& pair : usersID_active_tokens) {
        if (pair.second == token_resource_access_expired) {
            user_id = pair.first; // Return the key when a match is found
        }
    }

	if (user_id == "") {
		result.error_message = new char[strlen("REQUEST_DENIED") + 1];
		strcpy(result.error_message, "REQUEST_DENIED");
		result.token_refresh = new char[strlen(EMPTY) + 1];
		strcpy(result.token_refresh, EMPTY);
		result.token_resource_access = new char[strlen(EMPTY) + 1];
		strcpy(result.token_resource_access, EMPTY);
		result.validity = 0;
		return &result;
	}

	fout << "BEGIN " << user_id << " AUTHZ REFRESH" << endl;

	// if the given expired token corresponds to the user
		
	// check if the user has requested a refresh token when he first asked for the access token
	if (refresh_token != EMPTY) {
		// generate new access token and new refresh token
		char* refresh_token_char = strdup(refresh_token.c_str());
		char* new_token_resource_access = generate_access_token(refresh_token_char);
		string new_token_resource_access_string(new_token_resource_access);
		fout << "  AccessToken = " << new_token_resource_access_string << endl;

		char* new_token_refresh = generate_access_token(new_token_resource_access);
		string new_token_refresh_string(new_token_refresh);
		fout << "  RefreshToken = " << new_token_refresh_string << endl;

		// update the database
		usersID_active_tokens[user_id] = new_token_resource_access_string;
		server_database[new_token_resource_access_string] = server_database[token_resource_access_expired];
		server_database[new_token_resource_access_string].tokens.token_resource_access = new_token_resource_access_string;
		server_database[new_token_resource_access_string].tokens.token_refresh = new_token_refresh_string;
		server_database[new_token_resource_access_string].tokens.validity = token_validity;
		server_database.erase(token_resource_access_expired);

		// return the new access token and the new refresh token
		result.token_resource_access = strdup(new_token_resource_access);
		result.token_refresh = strdup(new_token_refresh);
		result.error_message = strdup("");
		result.validity = token_validity;
	} else {
		result.error_message = new char[strlen("REQUEST_DENIED") + 1];
		strcpy(result.error_message, "REQUEST_DENIED");
		result.token_refresh = new char[strlen(EMPTY) + 1];
		strcpy(result.token_refresh, EMPTY);
		result.token_resource_access = new char[strlen(EMPTY) + 1];
		strcpy(result.token_resource_access, EMPTY);
		result.validity = 0;
	}
	
	return &result;
}
