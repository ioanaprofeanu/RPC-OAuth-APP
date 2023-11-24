/*
	Profeanu Ioana - 343C1
	Tema 1 SPRC
	- the file contains the server end-user emulation for
	token signing
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

// function for verifying the permissions and signing the token
// on behalf of the end user
reply_token_approval *
func_token_approval_1_svc(request_token_approval arg1,  struct svc_req *rqstp)
{
	static reply_token_approval result;
	string token_authorize_access = arg1.token_authorize_access;
	
	// parse the current line inside the waitlist permissions queue
	if (!waitlist_permissions.empty()) {
		// get the current permission request from the queue
		istringstream current_permissions(waitlist_permissions.front());
		waitlist_permissions.pop();

		// extract the pairs of resource name and permissions from
		// the current permission request
		string resource_name, permissions;
		while (getline(current_permissions, resource_name, ',')) {
			getline(current_permissions, permissions, ',');
			// check if the resource is in the database
			auto it = find(resources.begin(), resources.end(), resource_name);
			if (it != resources.end()) {
				// iterate through each letter representing a permission
				// and update the database entry which has the token
				// authorization access as key
				for (char current_permission : permissions) {
					switch (current_permission) {
						case 'R':
							server_database[token_authorize_access].
							permissionsResources[resource_name].Read = true;
							break;
						case 'I':
							server_database[token_authorize_access].
							permissionsResources[resource_name].Insert = true;
							break;
						case 'M':
							server_database[token_authorize_access].
							permissionsResources[resource_name].Modify = true;
							break;
						case 'D':
							server_database[token_authorize_access].
							permissionsResources[resource_name].Delete = true;
							break;
						case 'X':
							server_database[token_authorize_access].
							permissionsResources[resource_name].Execute = true;
							break;
						default:
							break;
					}
				}
			} else if (resource_name == "*" && permissions == "-") {
				// if the user does not approve the access to any resource,
				// return the authorization token unsigned
				result.token_authorize_access_signed =
					strdup(token_authorize_access.c_str());
				return &result;
			}
		}
	}

	// sign the token because the user approved the access
	// to at least one resource
	string signed_token_authorize_access =
		SIGNATURE + token_authorize_access;
	result.token_authorize_access_signed =
		strdup(signed_token_authorize_access.c_str());
	return &result;
}