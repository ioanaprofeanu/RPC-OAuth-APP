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

reply_token_approval *
func_token_approval_1_svc(request_token_approval arg1,  struct svc_req *rqstp)
{
	static reply_token_approval result;
	string token_authorize_access = arg1.token_authorize_access;
	
	// iau linia curenta din approvals si o parsez
	if (!waitlist_permissions.empty()) {
		// get the current permission request from the queue
		istringstream current_permissions(waitlist_permissions.front());
		waitlist_permissions.pop();

		string resource_name, permissions;
		while (getline(current_permissions, resource_name, ',')) {
			getline(current_permissions, permissions, ',');
			// check if the resource is in the database
			auto it = find(resources.begin(), resources.end(), resource_name);
			if (it != resources.end()) {
				for (char current_permission : permissions) {
					switch (current_permission) {
						case 'R':
							server_database[token_authorize_access].permissionsResources[resource_name].Read = true;
							break;
						case 'I':
							server_database[token_authorize_access].permissionsResources[resource_name].Insert = true;
							break;
						case 'M':
							server_database[token_authorize_access].permissionsResources[resource_name].Modify = true;
							break;
						case 'D':
							server_database[token_authorize_access].permissionsResources[resource_name].Delete = true;
							break;
						case 'X':
							server_database[token_authorize_access].permissionsResources[resource_name].Execute = true;
							break;
						default:
							break;
					}
				}
			} else if (resource_name == "*" && permissions == "-") {
				// if the user does not approve the access to any resource,
				// return the authorization token unsigned
				result.token_authorize_access_signed = strdup(token_authorize_access.c_str());
				return &result;
			}
		}
	}

	// sign the token because the user approved the access to at least one resource
	string signed_token_authorize_access = "SIGNED_" + token_authorize_access;
	result.token_authorize_access_signed = strdup(signed_token_authorize_access.c_str());
	return &result;
}