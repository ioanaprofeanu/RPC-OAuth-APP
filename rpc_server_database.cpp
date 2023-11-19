#include <iostream>
#include <fstream>
#include <string>
#include <unordered_map>
#include "server_utils.h"
#include <vector>
#include <queue>
#include "rpc_server_database.h"
using namespace std;

// Unordered map for users id and their current active token
unordered_map<string, string> usersID_active_tokens;
// Unordered map for current token, permissions for each resource and all tokens
unordered_map<string, Database_Value> server_database;
// vector of all resources
vector<string> resources;
// queue with the permissions that are waiting for approval
queue<string> waitlist_permissions;
int num_users, num_resources;

void read_usersIDs(const string& filename) {
    ifstream file(filename);
    
    if (!file.is_open()) {
        cerr << "Error: Unable to open file " << filename << endl;
        return;
    }

    string line;
    
    // Read the number of users from the first line
    if (getline(file, line)) {
        try {
            num_users = stoi(line);
        } catch (const invalid_argument& e) {
            cerr << "Error: Invalid number of users in file " << filename << endl;
            return;
        }
    } else {
        cerr << "Error: Empty file " << filename << endl;
        return;
    }

    // Read user IDs and add them to the map
    for (int i = 0; i < num_users && getline(file, line); i++) {
        usersID_active_tokens[line] = "";
    }

    file.close();
}

void read_resources(const string& filename) {
    ifstream file(filename);

    if (!file.is_open()) {
        cerr << "Error: Unable to open file " << filename << endl;
        return;
    }

    string line;

    // Read the number of resources from the first line
    if (getline(file, line)) {
        try {
            num_resources = stoi(line);
        } catch (const invalid_argument& e) {
            cerr << "Error: Invalid number of resources in file " << filename << endl;
            return;
        }
    } else {
        cerr << "Error: Empty file " << filename << endl;
        return;
    }

    // Read resource names and add them to the vector
    resources.clear();  // Clear existing resources
    for (int i = 0; i < num_resources && getline(file, line); i++) {
        resources.push_back(line);
    }

    file.close();
}

void read_permissions(const string& filename) {
    ifstream file(filename);

    if (!file.is_open()) {
        cerr << "Error: Unable to open file " << filename << endl;
        return;
    }

    string line;

    // Clear the queue
    while (!waitlist_permissions.empty()) {
        waitlist_permissions.pop();
    }

    // Read all lines until the end of the file
    while (getline(file, line)) {
        waitlist_permissions.push(line);
    }

    file.close();
}

// function for initializing a database entry with default values
// the new authorization token is passed as a parameter
Database_Value initialize_server_database_entry(string new_token_authorize_access)
{
	Database_Value entry;
	Permissions_Resources permissionsResources;
	Tokens tokens;

	// initialize tokens to empty string
	tokens.token_authorize_access = new_token_authorize_access;
	tokens.token_resource_access = NO_TOKEN;
	tokens.token_refresh = NO_TOKEN;
	tokens.validity = 0;

	// for each resource, initialize permissions to false
	for (int i = 0; i < num_resources; i++) {
		Permissions permissions;
		permissions.Read = false;
		permissions.Insert = false;
		permissions.Modify = false;
		permissions.Delete = false;
		permissions.Execute = false;
		permissionsResources[resources[i]] = permissions;
	}
	entry.permissionsResources = permissionsResources;
	entry.tokens = tokens;
	return entry;
}