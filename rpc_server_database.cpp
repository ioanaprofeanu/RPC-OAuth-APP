/*
	Profeanu Ioana - 343C1
	Tema 1 SPRC
	- the file contains the functions which are used by the server
	to modify the database
*/

#include <iostream>
#include <fstream>
#include <string>
#include <unordered_map>
#include "rpc_server_utils.h"
#include <vector>
#include <queue>
#include "rpc_server_database.h"
using namespace std;

// unordered map for users id and their current active token
unordered_map<string, string> usersID_active_tokens;
// unordered map for current token, permissions
// for each resource and all tokens
unordered_map<string, Database_Value> server_database;
// vector of all resources
vector<string> resources;
// queue with the permissions that are waiting for approval
queue<string> waitlist_permissions;
int num_users, num_resources, token_validity;
ofstream fout("server.out");

/**
 * generate alpha-numeric string based on random char*
 * 
 * INPUT: fixed length of 16
 * OUTPUT: rotated string
 * */
char* generate_access_token(char* clientIdToken) {
    char *token = (char *)malloc(TOKEN_LEN * sizeof(char*));
    int i, key, used[TOKEN_LEN];
    int rotationIndex = TOKEN_LEN;

    memset(used, 0, TOKEN_LEN * sizeof(int));
    for (i = 0; i < TOKEN_LEN; i++) {
        do {
            key = rand() % rotationIndex;
        } while (used[key] == 1);
        token[i] = clientIdToken[key];
        used[key] = 1;
    }
    token[TOKEN_LEN] = '\0';
    return token;
}

// functions for reading the user id's from file
void read_usersIDs(const string& filename) {
    ifstream file(filename);
    
    if (!file.is_open()) {
        cerr << "Unable to open file: " << filename << endl;
        return;
    }

    string line;
    
    // Read the number of users from the first line
    if (getline(file, line)) {
        try {
            num_users = stoi(line);
        } catch (const invalid_argument& e) {
            cerr << "Invalid number of users." << endl;
            return;
        }
    } else {
        cerr << "Empty file." << endl;
        return;
    }

    // read the user id's and add them to the unordered map of
	// users id and their current active token
    for (int i = 0; i < num_users && getline(file, line); i++) {
		// initialize the user's active token to empty string
        usersID_active_tokens[line] = EMPTY;
    }

    file.close();
}

// function for reading the resources from file
void read_resources(const string& filename) {
    ifstream file(filename);

    if (!file.is_open()) {
        cerr << "Unable to open file:" << filename << endl;
        return;
    }

    string line;

    // Read the number of resources from the first line
    if (getline(file, line)) {
        try {
            num_resources = stoi(line);
        } catch (const invalid_argument& e) {
            cerr << "Invalid number of resources." << endl;
            return;
        }
    } else {
        cerr << "Empty file." << endl;
        return;
    }

    // Read resource names and add them to the vector
    resources.clear();
    for (int i = 0; i < num_resources && getline(file, line); i++) {
        resources.push_back(line);
    }

    file.close();
}

// function for reading the permissions from file
void read_permissions(const string& filename) {
    ifstream file(filename);

    if (!file.is_open()) {
        cerr << "Unable to open file: " << filename << endl;
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
Database_Value initialize_server_database_entry
	(string new_token_authorize_access)
{
	Database_Value entry;
	Permissions_Resources permissionsResources;
	Tokens tokens;

	// initialize tokens to empty string
	tokens.token_authorize_access = new_token_authorize_access;
	tokens.token_resource_access = EMPTY;
	tokens.token_refresh = EMPTY;
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