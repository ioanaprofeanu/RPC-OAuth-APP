/*
	Profeanu Ioana - 343C1
	Tema 1 SPRC
	- the header file contains the structures used by the server
*/
#ifndef RPC_SERVER_UTILS_H
#define RPC_SERVER_UTILS_H

#include <unordered_map>
#include <string>

// structure for permissions
struct Permissions {
    bool Read;
    bool Insert;
    bool Modify;
    bool Delete;
    bool Execute;
};

// structure for tokens
struct Tokens {
    std::string token_authorize_access;
    std::string token_resource_access;
    std::string token_refresh;
    int validity;
};

// unordered map for Permissions with resource names
using Permissions_Resources = std::unordered_map<std::string, Permissions>;

// structure for the value of the unordered map
struct Database_Value {
    Permissions_Resources permissionsResources;
    Tokens tokens;
};

#define EMPTY ""
#define SIGNATURE "SIGNED_"

#endif // RPC_SERVER_UTILS_H