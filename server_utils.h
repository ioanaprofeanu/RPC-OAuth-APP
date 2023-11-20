#ifndef SERVER_UTILS_H
#define SERVER_UTILS_H

#include <unordered_map>
#include <string>

// Structure for permissions
struct Permissions {
    bool Read;
    bool Insert;
    bool Modify;
    bool Delete;
    bool Execute;
};

// Structure for tokens
struct Tokens {
    std::string token_authorize_access;
    std::string token_resource_access;
    std::string token_refresh;
    int validity;
};

// Unordered map for Permissions with resource names
using Permissions_Resources = std::unordered_map<std::string, Permissions>;

// Structure for the value
struct Database_Value {
    Permissions_Resources permissionsResources;
    Tokens tokens;
};

#define EMPTY ""
#define SIGNATURE "SIGNED_"

#endif // SERVER_UTILS_H