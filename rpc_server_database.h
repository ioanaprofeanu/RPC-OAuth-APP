#ifndef RPC_SERVER_DATABASE_H
#define RPC_SERVER_DATABASE_H

#include <iostream>
#include <fstream>
#include <unordered_map>
#include "server_utils.h"
#include <vector>
#include <queue>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>

#define TOKEN_LEN 15

// Unordered map for users id and their current active token
extern std::unordered_map<std::string, std::string> usersID_active_tokens;
// Unordered map for current token, permissions for each resource and all tokens
extern std::unordered_map<std::string, Database_Value> server_database;
// vector of all resources
extern std::vector<std::string> resources;
// queue with the permissions that are waiting for approval
extern std::queue<std::string> waitlist_permissions;
extern int num_users;
extern int num_resources;
extern int token_validity;
extern std::ofstream fout;

/**
 * generate alpha-numeric string based on random char*
 * 
 * INPUT: fixed length of 16
 * OUTPUT: rotated string
 * */
char* generate_access_token(char* clientIdToken);

// functie citire date din fisiere
void read_usersIDs(const std::string& filename);
void read_resources(const std::string& filename);
void read_permissions(const std::string& filename);

// functie de initializat o intrare in baza de date cu valori default
Database_Value initialize_server_database_entry(std::string new_token_authorize_access);

#endif // RPC_SERVER_DATABASE_H