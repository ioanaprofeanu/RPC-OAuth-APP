CC = gcc
CXX = g++
CFLAGS = -I/usr/include/tirpc -g -O0
LDFLAGS = -lnsl -ltirpc

all: rpc_auth_app_server rpc_auth_app_client

rpc_auth_app_server: rpc_auth_app_svc.o rpc_auth_app_authorization_server.o rpc_auth_app_signature_user.o rpc_auth_app_validate_action_server.o rpc_auth_app_xdr.o rpc_server_database.o
	$(CXX) -o rpc_auth_app_server $^ $(LDFLAGS)

rpc_auth_app_client: rpc_auth_app_clnt.o rpc_auth_app_client.o rpc_auth_app_xdr.o rpc_client_commands.o
	$(CXX) -o rpc_auth_app_client $^ $(LDFLAGS)

rpc_auth_app_svc.o: rpc_auth_app_svc.cpp
	$(CXX) $(CFLAGS) -c $<

# rpc_auth_app_server.o: rpc_auth_app_server.cpp
# 	$(CXX) $(CFLAGS) -c $<
rpc_auth_app_authorization_server.o: rpc_auth_app_authorization_server.cpp
	$(CXX) $(CFLAGS) -c $<

rpc_auth_app_signature_user.o: rpc_auth_app_signature_user.cpp
	$(CXX) $(CFLAGS) -c $<

rpc_auth_app_validate_action_server.o: rpc_auth_app_validate_action_server.cpp
	$(CXX) $(CFLAGS) -c $<

rpc_auth_app_clnt.o: rpc_auth_app_clnt.c
	$(CC) $(CFLAGS) -c $<

rpc_auth_app_client.o: rpc_auth_app_client.cpp
	$(CXX) $(CFLAGS) -c $<

rpc_auth_app_xdr.o: rpc_auth_app_xdr.c
	$(CC) $(CFLAGS) -c $<

rpc_server_database.o: rpc_server_database.cpp
	$(CXX) $(CFLAGS) -c $<

rpc_client_commands.o: rpc_client_commands.cpp
	$(CXX) $(CFLAGS) -c $<

clean:
	rm -f *.o rpc_auth_app_server rpc_auth_app_client
