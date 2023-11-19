CC = g++
CFLAGS = -I/usr/include/tirpc -g -O0
LDFLAGS = -lnsl -ltirpc

all: rpc_auth_app_server rpc_auth_app_client

rpc_auth_app_server: rpc_auth_app_svc.o rpc_auth_app_server.o rpc_auth_app_xdr.o rpc_server_database.o
	$(CC) -o rpc_auth_app_server $^ $(LDFLAGS)

rpc_auth_app_client: rpc_auth_app_clnt.o rpc_auth_app_client.o rpc_auth_app_xdr.o
	$(CC) -o rpc_auth_app_client $^ $(LDFLAGS)

rpc_auth_app_svc.o: rpc_auth_app_svc.c
	$(CC) $(CFLAGS) -c $<

rpc_auth_app_server.o: rpc_auth_app_server.cpp
	$(CC) $(CFLAGS) -c $<

rpc_auth_app_clnt.o: rpc_auth_app_clnt.c
	$(CC) $(CFLAGS) -c $<

rpc_auth_app_client.o: rpc_auth_app_client.cpp
	$(CC) $(CFLAGS) -c $<

rpc_auth_app_xdr.o: rpc_auth_app_xdr.c
	$(CC) $(CFLAGS) -c $<

rpc_server_database.o: rpc_server_database.cpp
	$(CC) $(CFLAGS) -c $<

clean:
	rm -f *.o rpc_auth_app_server rpc_auth_app_client
