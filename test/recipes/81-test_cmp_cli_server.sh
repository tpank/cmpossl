#!/bin/bash
export DATA_DIR=./test/recipes/65-test_cmp_client_data
export LOACAL_PORT_NUMBER=7000

# start CMP HTTP server in background
apps/openssl cmp -port $LOACAL_PORT_NUMBER \
    -srv_cert $DATA_DIR/server.crt -srv_key $DATA_DIR/server.key \
	-accept_unprotected -rsp_cert $DATA_DIR/client.crt \
	-certout /tmp/newcert.crt &

apps/openssl cmp -server localhost:$LOACAL_PORT_NUMBER -cmd ir \
    -cert $DATA_DIR/client.crt -key $DATA_DIR/client.key \
    -certout /tmp/newcert.crt -trusted $DATA_DIR/server.crt \
    -unprotectedrequests -unprotectederrors -no_check_time	
    
# cleanup
killall openssl

# start CMP HTTP server in background
apps/openssl cmp -port $LOACAL_PORT_NUMBER \
    -srv_cert $DATA_DIR/server.crt -srv_key $DATA_DIR/server.key \
	-accept_unprotected -rsp_cert $DATA_DIR/client.crt \
	-certout /tmp/newcert.crt -poll_count 3 -checkafter 2 &

apps/openssl cmp -server localhost:$LOACAL_PORT_NUMBER -cmd ir \
    -cert $DATA_DIR/client.crt -key $DATA_DIR/client.key \
    -certout /tmp/newcert.crt -trusted $DATA_DIR/server.crt \
    -unprotectedrequests -unprotectederrors -no_check_time	
    
# cleanup
killall openssl