#!/bin/bash
#
# This is a convenience script that generates a self-signed certificate
# that by default is valid for 3650 days. Adjust the variable below to
# change this.
DAYS=3650
#
if [ "x$1" == "x" ] ; then
	HOST=`hostname`
else
	HOST=$1
fi

OUTCER=`echo -n $HOST ; echo -n "_cert.pem"`
OUTKEY=`echo -n $HOST ; echo -n ".key"`

cat > /tmp/tmp-ssl-eemo.cnf <<EOF
[req]
distinguished_name	= req_dn
encrypt_key		= no
prompt			= no
string_mask		= nombstr

[req_dn]
commonName		= $HOST
EOF

# Generate the certificate
openssl req -nodes -newkey rsa:2048 -new -x509 -keyout $OUTKEY -out $OUTCER -days $DAYS -config /tmp/tmp-ssl-eemo.cnf

if [ $? -ne 0 ] ; then
	echo "An error occurred while producing the new certificate"
	rm /tmp/tmp-key
	exit $?
fi

echo "New certificate: $OUTCER"
echo "Key is in: $OUTKEY"

rm -rf /tmp/tmp-ssl-eemo.cnf
