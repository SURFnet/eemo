#!/bin/bash
#
# This is a convenience script that generates a self-signed certificate
# that by default is valid for 365 days. Adjust the variable below to
# change this.
DAYS=365
#
# The certificate will be output as eemo_self_signed.cer in PEM format,
# the key will be output as eemo_self_signed.key, also in PEM format.
# Change the variable below to use a different name.
OUTCER="eemo_self_signed.cer"
OUTKEY="eemo_self_signed.key"

# Start by generating a key
echo "Temporary passphrase" > /tmp/tmp-pf

openssl genrsa -out /tmp/tmp-key 2048

if [ $? -ne 0 ] ; then
	echo "An error occurred while generating a new key"
	exit $?
fi

# Generate the CSR
echo "Please complete the requested fields; specify the server name as CN"

openssl req -new -key /tmp/tmp-key -out /tmp/tmp-csr

if [ $? -ne 0 ] ; then
	echo "An error occurred while producing a CSR"
	rm /tmp/tmp-key
	exit $?
fi

# Produce the certificate
openssl x509 -req -days $DAYS -in /tmp/tmp-csr -signkey /tmp/tmp-key -out /tmp/tmp-crt

if [ $? -ne 0 ] ; then
	echo "An error occurred while producing the certificate"
else
	mv /tmp/tmp-key $OUTKEY
	mv /tmp/tmp-crt $OUTCER
fi

rm -rf /tmp/tmp-key /tmp/tmp-crt /tmp/tmp-csr
