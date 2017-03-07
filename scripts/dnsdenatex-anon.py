#!/usr/bin/env python2.7
#
# This script anonymises the output of the dnsdenatex plugin. It takes three
# input parameters:
#
# 1) the name of the input CSV file from the dnsdenatex plugin
# 2) the name of the output CSV file from the dnsdenatex plugin
# 3) a random string that is to be used as salt for the hash

import os
import sys
import hashlib

def anonymise_dnsdenatex(in_csv, out_csv, salt):
	in_fd = open(in_csv, 'r')
	out_fd = open(out_csv, 'w')

	field_count = 0

	header = in_fd.readline()

	header = header.strip('\n')
	header = header.strip('\r')

	if header == 'timestamp,client_ip,ip_ipid,ip_ttl,udp_srcport,dns_qid,dns_qtype,dns_qclass,dns_qname,dns_edns0,dns_edns0_do,dns_edns0_maxsize':
		field_count = 12
		print 'This is a file containing queries'
	elif header == 'timestamp,client_ip,ip_ipid,ip_ttl,udp_dstport,dns_qid,dns_qtype,dns_qclass,dns_qname,first_response_ttl,dns_edns0,dns_edns0_do,dns_edns0_maxsize':
		field_count = 13
		print 'This is a file containing responses'
	else:
		print 'Invalid CSV header in {}'.format(in_csv)
		in_fd.close()
		out_fd.close()
		sys.exit(1)

	out_fd.write('{}\n'.format(header))

	line_ct = 0

	# fields[1] = client_ip
	client_ip_index = 1
	# fields[8] = qname
	qname_index = 8
	#
	for line in in_fd:
		line = line.strip('\n')
		line = line.strip('\r')

		fields = line.split(',')

		if len(fields) != field_count :
			print 'Line {} has an invalid number of fields ({} != {}), skipping'.format(line_ct + 2, len(fields), field_count)
			continue

		# Initialise hash
		md = hashlib.sha256()

		# Add a pinch of salt
		md.update(salt)

		# Anonymise the source IP
		md.update(fields[client_ip_index])
		fields[client_ip_index] = md.hexdigest()

		# Anonymise the query name; not clearing the hash object
		# ensures that query names from other source IPs cannot
		# be matched to the same hash value
		md.update(fields[qname_index])
		fields[qname_index] = md.hexdigest()

		out_fd.write('{}\n'.format(','.join(fields)))

		line_ct += 1

	print 'Anonymised {} entries'.format(line_ct)

	in_fd.close()
	out_fd.close()

def main():
	if len(sys.argv) != 4:
		print 'Unexpected number of command-line arguments ({})'.format(len(sys.argv))
		sys.exit(1)

	in_csv = sys.argv[1]
	out_csv = sys.argv[2]
	salt = sys.argv[3]

	print 'Reading from {}'.format(in_csv)
	print 'Writing to {}'.format(out_csv)
	print 'Using the following salt: "{}"'.format(salt)

	anonymise_dnsdenatex(in_csv, out_csv, salt)

	return

if __name__ == "__main__":
	main()
