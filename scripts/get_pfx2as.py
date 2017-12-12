#!/usr/bin/python

from bs4 import BeautifulSoup
import requests
import urllib2
import datetime
import dateutil.parser
import sys
import os

# CAIDA prefix-to-AS base URL for IPv4
caida_base_url_v4 = "http://data.caida.org/datasets/routing/routeviews-prefix2as/"

# CAIDA prefix-to-AS base URL for IPv6
caida_base_url_v6 = "http://data.caida.org/datasets/routing/routeviews6-prefix2as/"

def find_caida_data_url(dt, base_url):
	base_url	= "{}/{}/{:02d}".format(base_url, dt.year, dt.month)
	date_mask	= "{:04d}{:02d}{:02d}".format(dt.year, dt.month, dt.day)
	day_url		= None
	
	page = requests.get(base_url).text
	soup = BeautifulSoup(page, 'html.parser')

	for find_dayurl in [base_url + '/' + node.get('href') for node in soup.find_all('a') if node.get('href').endswith('pfx2as.gz')]:
		if find_dayurl.find(date_mask) >= 0:
			day_url = find_dayurl
			break

	if day_url is None:
		print "Unable to find day-specific URL for {}".format(dt.isoformat())

	return day_url

def download_file(file_url, store_as):
	# Retrieve file
	try:
		response = urllib2.urlopen(file_url)
	except:
		print "Failed to open URL {}".format(file_url)
		sys.exit(1)

	# Write file
	try:
		with open(store_as, 'w') as f:
			f.write(response.read())
	except:
		print "Failed to write to file {}".format(store_as)
		sys.exit(1)

def main():
	if len(sys.argv) != 2:
		print 'Expected one argument: the data to retrieve data for'
		sys.exit(1)

	day = dateutil.parser.parse(sys.argv[1]).date()

	print 'Retrieving data for {}...'.format(day)

	v4_url = find_caida_data_url(day, caida_base_url_v4)
	v6_url = find_caida_data_url(day, caida_base_url_v6)

	if v4_url is None or v6_url is None:
		print 'Could not find a download URL for one of the two datasets for this day, giving up!'
		sys.exit(1)

	v4_out = 'pfx2as-v4-{:04d}{:02d}{:02d}.gz'.format(day.year,day.month,day.day)
	v6_out = 'pfx2as-v6-{:04d}{:02d}{:02d}.gz'.format(day.year,day.month,day.day)

	print 'Downloading IPv4 data from {} to {}...'.format(v4_url, v4_out)

	download_file(v4_url, v4_out)

	print 'Downloading IPv6 data from {} to {}...'.format(v6_url, v6_out)

	download_file(v6_url, v6_out)

	print 'All done!'

if __name__ == "__main__":
	main()
