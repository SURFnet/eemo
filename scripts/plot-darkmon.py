#!/usr/bin/env python

import matplotlib
matplotlib.use('SVG')

import matplotlib.patches as mpatches
import matplotlib.pyplot as pp
import json
import sys
import datetime
import time

def dt_to_epoch(timestamp):
	return int(time.mktime(timestamp.timetuple()))

def ts_to_top_ts(csv_dir, from_time, x):
	udp_dict = dict()
	tcp_dict = dict()

	# Start by generating the timestamps of the hourly epoch files to read
	hour_ts = []

	start_hour = int(dt_to_epoch(from_time) / 3600) * 3600
	start_hour -= 86400
	end_ts = dt_to_epoch(from_time)
	start_ts = end_ts - 86400
	cur_hour = start_hour

	while cur_hour < end_ts:
		hour_ts.append(cur_hour)
		cur_hour += 3600

	# Read date from individual hour files
	for hour in hour_ts:
		hour_name = '{}/darknet_{}.csv'.format(csv_dir, hour)

		try:
			hour_file = open(hour_name, 'r')

			print 'Reading data from hour file {}'.format(hour_name)

			line_no = 0
			read_count = 0

			for line in hour_file:
				line_no += 1

				try:
					json_data = json.loads(line)

					if int(json_data['timestamp']) >= start_ts and \
					   int(json_data['timestamp']) <= end_ts:
						for udp_datum in json_data['udp']:
							port = udp_datum['port']
							seen = udp_datum['seen_count']
				
							current_seen = udp_dict.get(port, 0)
							current_seen += seen
				
							udp_dict[port] = current_seen

						for tcp_datum in json_data['tcp']:
							port = tcp_datum['port']
							seen = tcp_datum['seen_count']
				
							current_seen = tcp_dict.get(port, 0)
							current_seen += seen
				
							tcp_dict[port] = current_seen

						read_count += 1
				except:
					print 'JSON parse error on line {}'.format(line_no)

			hour_file.close()

			print 'Processed {} entries from {}'.format(read_count, hour_name)
		except:
			print 'Could not open hour file {} for reading, skipping'.format(hour_name)

	udp_tuples = []
	tcp_tuples = []

	for port in udp_dict.keys():
		udp_tuples.append((port, udp_dict[port]))

	for port in tcp_dict.keys():
		tcp_tuples.append((port, tcp_dict[port]))

	udp_tuples.sort(key=lambda tup: tup[1])
	tcp_tuples.sort(key=lambda tup: tup[1])

	udp_tuples.reverse()
	tcp_tuples.reverse()

	# Cut to top x
	top_udp_list = []
	top_tcp_list = []

	for i in range(0, x):
		top_udp_list.append(udp_tuples[i][0])
		top_tcp_list.append(tcp_tuples[i][0])

	print 'Top UDP ports over period: {}'.format(top_udp_list)
	print 'Top TCP ports over period: {}'.format(top_tcp_list)

	udp_ts = []
	tcp_ts = []

	for i in range(0, x):
		udp_ts.append([])
		tcp_ts.append([])

	timestamps = []

	# Read date from individual hour files
	for hour in hour_ts:
		hour_name = '{}/darknet_{}.csv'.format(csv_dir, hour)

		try:
			hour_file = open(hour_name, 'r')

			print 'Reading data from hour file {}'.format(hour_name)

			line_no = 0
			read_count = 0

			for line in hour_file:
				line_no += 1

				try:
					json_data = json.loads(line)

					if int(json_data['timestamp']) >= start_ts and \
					   int(json_data['timestamp']) <= end_ts:
						timestamps.append(datetime.datetime.fromtimestamp(json_data['timestamp']))

						for i in range(0, x):
							udp_seen_count = 0
							tcp_seen_count = 0
				
							for udp_datum in json_data['udp']:
								if udp_datum['port'] == top_udp_list[i]:
									udp_seen_count = udp_datum['seen_count']
				
							for tcp_datum in json_data['tcp']:
								if tcp_datum['port'] == top_tcp_list[i]:
									tcp_seen_count = tcp_datum['seen_count']
				
							udp_ts[i].append(udp_seen_count)
							tcp_ts[i].append(tcp_seen_count)

						read_count += 1
				except:
					print 'JSON parse error on line {}'.format(line_no)

			hour_file.close()

			print 'Processed {} entries from {}'.format(read_count, hour_name)
		except:
			print 'Could not open hour file {} for reading, skipping'.format(hour_name)

	udp_tot_counts = []
	tcp_tot_counts = []
	udp_other = 0
	tcp_other = 0

	for i in range(0, x):
		udp_tot_counts.append(udp_tuples[i][1])
		tcp_tot_counts.append(tcp_tuples[i][1])

	if len(udp_tuples) > x:
		for i in range(x, len(udp_tuples)):
			udp_other += udp_tuples[i][1]

	if len(tcp_tuples) > x:
		for i in range(x, len(tcp_tuples)):
			tcp_other += tcp_tuples[i][1]

	return top_udp_list,top_tcp_list,timestamps,udp_ts,tcp_ts,udp_tot_counts,udp_other,tcp_tot_counts,tcp_other

plotcolors = ["#332288", "#88CCEE", "#44AA99", "#117733", "#999933", "#DDCC77", "#661100", "#CC6677", "#882255", "#AA4499", "#C0C0C0"]

def plot_ts(top_list, timestamps, ts, output_file):
	fig = pp.figure(figsize = (17, 4))

	plot_ax = pp.subplot2grid((1,17), (0, 0), colspan=15)

	plot_ax.stackplot(timestamps, ts, colors=plotcolors, edgecolor='none')
	plot_ax.grid(True)

	legend_patches = []
	legend_labels = []

	for i in range(0, len(top_list)):
		legend_patches.append(mpatches.Patch(color = plotcolors[i]))
		legend_labels.append('{}'.format(top_list[i]))

	#legend_patches.reverse()
	#legend_labels.reverse()

	legend_ax = pp.subplot2grid((1, 17), (0, 15), colspan=2)

	legend_ax.axis('off')
	legend_ax.legend(legend_patches, legend_labels, bbox_to_anchor=(0, 0, 1, 1), ncol=1, mode="expand", borderaxespad=0)

	pp.savefig(output_file)

def plot_port_pie(top_list, tot_counts, other, output_file):
	fig = pp.figure(figsize = (8, 6))

	legend_patches = []
	legend_labels = []

	for i in range(0, len(top_list)):
		legend_patches.append(mpatches.Patch(color = plotcolors[i]))
		legend_labels.append('{}'.format(top_list[i]))

	legend_patches.append(mpatches.Patch(color = "#C0C0C0"))
	legend_labels.append('other')

	plot_ax = pp.subplot2grid((4, 8), (0, 0), colspan=6, rowspan=4)

	tot_counts.append(other)

	plot_ax.pie(tot_counts, colors=plotcolors, autopct='%1.0f%%', shadow=False, pctdistance=1.1)

	legend_ax = pp.subplot2grid((4, 8), (0, 6), colspan=2, rowspan=4)

	legend_ax.axis('off')
	legend_ax.legend(legend_patches, legend_labels, ncol=1, mode="expand", borderaxespad=0, bbox_to_anchor=(0, 0, 1, 1), loc='center')

	pp.savefig(output_file)

def main():
	csv_dir = sys.argv[1]
	output_dir = sys.argv[2]

	now = datetime.datetime.now()

	print 'Processing data until {}'.format(now)
	print 'Reading input CSVs from {}'.format(csv_dir)

	top_udp_list, top_tcp_list, timestamps, udp_ts, tcp_ts, udp_tot_counts, udp_other, tcp_tot_counts, tcp_other  = ts_to_top_ts(csv_dir, now, 10)

	plot_ts(top_udp_list, timestamps, udp_ts, '{}/udp_timeseries.svg'.format(output_dir))
	plot_ts(top_tcp_list, timestamps, tcp_ts, '{}/tcp_timeseries.svg'.format(output_dir))

	plot_port_pie(top_udp_list, udp_tot_counts, udp_other, '{}/udp_distribution.svg'.format(output_dir))
	plot_port_pie(top_tcp_list, tcp_tot_counts, tcp_other, '{}/tcp_distribution.svg'.format(output_dir))

if __name__ == '__main__':
	main()
