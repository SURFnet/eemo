#include <stdio.h>
#include <pcap.h>
#include <string.h>
#include <stdlib.h>

#define ETHER_IP	0x0800
#define PROTO_UDP	0x0011
#define PROTO_TCP	

#define FLAG_SET(flags, flag) ((flags & flag) == flag)

/* IP header definition */
#define IP_VER(ver) ((ver & 0xf0) >> 4)
#define IP_HDRLEN(len) (len & 0x0f)

/* IPv4 header definition */
#define IPV4_DONTFRAG	0x4000
#define IPV4_MOREFRAG	0x2000
#define IPV4_FRAGMASK	0x1fff

typedef struct
{
	u_char		ip4_ver_hl;	/* header length + version */
	u_char		ip4_tos;	/* type-of-service */
	u_short		ip4_len;	/* total length */
	u_short		ip4_id;		/* packet ID */
	u_short		ip4_ofs;	/* fragment offset */
	u_char		ip4_ttl;	/* time-to-live */
	u_char		ip4_proto;	/* protocol */
	u_short		ip4_chksum;	/* packet checksum */
	u_char		ip4_src[4];	/* source address */
	u_char		ip4_dst[4];	/* destination address */
}
hdr_ipv4_t;

/* UDP header definition */
typedef struct
{
	u_short		udp_srcport;	/* source port */
	u_short		udp_dstport;	/* destination port */
	u_short		udp_len;	/* datagram length */
	u_short		udp_chksum;	/* UDP checksum */
}
hdr_udp_t;

/* DNS header definition */
#define DNS_QRFLAG	0x8000
#define DNS_AAFLAG	0x0400
#define DNS_TCFLAG	0x0200
#define DNS_RDFLAG	0x0100
#define DNS_RAFLAG	0x0080
#define DNS_OPCODE(flags) ((flags & 0x7800) >> 11)
#define DNS_RCODE(flags) (flags & 0x000f)

typedef struct
{
	u_short		dns_qid;	/* query ID */
	u_short		dns_flags;	/* flags field */
	u_short		dns_qdcount;	/* query count */
	u_short		dns_ancount;	/* answer count */
	u_short		dns_nscount;	/* authority count */
	u_short		dns_arcount;	/* additional count */
}
hdr_dns_t;

/* Convert IPv4 header from network byte order */
void hdr_ipv4_ntoh(hdr_ipv4_t* hdr)
{
	hdr->ip4_len 	= ntohs(hdr->ip4_len);
	hdr->ip4_id	= ntohs(hdr->ip4_id);
	hdr->ip4_ofs	= ntohs(hdr->ip4_ofs);
	hdr->ip4_chksum	= ntohs(hdr->ip4_chksum);
}

/* Convert UDP header from network byte order */
void hdr_udp_ntoh(hdr_udp_t* hdr)
{
	hdr->udp_srcport	= ntohs(hdr->udp_srcport);
	hdr->udp_dstport	= ntohs(hdr->udp_dstport);
	hdr->udp_len		= ntohs(hdr->udp_len);
	hdr->udp_chksum		= ntohs(hdr->udp_chksum);
}

/* Convert DNS header from network byte order */
void hdr_dns_ntoh(hdr_dns_t* hdr)
{
	hdr->dns_qid		= ntohs(hdr->dns_qid);
	hdr->dns_flags		= ntohs(hdr->dns_flags);
	hdr->dns_qdcount	= ntohs(hdr->dns_qdcount);
	hdr->dns_ancount	= ntohs(hdr->dns_ancount);
	hdr->dns_nscount	= ntohs(hdr->dns_nscount);
	hdr->dns_arcount	= ntohs(hdr->dns_arcount);
}

void printf_mac(u_char mac[6])
{
	int i = 0;

	printf("%02X", mac[i++]);

	for (; i < 6; i++)
	{
		printf(":%02X", mac[i]);
	}
}

void printf_ip4(u_char ip[4])
{
	printf("%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3]);
}

void printf_ip6(u_short ip[8])
{
	int i = 0;

	printf("%X", ip[i++]);

	for (; i < 8; i++)
	{
		printf(":%X", ip[i]);
	}
}

void process_dns_payload(const u_char* payload, int len)
{
	hdr_dns_t hdr;
	u_char* qdata = NULL;
	u_short qdatalen = 0;
	int i = 0;

	/* Check length */
	if (len < sizeof(hdr_dns_t))
	{
		fprintf(stderr, "Malformed DNS payload\n");
		return;
	}

	/* Take header and convert to host byte order */
	memcpy(&hdr, &payload[0], sizeof(hdr));
	hdr_dns_ntoh(&hdr);

	/* Print header data */
	printf("DNS query ID:         %d\n", hdr.dns_qid);
	printf("DNS flags:            0x%04X\n", hdr.dns_flags);
	printf("DNS QR:               %d\n", FLAG_SET(hdr.dns_flags, DNS_QRFLAG) ? 1 : 0);
	printf("DNS opcode:           %d\n", DNS_OPCODE(hdr.dns_flags));
	printf("DNS AA:               %d\n", FLAG_SET(hdr.dns_flags, DNS_AAFLAG) ? 1 : 0);
	printf("DNS TC:               %d\n", FLAG_SET(hdr.dns_flags, DNS_TCFLAG) ? 1 : 0);
	printf("DNS RD:               %d\n", FLAG_SET(hdr.dns_flags, DNS_RDFLAG) ? 1 : 0);
	printf("DNS RA:               %d\n", FLAG_SET(hdr.dns_flags, DNS_RAFLAG) ? 1 : 0);
	printf("DNS RCODE:            %d\n", DNS_RCODE(hdr.dns_flags));
	printf("DNS query count:      %d\n", hdr.dns_qdcount);
	printf("DNS answer count:     %d\n", hdr.dns_ancount);
	printf("DNS authority count:  %d\n", hdr.dns_nscount);
	printf("DNS additional count: %d\n", hdr.dns_arcount);

	if (!FLAG_SET(hdr.dns_flags, DNS_QRFLAG))
	{
		/* This is a query; check that it is sane */
		if (((DNS_OPCODE(hdr.dns_flags) != 0) && (DNS_OPCODE(hdr.dns_flags) != 1)) ||
		    FLAG_SET(hdr.dns_flags, DNS_AAFLAG) ||
		    FLAG_SET(hdr.dns_flags, DNS_TCFLAG) ||
		    FLAG_SET(hdr.dns_flags, DNS_RAFLAG) ||
		    (DNS_RCODE(hdr.dns_flags) != 0) ||
		    (hdr.dns_qdcount != 1) || /* according to Alan Clegg, *everybody* does it this way ;-) */
		    (hdr.dns_ancount > 0) ||
		    (hdr.dns_nscount > 0) ||
		    (hdr.dns_arcount > 1)) /* has to accept 1 for EDNS buffer size */
		{
			fprintf(stderr, "Malformed DNS query packet\n");
			return;
		}

		/* Retrieve all queries */
		while (hdr.dns_qdcount > 0)
		{
			int ofs = 0;
			int qnamelen = 0;
			char* qname = NULL;
			int qnameofs = 0;
			u_short qtype = 0;
			u_short qclass = 0;

			qdatalen = len - sizeof(hdr_dns_t);
			qdata = &payload[sizeof(hdr_dns_t)];

			/* Determine the length of the QNAME */
			do
			{
				if (qdata[ofs] == 0) break; /* root label reached */

				qnamelen += qdata[ofs] + 1;
				ofs += qdata[ofs];
			}
			while (++ofs < qdatalen);

			if (ofs >= qdatalen) break; /* parse error */

			/* Copy query name */
			ofs = 0;

			qnamelen++; /* added space for \0 */
			qname = (char*) malloc((qnamelen) * sizeof(char));
			memset(qname, 0, qnamelen);

			do
			{
				int elemLen = qdata[ofs++];

				if (elemLen == 0) break; /* root label reached */

				while ((elemLen > 0) && (ofs < qdatalen))
				{
					qname[qnameofs++] = qdata[ofs++];
					elemLen--;
				}

				qname[qnameofs++] = '.';
			}
			while (ofs < qdatalen);

			printf("DNS query name:       %s\n", qname);

			free(qname);

			/* Determine the query type and class */
			if ((qdatalen - ofs) < 4)
			{
				break;
			}

			memcpy(&qtype, &qdata[ofs], 2);
			ofs += 2;
			memcpy(&qclass, &qdata[ofs], 2);
			ofs += 2;
			qtype = ntohs(qtype);
			qclass = ntohs(qclass);

			printf("DNS query type:       %d\n", qtype);
			printf("DNS query class:      %d\n", qclass);

			hdr.dns_qdcount--;
		}

		if (hdr.dns_qdcount > 0)
		{
			fprintf(stderr, "DNS query parse error\n");
		}
	}
}

void process_raw_udp(const u_char* packet, int len)
{
	hdr_udp_t hdr;

	/* Check length */
	if (len < sizeof(hdr_udp_t))
	{
		fprintf(stderr, "Malformed UDP datagram\n");
		return;
	}

	/* Take header and convert to host byte order */
	memcpy(&hdr, &packet[0], sizeof(hdr));
	hdr_udp_ntoh(&hdr);

	/* Print header data */
	printf("UDP source port:      %d\n", hdr.udp_srcport);
	printf("UDP destination port: %d\n", hdr.udp_dstport);
	printf("UDP datagram length:  %d bytes\n", hdr.udp_len);
	printf("UDP checksum:         0x%04X\n", hdr.udp_chksum);

	/* See if we can print some more data */
	switch(hdr.udp_dstport)
	{
	case 53:
		/* DNS query */
		process_dns_payload(&packet[sizeof(hdr_udp_t)], len - sizeof(hdr_udp_t));
		break;
	default:
		printf("No further processing will be done on this packet\n");
		break;
	}
}

void process_raw_ipv4(const u_char* packet, int len)
{
	hdr_ipv4_t hdr;

	/* Check length */
	if (len < sizeof(hdr_ipv4_t))
	{
		fprintf(stderr, "Malformed IPv4 packet header\n");
		return;
	}

	/* Take header and convert to host byte order */
	memcpy(&hdr, &packet[0], sizeof(hdr));
	hdr_ipv4_ntoh(&hdr);

	/* Print header data */
	printf("IPv4 header length:       %d bytes\n", IP_HDRLEN(hdr.ip4_ver_hl));
	printf("IPv4 type of service:     %d\n", hdr.ip4_tos);
	printf("IPv4 datagram length:     %d bytes\n", hdr.ip4_len);
	printf("IPv4 datagram ID:         0x%04X\n", hdr.ip4_id);
	printf("IPv4 fragment offset:     %d\n", hdr.ip4_ofs & IPV4_FRAGMASK);
	if (FLAG_SET(hdr.ip4_ofs, IPV4_DONTFRAG)) printf("IPv4 don't fragment flag set\n");
	if (FLAG_SET(hdr.ip4_ofs, IPV4_MOREFRAG)) printf("IPv4 more fragments to follow\n");
	printf("IPv4 time-to-live:        %d seconds\n", hdr.ip4_ttl);
	printf("IPv4 protocol:            0x%04X\n", hdr.ip4_proto);
	printf("IPv4 checksum:            0x%04X\n", hdr.ip4_chksum);
	printf("IPv4 source address:      ");
	printf_ip4(hdr.ip4_src);
	printf("\n");
	printf("IPv4 destination address: ");
	printf_ip4(hdr.ip4_dst);
	printf("\n");

	/* Process individual packet type */
	switch(hdr.ip4_proto)
	{
	case PROTO_UDP:
		process_raw_udp(&packet[sizeof(hdr_ipv4_t)], len - sizeof(hdr_ipv4_t));
		break;
	default:
		printf("No further processing of this packet type will be done\n");
		break;
	}
}

void process_raw_ipv6(const u_char* packet, int len)
{
}

void process_raw_ip(const u_char* packet, int len)
{
	if (len == 0) return;

	/* The first byte contains the IP version number */
	switch(IP_VER(packet[0]))
	{
	case 4:
		printf("Processing IPv4 packet\n");
		process_raw_ipv4(packet, len);
		break;
	case 6:
		printf("Processing IPv6 packet\n");
		process_raw_ipv6(packet, len);
		break;
	default:
		fprintf(stderr, "Unknown IP version %d\n", IP_VER(packet[0]));
		break;
	}
}

void process_raw_ether(const u_char* packet, int len)
{
#pragma pack(push, 1)
	struct sniff_ethernet
	{
		u_char ether_dhost[6];
		u_char ether_shost[6];
		u_short ether_type;
	} sniff_ethernet;
#pragma pop()

	if (len < sizeof(sniff_ethernet))
	{
		fprintf(stderr, "Malformed packet, skipping\n");
		return;
	}

	memcpy(&sniff_ethernet, packet, sizeof(sniff_ethernet));
	sniff_ethernet.ether_type = ntohs(sniff_ethernet.ether_type);

	printf("Source:      ");
	printf_mac(sniff_ethernet.ether_shost);
	printf("\n");
	printf("Destination: ");
	printf_mac(sniff_ethernet.ether_dhost);
	printf("\n");
	printf("Type:        0x%04X\n", sniff_ethernet.ether_type);

	if (sniff_ethernet.ether_type == ETHER_IP)
	{
		process_raw_ip(&packet[sizeof(sniff_ethernet)], len - sizeof(sniff_ethernet));
	}
}

int main(int argc, char* argv[])
{
	char* dev, errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle;
	struct bpf_program packetFilter;
	char filterExpr[] = "dst port 53";
	bpf_u_int32 mask = 0;
	bpf_u_int32 net = 0;
	struct pcap_pkthdr header;
	const u_char* packet = NULL;
	int i = 0;

	dev = pcap_lookupdev(errbuf);

	if (dev == NULL)
	{
		fprintf(stderr, "Could not find default capture device: %s\n", errbuf);

		return 2;
	}

	printf("Using default capture device: %s\n", dev);

	/* Find out device properties */
	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1)
	{
		fprintf(stderr, "Unable to determine device properties for %s: %s\n", dev, errbuf);
	}

	/* Open device in promiscuous mode */
	handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);

	if (handle == NULL)
	{
		fprintf(stderr, "Failed to open device %s: %s\n", dev, errbuf);
	}

	/* Compile and apply filter */
	if (pcap_compile(handle, &packetFilter, filterExpr, 0, net) == -1)
	{
		fprintf(stderr, "Failed to compile packet filters: %s\n", pcap_geterr(handle));
		return 2;
	}

	if (pcap_setfilter(handle, &packetFilter) == -1)
	{
		fprintf(stderr, "Failed to apply packet filter: %s\n", pcap_geterr(handle));
		return 2;
	}

	while(1)
	{
		packet = pcap_next(handle, &header);

		if (packet == NULL)
		{
			continue;
		}

		printf("Captured packet with length %d\n", header.len);

		process_raw_ether(packet, header.len);

		printf("\n");
	}

	pcap_close(handle);

	return 0;
}

