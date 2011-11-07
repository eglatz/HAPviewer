/**
 *	\file gfilter_pcap.cpp
 *	\brief Filter to import pcap files
 */

#include <pcap++.h>	// C++ wrapper for libpcap
#include <string>
#ifdef __linux__
#include <linux/if_ether.h>	// Ethernet header, ethernet protocol types
#else
#include <netinet/if_ether.h>	// Ethernet header, ethernet protocol types
#endif // __linux__
#include <netinet/in_systm.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip.h>			// IPv4 header
#include <netinet/ip6.h>		// IPv6 header
#include <netinet/tcp.h>		// TCP header
#include <netinet/udp.h>		// UDP header
#include <netinet/in.h>			// IP protocol types
#include "gfilter_pcap.h"
#include "cflow.h"

using namespace pcappp;
using namespace std;

/**
 *	Constructor
 *
 *	\param	formatName	Name of this format
 *	\param	humanReadablePattern	A simple name pattern for files of this type, used by e.g. the GUI
 *	\param	regexPattern	Regex pattern used internally
 */
GFilter_pcap::GFilter_pcap(std::string formatName, std::string humanReadablePattern, std::string regexPattern) :
	GFilter(formatName, humanReadablePattern, regexPattern) {
	// nothing to do here
}

/**
 *	Read pcap data from file into memory-based temporary flow list.
 *	Assembles packets to flows.
 *	The temporary flow list is not yet sorted and uniflows are not yet qualified.
 *
 *	\param in_filename Filename to read
 *	\param flowlist List to fill with the flows
 *	\param local_net Local network address
 *	\param netmask Network mask for local network address
 *	\param append Future flag to allow the import of more than one file (not yet used)
 *
 *	@exception std::string Errortext
 */
void GFilter_pcap::read_file(std::string in_filename, CFlowList & flowlist, const IPv6_addr & local_net, const IPv6_addr & netmask, bool append) const {
	// Allocate temp_flowlist
	int maxnum_flows = 1000000; // We do not know in advance how many flows will be assembled FIXME: we could guess it from the filesize ?!
	flowlist.clear();
	flowlist.resize(maxnum_flows);

	// Hash map for packet-to-flow assembling and biflow pairing
	flowHashMap * flowHM = new flowHashMap();
	flowHashMap::iterator iter;

	int i = 0;
	long pcount = 0; // Packet counter
	long arp_packet_count = 0;
	long other_packet_count = 0;

	// (1) Open file for packet reading
	// ********************************
	try {
		PcapOffline pco(in_filename.c_str());

		DataLink dl = pco.get_datalink();

		if (true) {
			// Get some general infos from file
			string filename = pco.get_filename();
			cout << "File name is: " << filename << endl;

			int major = pco.get_major_version();
			int minor = pco.get_minor_version();
			cout << "Pcap file format used is version: " << major << "." << minor << endl;

			cout << "Using local_net=" << local_net << " and netmask=0x" << hex << netmask << dec << endl;

			if (pco.is_swapped()) {
				cout << "Capture data byte order differs from byte order used on this system.\n";
			} else {
				cout << "Capture data byte order complies with byte order used on this system.\n";
			}

			cout << "Data link code: " << dl.get_description() << endl;
		}

		if (dl.get_type() == DataLink::EN10MB) {
			if (true)
				cout << "INFO: data link type is standard Ethernet (10 MB up).\n";
		} else {
			string errtext = "ERROR: data link type is NOT Ethernet. Type code is: ";
			errtext += dl.get_type();
			errtext += " (not supported).\n";
			cerr << errtext;
			throw errtext;
		}
		if (true) {
			unsigned int slen = pco.get_snaplen();
			cout << "Snap length: " << slen << endl;
		}

		// (2) Process saved packets
		// *************************
		// Loop through pcap file by reading packet-by-packet.
		// Assemble packets to a flowlist.
		// Flowtype is correctly set to inflow/outflow or biflow.
		// NOTE: uniflow qualification is done in step 3

		Packet p;
		while (pco.ok()) {
			// Get next packet from file
			if (!pco.next(p))
				break; // Quit if no more packets avaliable
			pcount++;

			// Get packet length from header, but limit it to capture length
			Packet::Length len = (p.get_length() > p.get_capture_length()) ? p.get_length() : p.get_capture_length();

			if (len < sizeof(struct ethhdr)) { // Is packet too small?
				string errtext = "Found malformed packet. Packet # ";
				errtext += pcount;
				errtext += ".\n";
				cerr << errtext;
				throw errtext;
			}

			Packet::Data const * pdata = p.get_data();

			struct ethhdr * ether_hdr = (struct ethhdr *) pdata;

			// Process packet header data: check if data link protocol is ethernet
			if (ntohs(ether_hdr->h_proto) == ETH_P_IP) { // Check if IPv4 packet

				// Process IPv4 packet
				// -------------------

				if (len < (sizeof(struct ethhdr) + sizeof(struct iphdr))) { // Is packet too small?
					string errtext = "Found malformed packet. Packet # ";
					errtext += pcount;
					errtext += ".\n";
					cerr << errtext;
					throw errtext;
				}
				struct iphdr * ip_hdr = (struct iphdr *) (pdata + sizeof(struct ethhdr));

				// Get protocol
				uint8_t prot = ip_hdr->protocol;

				// Get IP addresses
				IPv6_addr srcIP = IPv6_addr(ntohl(ip_hdr->saddr));
				IPv6_addr dstIP = IPv6_addr(ntohl(ip_hdr->daddr));

				// Infer flow direction from known network/netmask values
				flow_type_t flowtype = inflow;
				IPv6_addr net(srcIP & netmask);
				if (net == local_net)
					flowtype = outflow;

				{
					string dir;
					if (flowtype == outflow)
						dir = "local";
					else
						dir = "remote";
					cout << "Found " << dir << " address srcIP = " << srcIP << endl;
				}

				// Get ports and flags (if TCP)
				uint16_t srcPort = 0, dstPort = 0;
				struct tcphdr * tcp_hdr = NULL;
				struct udphdr * udp_hdr = NULL;
				uint8_t flags = 0;
				if (prot == IPPROTO_TCP) {
					tcp_hdr = (struct tcphdr *) (pdata + sizeof(struct ethhdr) + sizeof(struct iphdr));
					srcPort = ntohs(tcp_hdr->source);
					dstPort = ntohs(tcp_hdr->dest);
					flags = *(((uint8_t *) &(tcp_hdr->ack_seq)) + 5);
				} else if (prot == IPPROTO_UDP) {
					udp_hdr = (struct udphdr *) (pdata + sizeof(struct ethhdr) + sizeof(struct iphdr));
					srcPort = ntohs(udp_hdr->source);
					dstPort = ntohs(udp_hdr->dest);
				}

				// Get start time (note: get_miliseconds() returns microsecs in libpcap++ V 0.0.2)
				// NOTE: we do not round the microsecs here, but cut-off not needed digits;
				// by this, an error of up to 1 ms may result which is acceptable for a ms-precision.
				uint64_t startMs = (uint64_t) (p.get_miliseconds() / 1000);
				startMs += 1000 * (uint64_t) (p.get_seconds());
				// Get layer 3 byte count
				long layer3len = p.get_length() - sizeof(struct ethhdr);
				uint8_t ToS = ip_hdr->tos;

				// Assign src/dst fields to appropriate local/remote fields
				IPv6_addr localIP, remoteIP;
				uint16_t localPort, remotePort;

				// Biflow matching: revert src/dst such that biflows are formed
				if (flowtype == outflow) {
					localIP = srcIP;
					remoteIP = dstIP;
					localPort = srcPort;
					remotePort = dstPort;
				} else {
					localIP = dstIP;
					remoteIP = srcIP;
					localPort = dstPort;
					remotePort = srcPort;
				}

				// Check if packet belongs to a new flow or updates an existing flow

				flowHashKey mykey(localIP, remoteIP, localPort, remotePort, prot);
				iter = flowHM->find(mykey);

				if (iter != flowHM->end()) {
					// Found: update found flow with new packet's data
					// Fetch reference to flow entry hash map
					cflow_t * f = iter->second;
					// Found: update flow by contents of current packet
					f->dOctets += layer3len;
					if (startMs > flowlist[i].startMs) {
						// New packet starts later
						f->durationMs = startMs - f->startMs;
					} else {
						// New packet starts earlier
						f->durationMs = f->startMs - startMs;
						// Set flow start to earlier packet start
						flowlist[i].startMs = startMs;
					}
					f->dPkts++;
					if ((f->flowtype != flowtype) && (f->flowtype != biflow)) {
						// New packet has opposite direction to earlier packets
						// Make it a biflow
						f->flowtype = biflow;
					}

				} else { // Not found
					// Make an initial entry into temp_flowlist
					flowlist[i].localIP = localIP;
					flowlist[i].remoteIP = remoteIP;
					flowlist[i].localPort = localPort;
					flowlist[i].remotePort = remotePort;
					flowlist[i].flowtype = flowtype;
					flowlist[i].prot = prot;
					flowlist[i].dOctets = layer3len;
					flowlist[i].startMs = startMs;
					flowlist[i].durationMs = 0;
					flowlist[i].dPkts = 1;
					flowlist[i].localAS = 0;
					flowlist[i].remoteAS = 0;
					flowlist[i].tos_flags = ToS;
					flowlist[i].magic = CFLOW_CURRENT_MAGIC_NUMBER;

					// Store 5-tuple together with reference to flow record in flow list
					(*flowHM)[mykey] = &flowlist[i];
					i++;
					if (i >= maxnum_flows) {
						string errtext = "INFO: terminating file reading due to full flow list.\n";
						errtext += maxnum_flows;
						errtext += " is the configured import limit.\n";
						cerr << errtext;
						throw errtext;
					}
				}

			} else if (ntohs(ether_hdr->h_proto) == ETH_P_IPV6) {
				// Process IPv6 packet
				// -------------------
				if (len < (sizeof(struct ethhdr) + sizeof(struct ip6_hdr))) { // Is packet too small?
					string errtext = "Found malformed packet. Packet # ";
					errtext += pcount;
					errtext += ".\n";
					cerr << errtext;
					throw errtext;
				}
				struct ip6_hdr * ip6_header = (struct ip6_hdr *) (pdata + sizeof(struct ethhdr));

				// Get protocol
				uint8_t prot = ip6_header->ip6_ctlun.ip6_un1.ip6_un1_nxt;

				// Get IP addresses
				IPv6_addr srcIP(ip6_header->ip6_src);
				IPv6_addr dstIP(ip6_header->ip6_dst);

				// Infer flow direction from known network/netmask values
				flow_type_t flowtype = inflow;
				IPv6_addr net(srcIP & netmask);
				if (net == local_net)
					flowtype = outflow;

				{
					string dir;
					if (flowtype == outflow)
						dir = "local";
					else
						dir = "remote";
					cout << "Found " << dir << " address srcIPv6 = " << srcIP << endl;
				}

				// Get ports and flags (if TCP)
				uint16_t srcPort = 0, dstPort = 0;
				struct tcphdr * tcp_hdr = NULL;
				struct udphdr * udp_hdr = NULL;
				uint8_t flags = 0;
				if (prot == IPPROTO_TCP) {
					tcp_hdr = (struct tcphdr *) (pdata + sizeof(struct ethhdr) + sizeof(struct ip6_hdr));
					srcPort = ntohs(tcp_hdr->source);
					dstPort = ntohs(tcp_hdr->dest);
					flags = *(((uint8_t *) &(tcp_hdr->ack_seq)) + 5);
				} else if (prot == IPPROTO_UDP) {
					udp_hdr = (struct udphdr *) (pdata + sizeof(struct ethhdr) + sizeof(struct ip6_hdr));
					srcPort = ntohs(udp_hdr->source);
					dstPort = ntohs(udp_hdr->dest);
				}

				// Get start time (note: get_miliseconds() returns microsecs in libpcap++ V 0.0.2)
				// NOTE: we do not round the microsecs here, but cut-off not needed digits;
				// by this, an error of up to 1 ms may result which is acceptable for a ms-precision.
				uint64_t startMs = (uint64_t) (p.get_miliseconds() / 1000);
				startMs += 1000 * (uint64_t) (p.get_seconds());
				// Get layer 3 byte count
				long layer3len = p.get_length() - sizeof(struct ethhdr);
				uint8_t ToS = ip6_header->ip6_ctlun.ip6_un1.ip6_un1_hlim;

				// Assign src/dst fields to appropriate local/remote fields
				IPv6_addr localIP, remoteIP;
				uint16_t localPort, remotePort;

				// Biflow matching: revert src/dst such that biflows are formed
				if (flowtype == outflow) {
					localIP = srcIP;
					remoteIP = dstIP;
					localPort = srcPort;
					remotePort = dstPort;
				} else {
					localIP = dstIP;
					remoteIP = srcIP;
					localPort = dstPort;
					remotePort = srcPort;
				}

				// Check if packet belongs to a new flow or updates an existing flow

				flowHashKey mykey(localIP, remoteIP, localPort, remotePort, prot);
				iter = flowHM->find(mykey);

				if (iter != flowHM->end()) {
					// Found: update found flow with new packet's data
					// Fetch reference to flow entry hash map
					cflow_t * f = iter->second;
					// Found: update flow by contents of current packet
					f->dOctets += layer3len;
					if (startMs > flowlist[i].startMs) {
						// New packet starts later
						f->durationMs = startMs - f->startMs;
					} else {
						// New packet starts earlier
						f->durationMs = f->startMs - startMs;
						// Set flow start to earlier packet start
						flowlist[i].startMs = startMs;
					}
					f->dPkts++;
					if ((f->flowtype != flowtype) && (f->flowtype != biflow)) {
						// New packet has opposite direction to earlier packets
						// Make it a biflow
						f->flowtype = biflow;
					}

				} else { // Not found
					// Make an initial entry into temp_flowlist
					flowlist[i].localIP = localIP;
					flowlist[i].remoteIP = remoteIP;
					flowlist[i].localPort = localPort;
					flowlist[i].remotePort = remotePort;
					flowlist[i].flowtype = flowtype;
					flowlist[i].prot = prot;
					flowlist[i].dOctets = layer3len;
					flowlist[i].startMs = startMs;
					flowlist[i].durationMs = 0;
					flowlist[i].dPkts = 1;
					flowlist[i].localAS = 0;
					flowlist[i].remoteAS = 0;
					flowlist[i].tos_flags = ToS;
					flowlist[i].magic = CFLOW_CURRENT_MAGIC_NUMBER;

					// Store 5-tuple together with reference to flow record in flow list
					(*flowHM)[mykey] = &flowlist[i];
					i++;
					if (i >= maxnum_flows) {
						string errtext = "INFO: terminating file reading due to full flow list.\n";
						errtext += maxnum_flows;
						errtext += " is the configured import limit.\n";
						cerr << errtext;
						throw errtext;
					}
				}
			} else {

				// Handle all non-IPv4/IPv6 traffic
				// ---------------------------
				//
				// Just update some statistics.
				switch (ntohs(ether_hdr->h_proto)) {
					case ETH_P_ARP:
						arp_packet_count++;
						break;
					default:
						other_packet_count++;
				}
			}
		}

	} catch (PcapError & pcerror) {
		cerr << "ERROR: " << pcerror.what() << endl;
		throw pcerror.what();
	} catch (...) {
		throw "Error in CImport::read_pcap_file_raw()";
	}

	flowlist.resize(i);
	cout << "(ignored packets: " << arp_packet_count << " (ARP), " << other_packet_count << " (OTHER).\n";
}

/**
 *	Decide if this filter supports this file, using the filename to decide
 *
 *	\param in_filename Inputfilename
 *
 *	\return True if the file is supported by this filter
 *
 */
bool GFilter_pcap::acceptFileForReading(std::string in_filename) const {
	return acceptFilename(in_filename);
}
