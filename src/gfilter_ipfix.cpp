/**
 *	\file gfilter_ipfix.cpp
 *	\brief Filter to import ipfix files
 */

#include <string>

#include "gfilter_ipfix.h"

using namespace std;

/**
 *	Constructor
 *
 *	\param	formatName	Name of this format
 *	\param	humanReadablePattern	A simple name pattern for files of this type, used by e.g. the GUI
 *	\param	regexPattern	Regex pattern used internally
 */
GFilter_ipfix::GFilter_ipfix(std::string formatName, std::string humanReadablePattern, std::string regexPattern) :
	GFilter(formatName, humanReadablePattern, regexPattern) {
	// nothing to do here
}

/**
 *	Read ipfix data from file into memory-based temporary flow list.
 *	Converts ipfix flows into cflow_t flows.
 *	Uses routines from libfixbuf and the file read/writer example to read ipfix files.
 *	The template used supports IPv4 uniflows only.
 *
 *	The temporary flow list is not yet sorted and uniflows are not yet qualified.
 *
 *	\param in_filename Inputfilename
 *	\param flowlist Reference to the flowlist
 *	\param local_net Local network address
 *	\param netmask Network mask for local network address
 *	\param append Future flag to allow the import of more than one file (not yet used)
 *
 *	@exception std::string Errortext
 */
void GFilter_ipfix::read_file(std::string in_filename, CFlowList & flowlist, const IPv6_addr & local_net, const IPv6_addr & netmask, bool append) const {
	bool debug5 = false; //FIXME: remove this kind of errorhandling

	// Allocate temp_flowlist
	int maxnum_flows = 1000000; // TODO We do not know in advance how many flows will be assembled
	flowlist.resize(maxnum_flows);

	// Hash map for biflow pairing
	flowHashMap * flowHM = new flowHashMap();
	flowHashMap::iterator iter;

	// Prepare for reading of ipfix file
	// *********************************
	FILE * pFile = util::openFile(in_filename.c_str(), "r");

	GError * err1 = NULL;
	fBuf_t * fbuf = vx5ReaderForFP(pFile, &err1);

	size_t s = 256;
	uint8_t * recbase = new uint8_t[s];

	// Read ipfix file
	// ***************
	// Read flow-by-flow, transform into cflow_t format and store in temporary flowlist
	int j = 0;
	int k = 0;
	gboolean ok = true;
	// cout<<"----"<<sizeof(vx5Flow_st)<<endl;
	while (ok) {
		GError * err2 = NULL;
		ok = fBufNext(fbuf, recbase, &s, &err2);

		if (!ok) {
			if (err2->code == FB_ERROR_EOF) {
				cout << "Read complete: EOF\n";
			} else {
				cerr << "INFO: failed reading, reason: ";
				cerr << err2->message << endl;
				throw string(err2->message);
			}
		} else {
			vx5Flow_t * irec = (vx5Flow_t *) recbase; // cast to ipfix record

			// check if record contains IPv6 data
			//cout << "version:" << util::bin2hexstring(&(irec->ipVersion), 1) << endl;
			bool isIPv6 = (irec->sourceIPv4Address == 0/*irec->ipVersion == IP_VERS_NR_IPv6*/); // TODO: check & fix

			// Get protocol
			uint8_t prot = irec->protocolIdentifier;
			// uint8_t prot = irec->nextHeaderIPv6;

			// Get ports and IP addresses
			uint16_t srcPort = irec->sourceTransportPort;
			uint16_t dstPort = irec->destinationTransportPort;
			IPv6_addr srcIP;
			IPv6_addr dstIP;
			if (isIPv6) {
				srcIP = util::ipV6IpfixToIpV6(irec->sourceIPv6Address);
				dstIP = util::ipV6IpfixToIpV6(irec->destinationIPv6Address);
			} else {
				srcIP = IPv6_addr(irec->sourceIPv4Address);
				dstIP = IPv6_addr(irec->destinationIPv4Address);
			}

			if (debug5) {
				if (srcIP == IPv6_addr() || dstIP == IPv6_addr()) {
					print_ipfix_record(recbase);
				}
			}

			// Assign src/dst fields to appropriate local/remote fields
			// Assign src/dst fields to appropriate local/remote fields
			IPv6_addr localIP, remoteIP;
			uint32_t localPort, remotePort;

			// Infer flow direction from known network/netmask values
			flow_type_t flowtype = inflow;
			if ((srcIP & netmask) == local_net) {
				flowtype = outflow;
			}

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

			uint64_t startMs = irec->flowStartMilliseconds;
			uint64_t endMs = irec->flowEndMilliseconds;

			uint64_t revdOctets = irec->reverseOctetTotalCount;
			uint32_t revdPkts = irec->reversePacketTotalCount;

			bool bidir = false;
			if (revdOctets > 0)
				bidir = true;

			uint64_t dOctets = irec->octetTotalCount + revdOctets;
			uint32_t dPkts = irec->packetTotalCount + revdPkts;

			// Check if flow is a new flow or updates/matches an existing flow
			flowHashKey mykey(localIP, remoteIP, localPort, remotePort, prot);
			iter = flowHM->find(mykey);

			if (iter != flowHM->end()) {
				// Found: update found cflow_t with new nfdump's flow data
				// Fetch reference to flow entry hash map
				cflow_t * f = iter->second;
				// Found: update flow by contents of current packet
				f->dOctets += dOctets;

				if (startMs > f->startMs) {
					// New flow starts later: modify duration
					f->durationMs = endMs - f->startMs;
				} else {
					// New flow starts earlier
					f->durationMs = (f->startMs + f->durationMs) - startMs;
					// Set flow start to earlier flow start
					flowlist[j].startMs = startMs;
				}

				f->dPkts += dPkts;
				if ((f->flowtype != flowtype) && (f->flowtype != biflow)) {
					// New packet has opposite direction to earlier packets
					// Make it a biflow
					f->flowtype = biflow;
				}

			} else { // Not found
				// Make an initial entry into temp_flowlist
				flowlist[j].localIP = localIP;
				flowlist[j].remoteIP = remoteIP;
				flowlist[j].localPort = localPort;
				flowlist[j].remotePort = remotePort;
				if (bidir) {
					flowlist[j].flowtype = biflow;
				} else {
					flowlist[j].flowtype = flowtype;
				}
				flowlist[j].prot = prot;
				flowlist[j].dOctets = dOctets;
				flowlist[j].startMs = startMs;
				flowlist[j].durationMs = endMs - startMs;
				flowlist[j].dPkts = dPkts;
				flowlist[j].localAS = 0;
				flowlist[j].remoteAS = 0;
				flowlist[j].tos_flags = 0;
				flowlist[j].magic = 1;

				// Store 5-tuple together with reference to flow record in flow list
				(*flowHM)[mykey] = &flowlist[j];
				j++;
				if (j >= maxnum_flows) {
					string errtext = "INFO: terminating file reading due to full flow list.\n";
					errtext += maxnum_flows;
					errtext += " is the configured import limit.\n";
					cerr << errtext;
					throw errtext;
				}
			}
			k++;
		}
	}
	util::closeFile(pFile);

	flowlist.resize(j);

	cout << "*** Processed " << k << " ipfix flows to " << flowlist.size() << " final flows.\n";
}

/**
 *	Print a single ipfix record to console in human readable form.
 *
 *	\param	recbase	Address of a single ipfix flow
 */
void GFilter_ipfix::print_ipfix_record(uint8_t * recbase) const {
	vx5Flow_t * irec = (vx5Flow_t *) recbase; // cast to ipfix record

	// 1. Copy ipfix record fields to cflow_t record fields
	// **************************************************
	// So far, we assign srcIP to localIP. IPFIX uses the initiator of a connection
	// as the srcIP. We use the terminology local/remote under the assumption
	// that one of the two endpoints is located within our local network/AS, i.e.
	// the capture point is the border btw. local/remote.
	// Furthermore, we assume an ipfix template containing the reverse counters.
	bool isIPv6 = (irec->sourceIPv4Address == 0/*irec->ipVersion==IP_VERS_NR_IPv6*/); // TODO: check&fix
	cflow_t flow;
	if (isIPv6) {
		flow.localIP = util::ipV6IpfixToIpV6(irec->sourceIPv6Address);
		flow.remoteIP = util::ipV6IpfixToIpV6(irec->destinationIPv6Address);
	} else {
		flow.localIP = IPv6_addr(irec->sourceIPv4Address);
		flow.remoteIP = IPv6_addr(irec->destinationIPv4Address);
	}
	flow.startMs = irec->flowStartMilliseconds;
	flow.durationMs = irec->flowEndMilliseconds - irec->flowStartMilliseconds;
	flow.localPort = irec->sourceTransportPort;
	flow.remotePort = irec->destinationTransportPort;
	flow.dOctets = irec->octetTotalCount + irec->reverseOctetTotalCount;
	flow.dPkts = irec->packetTotalCount + irec->reversePacketTotalCount;
	flow.localAS = 0;
	flow.remoteAS = 0;
	flow.prot = irec->protocolIdentifier;
	if (irec->reverseOctetTotalCount > 0) {
		flow.dir = biflow;
	} else {
		flow.dir = outflow;
	}
	flow.tos_flags = irec->tcpControlBits;

	// 2. Print cflow_t record obtained from ipfix record
	// ************************************************
	char text[1024];
	util::record2StringShort(flow, text);
	cout << text << endl;
}

/**
 *	Decide if this filter supports this file, using the filename to decide
 *
 *	\param in_filename Inputfilename
 *
 *	\return True if the file is supported by this filter
 *
 */
bool GFilter_ipfix::acceptFileForReading(std::string in_filename) const {
	return acceptFilename(in_filename);
}
