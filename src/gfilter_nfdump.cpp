/**
 *	\file gfilter_nfdump.cpp
 *	\brief Filter to import nfdump files
 */

#include <string>
#include <string.h>
#include <sys/stat.h>
#include <errno.h>
#include <sstream>

#include "gfilter_nfdump.h"
#include "gfilter_nfdump_gnfdump.h"	// nfdump file format support (extracted from nfdump tool set)
#include "cflow.h"
#include "IPv6_addr.h"

using namespace std;

/**
 *	Constructor
 *
 *	\param	formatName	Name of this format
 *	\param	humanReadablePattern	A simple name pattern for files of this type, used by e.g. the GUI
 *	\param	regexPattern	Regex pattern used internally
 */
GFilter_nfdump::GFilter_nfdump(std::string formatName, std::string humanReadablePattern, std::string regexPattern) :
	GFilter(formatName, humanReadablePattern, regexPattern) {
	// nothing to do here
}

/**
 *	Read nfdump data from file into memory-based temporary flow list.
 *	Supports nfdump 1.6.x file format.
 *	Converts nfdump flows into cflow_t flows.
 *	The resulting flowlist is not yet sorted and uniflows are not yet qualified.
 *
 *	\param in_filename Inputfilename
 *	\param flowlist Reference to the flowlist
 *	\param local_net Local network address
 *	\param netmask Network mask for local network address
 *	\param append Future flag to allow the import of more than one file (not yet used)
 *
 * \exception char* Errortext
 * \exception string Errortext
 */
void GFilter_nfdump::read_file(std::string in_filename, CFlowList & flowlist, const IPv6_addr & local_net, const IPv6_addr & netmask, bool append) const {
	cout << "Input file " << in_filename << " contains " << util::getFileSize(in_filename) << " bytes.\n";

	bool debug4 = false;

	// Allocate temp_flowlist
	int maxnum_flows = 1000000; // TODO We do not know in advance how many flows will be assembled
	flowlist.resize(maxnum_flows);

	// Hash map for biflow pairing
	flowHashMap * flowHM = new flowHashMap();
	flowHashMap::iterator iter;

	// Prepare for reading of nfdump file
	// **********************************
	data_block_header_t in_block_header;
	common_record_t *flow_record, *in_buff;
	master_record_t *master_record;
	stat_record_t stat_record;
	char * estring;

	extension_map_list_t extension_map_list;
	InitExtensionMaps(&extension_map_list);

	uint32_t total_flows = 0;
	uint64_t total_bytes = 0;

	// time window of all matched flows
	memset((void *) &stat_record, 0, sizeof(stat_record_t));
	stat_record.first_seen = 0x7fffffff;
	stat_record.msec_first = 999;

	// time window of all processed flows
	time_t t_first_flow, t_last_flow;
	t_first_flow = 0x7fffffff;
	t_last_flow = 0;

	// allocate network buffer
	uint64_t bufsize = (util::getFileSize(in_filename) * 12) / 10; // Add 20% reserve
	in_buff = (common_record_t *) malloc(bufsize);

	char *error;
	stat_record_t *stat_ptr;
	int rfd = OpenFile((char *) in_filename.c_str(), &stat_ptr, &error); // Open the file

	if (rfd < 0) {
		stringstream error;
		error << "Could not open " << in_filename;
		throw error.str();
	}

	nffile_t nffile;
	memset((void *) &nffile, 0, sizeof(nffile));

	// Read nfdump file
	// ****************
	// Read flow-by-flow, transform into cflow_t format and store in temporary flowlist
	int done = 0;
	int j = 0;
	while (!done) {
		int ret;

		// get next data block from file
		ret = ReadBlock(rfd, &in_block_header, (void *) in_buff, &estring);
		switch (ret) {
			case NF_CORRUPT:
			case NF_ERROR:
				if (ret == NF_CORRUPT)
					fprintf(stderr, "Skip corrupt data file '%s': '%s'\n", in_filename.c_str(), estring);
				else
					fprintf(stderr, "Read error in file '%s': %s\n", in_filename.c_str(), strerror(errno));
				// fall through
			case NF_EOF:
				// rfd == EMPTY_LIST
				done = 1;
				continue;
				break; // not really needed
			default:
				// successfully read block
				total_bytes += ret;
		}

		flow_record = in_buff;
		for (unsigned int i = 0; i < in_block_header.NumRecords; i++) {
			if (flow_record->type == CommonRecordType) {
				uint32_t map_id = flow_record->ext_map;

				total_flows++;
				master_record = &(extension_map_list.slot[map_id]->master_record);
				/*
				 * Expand file record into master record for further processing
				 * LP64 CPUs need special 32bit operations as it is not guarateed, that 64bit
				 * values are aligned
				 */
				ExpandRecord_v2(flow_record, extension_map_list.slot[map_id], master_record);

				// Get protocol
				uint8_t prot = master_record->prot;

				// Get ports and IP addresses
				uint16_t srcPort = master_record->srcport;
				uint16_t dstPort = master_record->dstport;
				IPv6_addr srcIP;
				IPv6_addr dstIP;
				if ((master_record->flags & FLAG_IPV6_ADDR) != 0) {
					srcIP = util::ipV6NfDumpToIpV6(master_record->v6.srcaddr);
					dstIP = util::ipV6NfDumpToIpV6(master_record->v6.dstaddr);

				} else {
					srcIP = IPv6_addr(master_record->v4.srcaddr);
					dstIP = IPv6_addr(master_record->v4.dstaddr);
				}

				// Assign src/dst fields to appropriate local/remote fields
				// Assign src/dst fields to appropriate local/remote fields
				IPv6_addr localIP, remoteIP;
				uint16_t localPort, remotePort;

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

				uint64_t startMs = (uint64_t) master_record->first * 1000 + master_record->msec_first;
				uint64_t endMs = (uint64_t) master_record->last * 1000 + master_record->msec_last;

				uint64_t dOctets = master_record->dOctets;
				uint32_t dPkts = master_record->dPkts;
				uint8_t tos_flags = master_record->tos;

				if (debug4) {
					// Print cflow_t record
					char s[512];
					//					util::record2StringShort(&flow, s);
					//					printf("%s\n", s);

					// print nfdump record
					print_record(master_record, s);
					printf("%s\n", s);
				}

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
						// Set flow start to earlierflow start
						flowlist[j].startMs = startMs;
					}

					f->dPkts += dPkts;
					if ((f->flowtype != flowtype) && (f->flowtype != biflow)) {
						// New packet has opposite direction to earlier packets
						// Make it a biflow
						f->flowtype = biflow;
					}

				} else { // Not found
					// Make an initial entry into flowlist
					flowlist[j].localIP = localIP;
					flowlist[j].remoteIP = remoteIP;
					flowlist[j].localPort = localPort;
					flowlist[j].remotePort = remotePort;
					flowlist[j].flowtype = flowtype;
					flowlist[j].prot = prot;
					flowlist[j].dOctets = dOctets;
					flowlist[j].startMs = startMs;
					flowlist[j].durationMs = endMs - startMs;
					flowlist[j].dPkts = dPkts;
					flowlist[j].localAS = 0;
					flowlist[j].remoteAS = 0;
					flowlist[j].tos_flags = tos_flags;
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

				// Update statistics
				UpdateStat(&stat_record, master_record);

				// Update global time span window
				if (master_record->first < (uint32_t) t_first_flow)
					t_first_flow = master_record->first;
				if (master_record->last > (uint32_t) t_last_flow)
					t_last_flow = master_record->last;

				// update number of flows matching a given map
				extension_map_list.slot[map_id]->ref_count++;

			} else if (flow_record->type == ExtensionMapType) {
				extension_map_t *map = (extension_map_t *) flow_record;

				Insert_Extension_Map(&extension_map_list, map);

			} else {
				fprintf(stderr, "Skip unknown record type %i\n", flow_record->type);
			}

			// Advance pointer by number of bytes for netflow record
			flow_record = (common_record_t *) ((pointer_addr_t) flow_record + flow_record->size);

		} // for all records
	} // while

	if (rfd > 0)
		close(rfd);

	PackExtensionMapList(&extension_map_list);

	free((void *) in_buff);

	flowlist.resize(j);
	if(j == 0)
		throw "This looks like a compressed nfdump file which we can not handle";

	cout << "*** Processed " << total_flows << " nfdump flows to " << flowlist.size() << " final flows.\n";
}

/**
 *	Decide if this filter supports this file, using the filename to decide
 *
 *	\param in_filename Inputfilename
 *
 *	\return True if the file is supported by this filter
 *
 */
bool GFilter_nfdump::acceptFileForReading(std::string in_filename) const {
	return acceptFilename(in_filename);
}
