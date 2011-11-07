/**
 *	\file ghpgdata.cpp
 *	\brief Metadata storage and host profile graphlet data storage.
 *
 *	Implements HPG to DOT transformation of graphlet data.
 *	HPG: a specific type of graphlet description (three versions exist, for details see below).
 *	DOT: graph data description format as defined by Graphviz ("dot-language").
 */
#include <iostream>
#include <sstream>
#include <assert.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <netinet/in.h>		// IP protocol type definitions
#include "ghpgdata.h"
#include "HashMapE.h"
#include "cflow.h"
#include "gutil.h"
#include "gsummarynodeinfo.h"

// Use a view where dstPort-->dstIP connections are shown as an additional graph partition
#define	DSTIP_DOUBLED

// Edge threshold for display of progress bar for get_hpgMetadata() execution
// (Note: numbers must be multiples of 3)
#define	PROGRESS_THRESHOLD	200001
#define	PROGRESS_INCREMENT	12501

#ifdef MAIN_TEST
const bool dbg = true;
const bool dbg2 = true;
const bool dbg4 = true;
const bool dbg5 = false;
const bool dbg6 = false;
#else
#ifdef NDEBUG
const bool dbg = false;
const bool dbg2 = false;
const bool dbg4 = false; // Set true to show raw edge in human-readable form
const bool dbg5 = false;
const bool dbg6 = false;
#else
const bool dbg = true;
const bool dbg2 = false;
const bool dbg4 = false; // Set true to show raw edge in human-readable form
const bool dbg5 = false;
const bool dbg6 = false;
#endif
#endif

#ifdef MAIN_TEST
uint32_t filedata1[] = { // Data for one graphlet plus a single next row.
	srcIP_prot, 1, 6,// i=0
	srcIP_prot, 1, 17,// 3
	prot_dstIP, 6, 3,// 6
	prot_dstIP, 6, 4,// 9
	dstIP_srcPort, 3, 7,// 12
	dstIP_srcPort, 4, 8,// 15
	srcPort_dstPort, 7, 10,// 18
	srcPort_dstPort, 8, 10,// 21
	prot_dstIP, 17, 5,// 24
	dstIP_srcPort, 5, 9,// 27
	srcPort_dstPort, 9, 11,// 30
	srcPort_dstPort, 9, 12,// 33
	16+srcIP_prot, 1, 6// 36 (row belonging to next graphlet)
};

uint32_t filedata2[] = { // Data for one graphlet. No other graphlet exists.
	srcIP_prot, 1, 6,// i=0
	srcIP_prot, 1, 17,// 3
	prot_dstIP, 6, 3,// 6
	prot_dstIP, 6, 4,// 9
	dstIP_srcPort, 3, 7,// 12
	dstIP_srcPort, 4, 8,// 15
	srcPort_dstPort, 7, 10,// 18
	srcPort_dstPort, 8, 10,// 21
	prot_dstIP, 17, 5,// 24
	dstIP_srcPort, 5, 9,// 27
	srcPort_dstPort, 9, 11,// 30
	srcPort_dstPort, 9, 12,// 33
};
#endif

using namespace std;

// Hash key & map for unique node check (use ipv6 keys as they have a suitable size of 128 bit)
typedef HashKeyIPv6 NodeHashKey;
typedef hash_map<HashKeyIPv6, uint32_t, HashFunction<HashKeyIPv6> , HashFunction<HashKeyIPv6> > NodeHashMap;

// For hpg2dot3(): store node_id and node_type as low/high 32 bits of an uint64_t entry
typedef CHashKey6_6 NodeHashKey2;
typedef hash_map<CHashKey6_6, node_hm_value, HashFunction<CHashKey6_6> , HashFunction<CHashKey6_6> > NodeHashMap2;

/**
 *	Constructor: initialize (for unit test only).
 *
 *	\exception char * Errormessage
 */
ChpgData::ChpgData() {
#ifndef MAIN_TEST
	cerr << "ERROR: wrong constructor (this cstor is for unit test only).\n";
	throw "ERROR: wrong constructor (this cstor is for unit test only).";
#endif
	elements = elements_read = rows = graphlet_cnt = 0;
	hpgdata = NULL;
	hpgdata_allocated = false;
	show_packet_counts = true;
	nodeInfos = NULL;
}

/**
 *	Constructor: use actual file size to determine needed memory space
 *	and remember name of file for later.
 *
 *	\param filename Name of hpg (host profile graphlet) file (*.hpg)
 *
 *	\exception std::string Errormessage
 */
ChpgData::ChpgData(const std::string & filename) {
	int field_size = sizeof(hpg_field);
	int record_size = field_size * 3;
	fname = filename;
	next_graphlet = 0;
	int filesize = util::getFileSize(filename);
	// Obtain file size and derive needed storage space from it
	if (!util::fileExists(filename) || filesize == 0) {
		string errtext = "ERROR: input file does not exist.\n";
		throw errtext;
	} else {
		cout << "File contains " << filesize << " bytes.\n";
	}
	if ((filesize % (record_size)) != 0) { // Do not tolerate incomplete edges
		string errtext = "file contains incomplete edge data.\n";
		cerr << "ERROR: " << errtext << endl;
		throw errtext;
	}
	elements = filesize / field_size;
	rows = elements / 3;

	hpgdata = new hpg_field[elements];
	hpgdata_allocated = true;
	graphlet_cnt = 0;
	hpgMetadata = new ChpgMetadata*[rows]; // Row count is upper bound on graphlet count
	graphlet_version = 0;
	show_packet_counts = true;
	nodeInfos = NULL;
}

/**
 * ChpgData destructor
 */
ChpgData::~ChpgData() {
	if (hpgdata != NULL && hpgdata_allocated)
		delete hpgdata;
	if (hpgMetadata != NULL) {
		for (int i = 0; i < graphlet_cnt; i++) {
			delete hpgMetadata[i];
		}
		delete hpgMetadata;
	}
}

/**
 *	Read hpg file data into memory.
 *
 *	\exception std::string Errormessage
 */
void ChpgData::read_hpg_file() {
	if (util::getFileSize(fname) == 0) {
		string error = "ERROR: empty file.";
		throw error;
	}

	// Read file data and store it in array "data"
	ifstream infs;
	try {
		util::open_infile(infs, fname);
	} catch (string & e) {
		throw e;
	}

	int j = 0;
	while (infs.good()) {
		if (j > elements) {
			cerr << "ERROR: array \"data\" overflow.\n";
			break;
		}
		infs.read((char *) (&hpgdata[j]), 3 * sizeof(IPv6_addr));
		j += 3;
	}
	infs.close();
	elements_read = j - 3; // Correct for last increment
	if (dbg)
		cout << "A total of " << elements_read << " elements and " << elements_read / 3 << " rows (edges) read from input file \"" << fname << "\".\n";

	if (elements_read != elements)
		cerr << "ERROR: calculated count of elements and effective caount of elements do not match.\n";

	rank_t rank = (rank_t) (hpgdata[0].eightbytevalue.data & 0xf);
	if (rank == version) {
		graphlet_version = 3;
	} else {
		cerr << "ERROR: cannot determine graphlet version from file data.\n\n";
	}
	if (dbg)
		cout << "Graphlet version seems to be " << graphlet_version << ".\n";

	if (dbg2)
		show_data(0, 30);
}

/**
 *	Read hpg data from memory into array "data".
 *
 *	This function primarily serves test purposes (uint test) and replaces in such
 *	settings the file_read() function whenever test data is stored in memory.
 *
 *	\param memdata Address of data stored in memory
 *	\param size of data in bytes
 */
void ChpgData::read_hpg_memory(hpg_field * memdata, int size) {
	hpgdata = memdata;
	elements = elements_read = size / sizeof(hpg_field);
	rows = elements / 3;
	hpgMetadata = new ChpgMetadata*[rows]; // Row count is upper bound on graphlet count
}

/**
 *	Infer metadata from data stored in array "data" and set-up index array for
 *	a later graphlet extraction.
 */
void ChpgData::get_hpgMetadata() {
	rank_t rank = (rank_t) (hpgdata[0].eightbytevalue.data & 0xf);
	if (rank == version) {
		graphlet_version = 3;
		get_hpgMetadata3();
	} else {
		cerr << "ERROR: cannot determine graphlet version from file data.\n\n";
		assert(false);
	}
}

/**
 *	Graphlet profile data definition (v2):
 *	 Note: we separate port numbers by protocol and by host identity
 *	 as they are not shared between protocols and between hosts.
 *
 *	 Limitations:
 *	 - host numbering wraps around at 2**12 (4096) // TODO: Still true?
 *	 - only four distinguished protocols, e.g. protcodes, to make port numbers unique
 *	   (but protocol node annotations support all IP protocol code values)
 *
 *	   rank (value 0.3..0)	value 1								value 2
 *
 *	   Inference of metadata list:
 *	   The metadata list contains a row per graphlet. Thus, metadata is inferred on a per
 *	   graphlet basis.
 *	   The goal is to obtain the count of nodes for each partition (e.g. localPort) and
 *	   the overall edge count of a graphlet in consideration.
 *	    - partition "localIP" node count is 1 (for a single host graphlet view, as used so far)
 *	    - all remaining partitions may obtain one or more nodes:
 *	        i) For each partition (right hand side of a rank_t edge) we count unique nodes
 *	           by use of a hash map.
 *	       ii) Upon change in rank we draw a summary by counting the unique hash map
 *	           entries: this gives us the unique node count for the just completed partition.
 *	      iii) This procedure is based on the fact (assumption) that all edges belonging to
 *	           a particular localIP are grouped together in the file data, and all edges
 *	           with equal rank and equal graphlet# are consecutively located in the file data.
 *				--> cflow2hpg() has to adhere to this sorting requirement.
 *
 *	\exception std::string Errormessage
 */
void ChpgData::get_hpgMetadata3(void) {
	cout << "INFO: version 3\n\n";

	rank_t rank = localIP_prot;
	rank_t last_rank = localIP_prot;

	// Implement a unique counter for right-hand side nodes
	// (right-hand side refers to the partition "on the right side" connected by an edge)
	NodeHashMap * node_hm = new NodeHashMap();
	NodeHashMap::iterator nodeiter;

	// Fetch first edge and initialize for graphlet scan
	//--------------------------------------------------
	int graphlet_nr = hpgdata[3].eightbytevalue.data >> GRAPHLETNUM_SHIFT;
	int last_graphlet_nr = 0;
	int i = 3; // Skip first edge (as it is version info)
	rank = (rank_t) (hpgdata[3].eightbytevalue.data & 0xf);
	// We expect first edge to have rank=localIP_prot
	// (must be an edge incident to localIP)
	if (rank != localIP_prot) {
		if (elements_read <= 3) {
			string errtext = "No flows to display for this host.\n";
			cerr << errtext;
			throw errtext;
		} else {
			stringstream ss;
			ss << elements_read;
			string errtext = "first hpg edge does not contain localIP (v=3). Elements read=" + ss.str() + "\n";
			cerr << "ERROR in get_hpgMetadata3(): " << errtext;
			cerr << "0: ";
			show_edge_data2(&(hpgdata[0]));
			cerr << "1: ";
			show_edge_data2(&(hpgdata[3]));
			cerr << "2: ";
			show_edge_data2(&(hpgdata[6]));
			cerr << "3: ";
			show_edge_data2(&(hpgdata[9]));
			cerr << "4: ";
			show_edge_data2(&(hpgdata[12]));
			throw errtext;
		}
	}
	hpgMetadata[0] = new ChpgMetadata();
	hpgMetadata[0]->graphlet_nr = graphlet_nr;
	hpgMetadata[0]->index = 0;
	int edge_cnt = 1;
	uint64_t total_bytes = 0;

	// Scan data graphlet-by-graphlet and calculate statistics
	// -------------------------------------------------------
	bool finalize = false;
	while (i < elements_read) { // Iterate through all graphlet edges
		assert(graphlet_cnt < rows);
		// Show and update a progress bar for large data sizes to be processed
		if ((i == PROGRESS_THRESHOLD) && ((double) elements_read > 1.5 * (double) PROGRESS_THRESHOLD)) {
			//			double fraction = (double)PROGRESS_THRESHOLD/(double)elements_read;
			if (dbg)
				cout << "Activating progress bar.\n";
			//			signal_show_progressbar(fraction);
		}

		if ((i > PROGRESS_THRESHOLD) && (i % PROGRESS_INCREMENT == 0)) {
			double fraction = (double) i / (double) elements_read;
			if (dbg)
				cout << "Updating progress bar (progress = " << fraction << ")\n";
			//			signal_set_progress(fraction);
			cout << "\rProcessed: " << i / 3 << " edges, " << graphlet_cnt << " graphlets.";
			cout.flush();
		}

		if (finalize) { // Handle special case of last graphlet
			// All edges contained in file are read: complete last graphlet
			int unique_cnt = 0;

			for (nodeiter = node_hm->begin(); nodeiter != node_hm->end(); nodeiter++) {
				unique_cnt++;
			}
			switch (last_rank) { // Use rank of last edge belonging to old rank
				case localIP_prot:
					hpgMetadata[graphlet_cnt]->prot_count = unique_cnt;
					break;
				case prot_localPort:
				case prot_localPortSum:
					hpgMetadata[graphlet_cnt]->srcPort_cnt += unique_cnt;
					break;
				case localPort_remotePort:
				case localPortSum_remotePort:
				case localPort_remotePortSum:
				case localPortSum_remotePortSum:
					hpgMetadata[graphlet_cnt]->dstPort_cnt += unique_cnt;
					break;
				case remotePort_remoteIP:
				case remotePortSum_remoteIP:
				case remotePort_remoteIPsum:
				case remotePortSum_remoteIPsum:
					hpgMetadata[graphlet_cnt]->dstIP_cnt += unique_cnt;
					break;
				case totalBytes:
					hpgMetadata[graphlet_cnt]->bytesForAllFlows = total_bytes;
					break;
				default:
					cerr << "ERROR: invalid rank encountered (not defined for graphlet format v2).\n";
					break;
			}
			hpgMetadata[graphlet_cnt]->edge_count = edge_cnt;
			graphlet_cnt++; // Last graphlet processed
			break;
		}

		if (partition_changed3(rank, last_rank)) {
			// Current rank is complete: no more nodes exist: update statistics of this rank
			int unique_cnt = 0;
			for (nodeiter = node_hm->begin(); nodeiter != node_hm->end(); nodeiter++) {
				unique_cnt++;
			}
			switch (last_rank) { // Use rank of last edge belonging to old rank
				case localIP_prot:
					hpgMetadata[graphlet_cnt]->prot_count = unique_cnt;
					break;
				case prot_localPort:
				case prot_localPortSum:
					hpgMetadata[graphlet_cnt]->srcPort_cnt += unique_cnt;
					break;
				case localPort_remotePort:
				case localPortSum_remotePort:
				case localPort_remotePortSum:
				case localPortSum_remotePortSum:
					hpgMetadata[graphlet_cnt]->dstPort_cnt += unique_cnt;
					break;
				case remotePort_remoteIP:
				case remotePortSum_remoteIP:
				case remotePort_remoteIPsum:
				case remotePortSum_remoteIPsum:
					hpgMetadata[graphlet_cnt]->dstIP_cnt += unique_cnt;
					break;
				case totalBytes:
					hpgMetadata[graphlet_cnt]->bytesForAllFlows = total_bytes;
					break;
				default:
					cerr << "ERROR: invalid rank encountered (not defined for graphlet format v3).\n";
					break;
			}
			// Prepare for next rank data
			delete node_hm;
			node_hm = new NodeHashMap();
			//			node_hm->clear();		// Don't use: very slow for high entry counts (replace by delete/new)
			last_rank = rank;
			if (graphlet_nr != last_graphlet_nr) { // Edge belongs to new graphlet
				hpgMetadata[graphlet_cnt]->edge_count = edge_cnt - 1; // Current edeg belongs to new graphlet
				graphlet_cnt++; // One graphlet processed
				// Prepare for new graphlet
				edge_cnt = 1;
				hpgMetadata[graphlet_cnt] = new ChpgMetadata();
				//				hpgMetadata[graphlet_cnt]->graphlet_nr = graphlet_nr;
				hpgMetadata[graphlet_cnt]->graphlet_nr = graphlet_cnt; // Use graphlet counter as it is not restricted to a max of 8192
				hpgMetadata[graphlet_cnt]->index = i;
				last_graphlet_nr = graphlet_nr;
			}
		}
		if (rank == totalBytes) {
			// We expect at most one such pseudo edge containing the total byte count for current host
			total_bytes = ((uint64_t) hpgdata[i + 1].eightbytevalue.data << 32) + hpgdata[i + 2].eightbytevalue.data;
		} else {
			// Another edge:
			// Update unique right-hand side node counter
			NodeHashKey mykey(hpgdata[i + 2].data);
			nodeiter = node_hm->find(mykey);
			if (nodeiter == node_hm->end()) {
				// It is a new right-hand side node
				(*node_hm)[mykey] = hpgdata[i + 2].eightbytevalue.data;
			}
		}

		i += 3; // Switch to next edge
		if (i >= elements_read) {
			if (edge_cnt > 0)
				finalize = true;
			i -= 3;
		} else {
			graphlet_nr = getGraphletNumber(hpgdata[i + 0]);
			rank = getRank(hpgdata[i + 0]);
			edge_cnt++;
		}
	}
	cout << "\rProcessed: " << i / 3 << " edges, " << graphlet_cnt << " graphlets. Graphlet format is " << graphlet_version << "\n";
	delete node_hm;
#ifdef GUI
	signal_hide_progressbar();
#endif
	if (dbg) {
		cout << "A total of " << i + 3 << " edges processed: " << graphlet_cnt << " graphlets found.\n";
	}

	if (dbg) {
		i = 0;
		while (i < elements_read) { // Iterate through all graphlet edges
			show_edge_data(&hpgdata[i]);
			i += 3; // Switch to next edge
		}
	}
}

/**
 *	Report number of graphlets
 *
 *	\return int Number of graphlets
 */
int ChpgData::get_num_graphlets() {
	return graphlet_cnt;

}

/**
 *	Transform graphlet whose data is contained at "index" in data array "data"
 *	into DOT format and store DOT data in a temporary file with name ".g.dot".
 *
 *	\param index Index into array "data". A valid index is a multiple of three.
 *	\param outfilename Name of output file
 *
 *	\exception std::string Errormessage
 */
void ChpgData::hpg2dot(int index, std::string & outfilename) {
	assert(graphlet_version == 3);
	// version 3 is the only supported one
	try {
		hpg2dot3(index, outfilename);
	} catch (string & e) {
		throw e;
	}
}

/**
 *	Transform graphlet whose data is contained at "index" in data array "data"
 *	into DOT format and store DOT data in a temporary file with name ".g.dot"
 *	Assumes graphlet format v3.
 *
 *	\param index Index into array "data". A valid index is a multiple of three.
 *	\param outfname Name of output file
 *
 *	\exception std::string Errormessage
 */
void ChpgData::hpg2dot3(int index, std::string & outfilename) {
	ofstream outfs;
	try {
		util::open_outfile(outfs, outfilename);
	} catch (...) {
		string errtext = "Opening output file" + outfilename + " failed.\n";
		cerr << "ERROR: " << errtext;
		throw errtext;
	}

	// Write dot header data
	outfs << "graph G { /* Created by hpg2dot3() */\n" <<
				"rankdir=LR;\n" << "node[shape=plaintext,fontsize=16,fontname=\"Arial\"];\n" <<
				"localIP[label=\"localIP\"];" << "protocol[label=\"protocol\"];" << "localPort[label=\"localPort\"];" << "remotePort[label=\"remotePort\"];" << "remoteIP[label=\"remoteIP\"];" <<
					"\"localIP\"--\"protocol\"--\"localPort\"" << "\"localPort\"--\"remotePort\"[label=\"B(pkts)\"]" << "\"remotePort\"--\"remoteIP\"[label=\"fl.(p./fl.)\"]\n" <<
				"node[shape=ellipse];\n";

	hpg_field * value; // Storage for one graph edge in hpg format
	index += 3; // Skip version edge
	value = &hpgdata[index]; // Point to first edge
	if (getRank(value[0]) == version) {
		index += 3; // Skip version edge
		value = &hpgdata[index]; // Point to first edge
	}
	if (dbg5)
		show_edge_data(value);

	NodeHashMap2 * node_hm = new NodeHashMap2();
	NodeHashMap2::iterator nodeiter;

	// 1. Fetch first edge from memory and initialize graphlet from it
	// ***************************************************************
	const bool prefix = true; // Use "k#_" prefix for node identifiers if true

	uint16_t graphlet_nr = getGraphletNumber(value[0]);
	uint16_t last_graphlet_nr = graphlet_nr;
	rank_t rank = getRank(value[0]);
	//cout<<"[r]value[0].fourbytevalue.data:"<<value[0].fourbytevalue.data<<endl;
	//cout<<"[r]value[1].fourbytevalue.data:"<<value[1].fourbytevalue.data<<endl;
	//cout<<"[r]value[2].fourbytevalue.data:"<<value[2].fourbytevalue.data<<endl;

	rank_t last_rank = localIP_prot;
	char st[] = { "k1_" };
	// We expect first edge to have rank=localIP_prot
	// (must be an edge incident to localIP)

	static int counter_for_unique_subgraphs = 0;
	if (rank == localIP_prot) {
		IPv6_addr localIP(value[1].data);
		// Rank list
		if (prefix) {
			outfs << "subgraph " << counter_for_unique_subgraphs++ << " {rank=same;\"localIP\";\"" << st << localIP.toNumericString() << "\";}\n";
			if (dbg5)
				cout << "{rank=same;\"localIP\";\"" << st << localIP.toNumericString() << "\";}\n";
		} else {
			outfs << "subgraph " << counter_for_unique_subgraphs++ << "{ rank=same;\"localIP\";\"" << localIP.toNumericString() << "\";}\n";
		}
		// Node annotation
		if (prefix) {
			outfs /*<< "\""*/<< st << localIP.toNumericString() << /*"\""<<*/"[label=\"" << localIP << "\"];\n";
			if (dbg5)
				cout /*<< "\""*/<< st << localIP.toNumericString() << /*"\""<<*/"[label=\"" << localIP << "\"];\n";
		} else {
			outfs << "\"" << localIP.toNumericString() << "\"[label=\"" << localIP << "\"];\n";
		}
	} else {
		if (elements_read <= 3) { // In case we have filtered all flows for current host
			throw "No flows left.";
		} else {
			stringstream ss;
			ss << elements_read;
			string errtext = "first hpg edge does not contain localIP (v=3). Elements read=" + ss.str() + "\n";
			cerr << "ERROR in hpg2dot3(): " << errtext;
			cerr << "0: ";
			show_edge_data2(&(hpgdata[index - 3]));
			cerr << "1: ";
			show_edge_data2(&(hpgdata[index]));
			cerr << "2: ";
			show_edge_data2(&(hpgdata[index + 3]));
			cerr << "3: ";
			show_edge_data2(&(hpgdata[index + 6]));
			cerr << "4: ";
			show_edge_data2(&(hpgdata[index + 9]));
			throw errtext;
		}
	}

	// 2. Read data from file until one complete graphlet is processed
	// ***************************************************************
	// Here we do infer only the graphlet identified by "index".
	// The resulting DOT description is stored in temporary file "outfilename".
	int i = 0;
	bool finalize = false;
	bool add_semicolon = false;
	while (graphlet_nr == last_graphlet_nr || finalize) { // Do as long as it is the same graphlet as initialized.
		//int foo = index+i;
		//cout<<"[0|"<<"|"<<(&(hpgdata[foo+0].data))<<"|"<<foo<<"]"<<util::bin2hexstring(&(hpgdata[foo+0].data),16)<<"-"<<util::bin2hexstring(&(hpgdata[foo+0].fourbytevalue.data)+2, 2)<<endl;
		//cout<<"[1|"<<"|"<<(&(hpgdata[foo+1].data))<<"|"<<foo<<"]"<<util::bin2hexstring(&(hpgdata[foo+1].data),16)<<"-"<<util::bin2hexstring(&(hpgdata[foo+1].fourbytevalue.data)+2, 2)<<endl;
		//cout<<"[2|"<<"|"<<(&(hpgdata[foo+2].data))<<"|"<<foo<<"]"<<util::bin2hexstring(&(hpgdata[foo+2].data),16)<<"-"<<util::bin2hexstring(&(hpgdata[foo+2].fourbytevalue.data)+2, 2)<<endl;
		// A.) Check if current rank is complete (and finalize it if yes)
		// ==============================================================
		if (partition_changed3(rank, last_rank) || finalize) { // "last_rank" describes old partition that must be finalized now
			// Add semicolon to last edge statement if needed
			if (add_semicolon) {
				outfs << ";\n";
				if (dbg5)
					cout << ";\n";
				add_semicolon = false;
			}
			// Current rank is complete: no more nodes exist

			st[1] = 0x30 + rank2partition(last_rank); // We output always right-hand node

			if (last_rank != totalBytes) { // Suppress for pseudo node that is not visualized

				// a) Output header text for "same rank" list
				outfs << "subgraph " << counter_for_unique_subgraphs++ << " {rank=same;";
				if (dbg5)
					cout << "{rank=same;";

				// b) Output "pseudo node" as descriptive text for old partition
				switch (last_rank) {
					case localIP_prot:
						outfs << "\"protocol\";";
						if (dbg5)
							cout << "\"protocol\";";
						break;

					case prot_localPort:
					case prot_localPortSum:
						outfs << "\"localPort\";";
						if (dbg5)
							cout << "\"localPort\";";
						break;

					case localPort_remotePort:
					case localPortSum_remotePort:
					case localPort_remotePortSum:
					case localPortSum_remotePortSum:
						outfs << "\"remotePort\";";
						if (dbg5)
							cout << "\"remotePort\";";
						break;

					case remotePort_remoteIP:
					case remotePortSum_remoteIP:
					case remotePort_remoteIPsum:
					case remotePortSum_remoteIPsum:
						outfs << "\"remoteIP\";";
						if (dbg5)
							cout << "\"remoteIP\";";
						break;

					case totalBytes: // Currently total byte count is not visualized
					case edge_label: // Edge info is visualized later
					case version: // Ignore
						break;

					default:
						stringstream errtext;
						errtext << "invalid rank encountered (v=3a) at i = " << i << ".\n";
						cerr << "ERROR: " << errtext.str();
						throw errtext.str();
				}
				// c) Output node ids for old partition
				// NOTE: dot language demands unique node ids, otherwise it's the same node (like another with the same id)
				if (prefix)
					st[1] = 0x31 + rank2partition(last_rank);
				for (nodeiter = node_hm->begin(); nodeiter != node_hm->end(); nodeiter++) {
					string value;
					if (rank2partition(last_rank) == 4) {
						IPv6_addr ip_value((nodeiter->second).value.data);
						value = ip_value.toNumericString();
					} else {
						std::stringstream ss;
						ss << (nodeiter->second).value.eightbytevalue.data;
						value = ss.str();
					}
					if (prefix)
						outfs << st;
					if (dbg5)
						cout << st;
					outfs << value << ";";
					if (dbg5)
						cout << value << ";";
				}
				// d) Output tail for "same rank" list
				outfs << "}\n";
				if (dbg5)
					cout << "}\n";
			}
			// e) Output node annotations for all nodes belonging to old partition
			for (nodeiter = node_hm->begin(); nodeiter != node_hm->end(); nodeiter++) {

				uint64_t node = (nodeiter->second).value.eightbytevalue.data;
				IPv6_addr addr_node((nodeiter->second).value.data);
				rank_t cur_rank = (rank_t) ((nodeiter->second).rank);

				switch (cur_rank) { // Use appropriate formats for node labels
					case localIP_prot:
						// Use protocol name
						if (prefix)
							outfs << st;
						if (dbg5)
							cout << st;
						outfs << node << "[label=\"" << util::ipV6ProtocolToString((uint8_t) node) << "\"];\n";
						if (dbg5)
							cout << node << "[label=\"" << util::ipV6ProtocolToString((uint8_t) node) << "\"];\n";
						break;

					case prot_localPort:
						// Use port number
						if (prefix)
							outfs << st;
						if (dbg5)
							cout << st;
						outfs << node << "[label=\"" << (uint16_t) (node & 0xffff) << "\"];\n";
						if (dbg5)
							cout << node << "[label=\"" << (uint16_t) (node & 0xffff) << "\"];\n";
						break;

					case prot_localPortSum:
						// Use summayr node annotation
						if (prefix)
							outfs << st;
						if (dbg5)
							cout << st;
						{
							int con = getConnectionCount((nodeiter->second).value);
							uint32_t role_nr = getRoleNumber((nodeiter->second).value);
							if (con > 0) {
								outfs << node << "[label=\"#con=" << con << getRoleNrString(role_nr) << "\"" << getRoleNumProperty(role_nr) << ", ";
								if (dbg5)
									cout << node << "[label=\"#con=" << con << getRoleNrString(role_nr) << "\"" << getRoleNumProperty(role_nr) << ", ";
								//cout << node << "[label=\"#con=" << con << "\", ";
							} else {
								outfs << node << "[label=\"\", ";
								if (dbg5)
									cout << node << "[label=\"\", ";
							}
							outfs << "shape=box, style=bold]" << ";\n";
							if (dbg5)
								cout << "shape=box, style=bold]" << ";\n";
							break;
						}

					case localPort_remotePort:
					case localPortSum_remotePort:
						// Use port number
						if (prefix)
							outfs << st;
						if (dbg5)
							cout << st;
						//outfs << st; if (dbg5) cout << st;
						outfs << node << "[label=\"" << (uint16_t) (node & 0xffff) << "\"];\n";
						if (dbg5)
							cout << node << "[label=\"" << (uint16_t) (node & 0xffff) << "\"];\n";
						break;

					case localPort_remotePortSum:
					case localPortSum_remotePortSum: {
						int con = getConnectionCount((nodeiter->second).value);
						uint32_t role_nr = getRoleNumber((nodeiter->second).value);
						if (prefix)
							outfs << st;
						if (dbg5)
							cout << st;
						if (con > 0) {
							outfs << node << "[label=\"" << getConnectionsString(con) << getRoleNrString(role_nr) << "\"" << getRoleNumProperty(role_nr) << ", ";
							if (dbg5)
								cout << node << "[label=\"=" << getConnectionsString(con) << getRoleNrString(role_nr) << "\"" << getRoleNumProperty(role_nr) << ", ";
						} else {
							outfs << node << "[label=\"\", ";
							if (dbg5)
								cout << node << "[label=\"\", ";
						}
						outfs << "shape=box, style=bold]" << ";\n";
						if (dbg5)
							cout << "shape=box, style=bold]" << ";\n";
						break;
					}

					case remotePort_remoteIP:
					case remotePortSum_remoteIP:
						if (prefix)
							outfs << st;
						if (dbg5)
							cout << st;
						{ // these brackets are needed because of the variable declaration
							outfs << addr_node.toNumericString() << "[label=\"" << (nodeiter->second).value.data << "\"" << getIpProperty(addr_node) << "];\n";
							if (dbg5)
								cout << addr_node.toNumericString() << "[label=\"" << (nodeiter->second).value.data << "\"" << getIpProperty(addr_node) << "];\n";
						}
						break;

					case remotePort_remoteIPsum:
					case remotePortSum_remoteIPsum:
						if (prefix)
							outfs << st;
						if (dbg5)
							cout << st;
						{
							int con = getConnectionCount((nodeiter->second).value);
							uint32_t role_nr = getRoleNumber((nodeiter->second).value);
							outfs << addr_node.toNumericString() << "[label=\"" << getHostsString(con);
							if (dbg5)
								cout << addr_node.toNumericString() << "[label=\"" << getHostsString(con);
							outfs << getRoleNrString(role_nr) << "\"" << getRoleNumProperty(role_nr) << ", shape=box, style=bold]" << ";\n";
							if (dbg5)
								cout << getRoleNrString(role_nr) << "\"" << getRoleNumProperty(role_nr) << ", shape=box, style=bold]" << ";\n";
							break;
						}

					case totalBytes: // Currently total byte count is not visualized
						break;

					case edge_label: // Edge info is visualized later
						break;

					default:
						stringstream errtext;
						errtext << "invalid rank encountered (v=3b) at i = " << i << ".\n";
						cerr << "ERROR: " << errtext.str();

						cerr << "Detailed error info:\n";
						hpg_field * val = &hpgdata[0];
						cerr << "\thpgdata[0] = ";
						show_edge_data1(val);
						cerr << "\tindex = " << index << endl;
						cerr << "\telements_read = " << elements_read << endl;
						val = &hpgdata[i];
						cerr << "\thpgdata[i = " << i << "] = ";
						show_edge_data1(val);
						int i = index;
						while (i < elements_read) { // Iterate through all graphlet edges
							val = &hpgdata[i];
							cerr << "\ti = " << i << ": ";
							show_edge_data1(val);
							i += 3; // Switch to next edge
						}

						throw errtext.str();
				}
			}
			// f) Check if graphlet is complete or at least all edges have been read
			if (finalize)
				break; // We are done with this graphlet
			if (graphlet_nr != last_graphlet_nr) {
				finalize = true; // Proceed to finalization
				continue;
			}
			// g) Prepare for new partition ("rank")
			node_hm->clear();
			last_rank = rank;
		} // if (partition_changed3(rank, last_rank) || finalize)
		// B.) Output current edge information
		// ===================================
		bool skip = false;
		if (rank != totalBytes) { // Suppress for pseudo node that is not visualized
			if (rank == edge_label) {
				skip = true;
				if (dbg2) {
					cout << "extra, ";
				}
				// Add extra annotation to edge
				outfs << "[label=\"";
				if (dbg5)
					cout << "[label=\"";
				outfs << value[1].eightbytevalue.data; // Bytes for flow associated with prior edge
				if (show_packet_counts && value[2].eightbytevalue.data != 0) { /*flows(packets/flow)*/
					if (value[2].eightbytevalue.data >> 31) {
						//cout << "### found fixed point value " << (value[2]  & 0x7fffffff) << endl;
						// It is a fixed point value with 1 digit behind decimal point
						double fpval = (double) (value[2].eightbytevalue.data & 0x7fffffff) / 10.0;
						outfs << "(" << fpval << ")";
						if (dbg5)
							cout << "(" << fpval << ")";
					} else { /*bytes(packets)*/
						//cout << "### found packet count: " << value[2] << endl;
						outfs << "(" << value[2].eightbytevalue.data << ")";
						if (dbg5)
							cout << "(" << value[2].eightbytevalue.data << ")";
					}
				}
				outfs << "\"]";
				if (dbg5)
					cout << "\"]";
			}
			if (!skip) { // It's a real edge
				int partition = rank2partition(rank);
				if (add_semicolon) {
					outfs << ";\n";
					if (dbg5)
						cout << ";\n";
					add_semicolon = false;
				}
				if (prefix) {
					st[1] = 0x30 + partition; // We output always right-hand node
					//string quote = (partition==1)?"\"":"";
					string quote = "";
					outfs << quote << st;
					if (dbg5)
						cout << quote << st;
				}
				if (partition == 3) {
					// Suppress flow type
					//cerr<<(value[1].eightbytevalue.data)<<"-"<<(value[1].eightbytevalue.data & LOCAL_EPORT0_MASK)<<endl;
					uint64_t node_id = (rank == localPortSum_remotePort || rank == localPortSum_remotePortSum) ? (value[1].eightbytevalue.data)
					      : (value[1].eightbytevalue.data & LOCAL_EPORT0_MASK);
					outfs << node_id << "--";
					if (dbg5)
						cout << node_id << "--";
				} else if (partition == 1) {/*key is ipv6=>longer than 8 byte*/
					IPv6_addr localIP(value[1].data);
					outfs << localIP.toNumericString() /*<<"\""*/<< "--";
					if (dbg5)
						cout << localIP.toNumericString() /*<<"\""*/<< "--";
				} else {
					outfs << value[1].eightbytevalue.data << "--";
					if (dbg5)
						cout << value[1].eightbytevalue.data << "--";
				}

				if (prefix) {
					st[1] = 0x31 + partition; // We output always right-hand node
					outfs << st;
					if (dbg5)
						cout << st;
				}

				if (partition == 2) {
					uint64_t node_id = (rank == prot_localPortSum) ? (value[2].eightbytevalue.data) : (value[2].eightbytevalue.data & LOCAL_EPORT0_MASK);
					outfs << node_id;
					if (dbg5)
						cout << node_id;
				} else if (partition == 4) {
					IPv6_addr addr(value[2].data);
					outfs << addr.toNumericString();
					if (dbg5)
						cout << addr.toNumericString();
				} else {
					outfs << value[2].eightbytevalue.data;
					if (dbg5)
						cout << value[2].eightbytevalue.data;
				}

				// Add edge type information indicating flow direction
				if (partition == 3) {
					uint8_t flowtype = GET_FLOWTYPE(value[1].eightbytevalue.data);
					if (flowtype != 0) {
						outfs << "[";
						if (dbg5)
							cout << "[";
						// HPG data contains flowtype: choose edge type accordingly
						switch (flowtype) {
							case biflow:
								outfs << "style=bold,dir=both,color=black";
								if (dbg5)
									cout << "style=bold,dir=both,color=black";
								break;
							case inflow:
								outfs << "dir=back, color=red";
								if (dbg5)
									cout << "dir=back, color=red";
								break;
							case outflow:
								outfs << "dir=forward, color=red";
								if (dbg5)
									cout << "dir=forward, color=red";
								break;
							case (inflow | unibiflow):
								outfs << "dir=back, color=green";
								if (dbg5)
									cout << "dir=back, color=green";
								break;
							case (outflow | unibiflow):
								outfs << "dir=forward, color=green";
								if (dbg5)
									cout << "dir=forward, color=green";
								break;
							default:
								cerr << "ERROR: encountered invalid flow type: " << (int) flowtype << endl;
								break;
						}
						outfs << "]";
						if (dbg5)
							cout << "]";
					}
				}
				if (partition == 4) { // Port-to-IP edge: choose color
					int color = GET_COLORCODE(value[1].eightbytevalue.data);
					switch (color) {
						case 1: // Red
							outfs << "[color=red]";
							break;
						case 2: // Green
							outfs << "[color=green]";
							break;
						default:
							outfs << "[color=black]";
							break;
					}
				}
				add_semicolon = true;
			}
		}

		// C.) Store right-hand side node of current edge in unique node list
		if (!skip) {
			uint32_t rank2 = rank;
			NodeHashKey2 mykey(rank2, value[2].data);
			nodeiter = node_hm->find(mykey);
			if (nodeiter == node_hm->end()) {
				//uint32_t rnode =  value[2].fourbytevalue.data;
				//if (rank2partition(rank)==2) { rnode = value[2].fourbytevalue.data & LOCAL_EPORT0_MASK; }
				//uint64_t rnode_entry = (((uint64_t)rank)<<32) + (uint64_t)rnode;
				node_hm_value hm_value;
				hm_value.rank = rank;
				hm_value.value = value[2];
				if (rank2partition(rank) == 2) {
					hm_value.value.reset();
					//cerr<<value[2].eightbytevalue.data<<"--"<<(value[2].eightbytevalue.data & LOCAL_EPORT0_MASK)<<endl;
					hm_value.value.eightbytevalue.data = (rank == prot_localPortSum) ? (value[2].eightbytevalue.data) : (value[2].eightbytevalue.data
					      & LOCAL_EPORT0_MASK);
				}
				(*node_hm)[mykey] = hm_value;
			}
		}

		// D.) Get next edge
		i += 3;
		if (index + i >= elements_read) { // Index is at array end or behind: do not use it
			finalize = true; // Graphlet is complete (was last one in list)
			continue;
		}
		value = &hpgdata[index + i]; // Point to next edge
		if (dbg5) {
			show_edge_data(value);
		}
		graphlet_nr = getGraphletNumber(value[0]);
		rank = getRank(value[0]);
		if (graphlet_nr != last_graphlet_nr) {
			finalize = true; // Stay in loop until last rank processed
		}
	}
	outfs << "}\n";
	if (dbg5)
		cout << "}\n";
	if (hap4nfsen && nodeInfos != NULL) {
		outfs << nodeInfos->printNodeInfos();
		if (dbg5) {
			cout << nodeInfos->printNodeInfos();
		}
	}
	outfs.close();
	if (dbg) {
		cout << "Successfully written " << i << " edges to file " << outfilename << endl;
	}
	if (dbg4) {
		for (int j = index - 3; j < index + i; j += 3) {
			show_edge_data2(&hpgdata[j]);
		}
	}
}

/**
 * Formats the connection count
 *
 * \param connection_count Number of connections
 *
 * \return std::string String Containins the formatted count.
 */
inline std::string ChpgData::getConnectionsString(const uint32_t connection_count) {
	return getGenericCountString("con", connection_count);
}

/**
 * Formats the host count
 *
 * \param host_count Number of hosts
 *
 * \return std::string String containing the formatted count
 */
inline std::string ChpgData::getHostsString(const uint32_t host_count) {
	return getGenericCountString("hosts", host_count);
}

/**
 * Formats the count-value of a generic summary node
 *
 * \param type Type of counted objects, e.g. "hosts", "con"
 * \param count The counted number
 *
 * \return std::string String containing the formatted count
 */
inline std::string ChpgData::getGenericCountString(const string & type, const uint32_t count) {
	stringstream ss;
	ss << "#";
	ss << type;
	ss << "=";
	ss << count;
	return ss.str();
}

/**
 * Converts a role number in a string, used for front-end presentation
 *
 * \param role_nr The role number
 *
 * \return std::string String containing the formatted role number
 */
inline string ChpgData::getRoleNrString(const uint32_t role_nr) {
	if (dbg6) { // role numbers are not shown by default
		stringstream ss;
		ss << " rn:";
		ss << role_nr;
		return ss.str();
	}
	return "";
}

/**
 * Extracts the number of connections from a hpg_field
 *
 * \param field A hpg_field
 *
 * \return uint32_t Number of connections
 */
inline uint32_t ChpgData::getConnectionCount(const hpg_field & field) {
	return (field.eightbytevalue.data & FLOW_COUNT_BIT_MASK);
}

/**
 * Extracts the role number from a hpg_field
 *
 * \param field A hpg_field
 *
 * \return uint32_t The role number
 */
inline uint32_t ChpgData::getRoleNumber(const hpg_field & field) {
	return (field.eightbytevalue.data >> ROLE_SHIFT3) & ROLE_NR_BIT_MASK;
}

/**
 * Returns a string containing the custom .dot property "ip"
 *
 * \param ip Value of property
 *
 * \return std::string Contains the property
 */
inline string ChpgData::getIpProperty(const IPv6_addr& ip) {
	stringstream ss;
	ss << ", ip=\"";
	ss << ip;
	ss << "\" ";
	return ss.str();
}

/**
 * Returns a string containing the custom .dot property "rolenum"
 *
 * \param role_number Value of property
 *
 * \return std::string String containing the property
 */
inline std::string ChpgData::getRoleNumProperty(const uint32_t role_number) {
	stringstream ss;
	ss << ", rolnum=\"";
	ss << role_number;
	ss << "\" ";
	return ss.str();
}

/**
 * Extracts the graphlet number from a hpg_field
 *
 * \param field A hpg_field
 *
 * \return uint16_t The extracted graphlet number.
 */
inline uint16_t ChpgData::getGraphletNumber(const hpg_field & field) {
	return field.eightbytevalue.data >> GRAPHLETNUM_SHIFT;
}

/**
 * Extracts rank information from a hpg_field
 *
 * \param field A hpg_field
 *
 * \return rank_t The extracted rank_t(for details, see hpg.h)
 */
inline rank_t ChpgData::getRank(const hpg_field & field) {
	return (rank_t) (field.eightbytevalue.data & 0xf);
}

/**
 *	Check for a partition change.
 *	In hpg version 3 definition we can have more than one rank for a partition.
 *
 *	\param rank	Current rank
 *	\param last_rank Last rank
 *
 *	\return bool True for a partition change
 */
bool ChpgData::partition_changed3(rank_t rank, rank_t last_rank) {
	if (rank == last_rank)
		return false;

	if ((rank == prot_localPort || rank == prot_localPortSum) && (last_rank == prot_localPort || last_rank == prot_localPortSum))
		return false;

	if ((rank == localPort_remotePort || rank == localPortSum_remotePort || rank == localPort_remotePortSum || rank == localPortSum_remotePortSum || rank
	      == edge_label) && (last_rank == localPort_remotePort || last_rank == localPortSum_remotePort || last_rank == localPort_remotePortSum || last_rank
	      == localPortSum_remotePortSum))
		return false;

	if ((rank == remotePort_remoteIP || rank == remotePortSum_remoteIP || rank == remotePort_remoteIPsum || rank == remotePortSum_remoteIPsum || rank
	      == edge_label) && (last_rank == remotePort_remoteIP || last_rank == remotePortSum_remoteIP || last_rank == remotePort_remoteIPsum || last_rank
	      == remotePortSum_remoteIPsum))
		return false;

	return true;
}

/**
 *	Get partition number from rank.
 *
 *	\param	rank	Rank enum code
 *
 *	\return  partition number (0-based, left-to-right)
 */
int ChpgData::rank2partition(rank_t rank) {
	if (graphlet_version < 3)
		return rank;

	switch (rank) {
		case localIP_prot:
			return 1;

		case prot_localPort:
		case prot_localPortSum:
			return 2;

		case localPort_remotePort:
		case localPortSum_remotePort:
		case localPort_remotePortSum:
		case localPortSum_remotePortSum:
			return 3;

		case remotePort_remoteIP:
		case remotePortSum_remoteIP:
		case remotePort_remoteIPsum:
		case remotePortSum_remoteIPsum:
			return 4;
		default:
			return 0;
	}
}

/**
 *	Return first graphlet property object.
 *
 *	\return ChpgMetadata* Pointer to graphlet property object (or NULL if none exists)
 */
ChpgMetadata * ChpgData::get_first_graphlet() {
	if (graphlet_cnt > 0) {
		next_graphlet = 1;
		return hpgMetadata[0];
	} else {
		return NULL;
	}
}

/**
 *	Return first graphlet property object.
 *	Use get_first_graphlet() to scan list from beginning.
 *
 *	\return ChpgMetadata* Pointer to graphlet property object (or NULL if none exists)
 */
ChpgMetadata * ChpgData::get_next_graphlet() {
	if (next_graphlet < graphlet_cnt) {
		return hpgMetadata[next_graphlet++];
	} else {
		return NULL;
	}
}

/**
 *	Get index into data array for a given graphlet number.
 *
 *	\param graphlet_nr graphlet number
 *
 *	\return index into data[]
 *
 *	\exception std::string Errormessage
 */
int ChpgData::get_index(unsigned int graphlet_nr) {
	if (hpgMetadata[graphlet_nr]->graphlet_nr == graphlet_nr) {
		// This is a hit if graphlet numbers start at 0 and are ascending (default)
		if (dbg) {
			cout << "get_index(): HIT -> graphlet number == line number.\n";
		}
		return hpgMetadata[graphlet_nr]->index;
	} else {
		// Search for graphlet_nr in metadata
		for (int i = 0; i < graphlet_cnt; i++) {
			if (hpgMetadata[i]->graphlet_nr == graphlet_nr) {
				return hpgMetadata[i]->index;
				if (dbg) {
					cout << "get_index(): MISS -> graphlet number != line number. Going to search.\n";
				}
			}
		}
		throw "get_index(): MISS -> graphlet number != line number. Going to search."; // Not found!
	}
}

/**
 *	Get total count of egdes.
 *
 *	\return int Edge count
 */
int ChpgData::get_edges() {
	return rows;
}

/**
 *	Print the information contained in a single edge in human readable form to console.
 *
 *	\param value Edge data array consisting of three consecutive uin32_t values
 */
void ChpgData::show_edge_data(hpg_field * value) {
	cout << "## ";
	show_edge_data0(value);
	cout << " ## ";
}

/**
 *	Print the information contained in a single edge in human readable form to console.
 *
 *	\param	value	Edge data array consisting of three consecutive uin32_t values
 */
void ChpgData::show_edge_data1(hpg_field * value) {
	cout << "{ ";
	show_edge_data0(value);
	cout << " }\n";
}

/**
 *	Print the information contained in a single edge in human readable form to console.
 *
 *	\param	value	Edge data array consisting of three consecutive uin32_t values
 */
void ChpgData::show_edge_data2(hpg_field * value) {
	show_edge_data0(value);
	cout << endl;
}

/**
 *	Print the information contained in a single edge in human readable form to console.
 *
 *	\param	value	Edge data array consisting of three consecutive uin32_t values
 */
void ChpgData::show_edge_data0(hpg_field * value) {
	assert(graphlet_version==3);
	// version 3 is the only supported one
	int graphlet_nr;
	rank_t rank;
	string proto;

	graphlet_nr = value[0].eightbytevalue.data >> 4;
	cout << graphlet_nr;
	rank = (rank_t) (value[0].eightbytevalue.data & 0xf);

	switch (rank) { // Use appropriate formats for node labels
		case localIP_prot:
			proto = util::ipV6ProtocolToString((uint8_t) (value[2].eightbytevalue.data & 0xff));
			cout << ", localIP_prot, " << value[1].data << ", " << proto;
			break;

		case prot_localPort:
			proto = util::ipV6ProtocolToString((uint8_t) (value[1].eightbytevalue.data & 0xff));
			cout << ", prot_localPort, " << proto << ", " << (uint16_t) (value[2].eightbytevalue.data & 0xffff);
			break;
		case prot_localPortSum:
			proto = util::ipV6ProtocolToString((uint8_t) (value[1].eightbytevalue.data & 0xff));
			cout << ", prot_localPortSum, " << proto << ", " << (int32_t) value[2].eightbytevalue.data;
			break;

		case localPort_remotePort:
			cout << ", localPort_remotePort, " << (uint16_t) value[1].eightbytevalue.data << ", " << (uint16_t) (value[2].eightbytevalue.data & 0xffff);
			break;
		case localPortSum_remotePort:
			cout << ", localPortSum_remotePort, " << (int32_t) value[1].eightbytevalue.data << ", " << (uint16_t) (value[2].eightbytevalue.data & 0xffff);
			break;
		case localPort_remotePortSum:
			cout << ", localPort_remotePortSum, " << (uint16_t) value[1].eightbytevalue.data << ", " << (int32_t) value[2].eightbytevalue.data;
			break;
		case localPortSum_remotePortSum:
			cout << ", localPortSum_remotePortSum, " << (int32_t) value[1].eightbytevalue.data << ", " << (int32_t) value[2].eightbytevalue.data;
			break;

		case remotePort_remoteIP:
			cout << ", remotePort_remoteIP, " << (uint16_t) value[1].eightbytevalue.data << ", " << value[2].data;
			break;
		case remotePortSum_remoteIP:
			cout << ", remotePortSum_remoteIP, " << (int32_t) value[1].eightbytevalue.data << ", " << value[2].data;
			break;
		case remotePort_remoteIPsum:
			cout << ", remotePort_remoteIPsum, " << (uint16_t) value[1].eightbytevalue.data << ", " << (int32_t) value[2].eightbytevalue.data;
			cout << " (" << (int16_t) (value[2].eightbytevalue.data >> 16) << ", " << (int16_t) (value[2].eightbytevalue.data & 0xffff);
			break;
		case remotePortSum_remoteIPsum:
			cout << ", remotePortSum_remoteIPsum, " << (uint16_t) value[1].eightbytevalue.data << ", " << (int32_t) value[2].eightbytevalue.data;
			cout << " (" << (int16_t) (value[2].eightbytevalue.data >> 16) << ", " << (int16_t) (value[2].eightbytevalue.data & 0xffff);
			break;

		case edge_label:
			cout << ", edge_label, " << (uint32_t) value[1].eightbytevalue.data << ", " << (uint32_t) value[2].eightbytevalue.data;
			break;

		case totalBytes:
			cout << ", totalBytes, " << (uint32_t) value[1].eightbytevalue.data << ", " << (uint32_t) value[2].eightbytevalue.data;
			break;

		case version:
			cout << ", version, " << (uint32_t) value[1].eightbytevalue.data << ", " << (uint32_t) value[2].eightbytevalue.data;
			break;

		default:
			cerr << ", ?(rank=" << rank << ")\n";
			break;
	}
}

/**
 *	Print graphlet edge data in human readable form to console.
 *
 *	\param index1 Edge index where to start
 *	\param index2 Edge index where to stop
 */
void ChpgData::show_data(int index1, int index2) {
	int graphlet_nr;
	rank_t rank;
	string ipv6;
	string proto;

	for (int i = 3 * index1; i < 3 * index2; i += 3) {
		if (i >= elements_read)
			break;
		graphlet_nr = hpgdata[i].eightbytevalue.data >> 4;
		cout << graphlet_nr;
		rank = (rank_t) (hpgdata[i].eightbytevalue.data & 0xf);
		switch (rank) { // Use appropriate formats for node labels
			case srcIP_prot: // prot
				proto = util::ipV6ProtocolToString((uint8_t) (hpgdata[i + 2].eightbytevalue.data & 0xff));
				cout << ", srcIP_prot, " << hpgdata[i + 1].data << ", " << proto << endl;
				break;
			case prot_dstIP: // dstIP
				proto = util::ipV6ProtocolToString((uint8_t) (hpgdata[i + 1].eightbytevalue.data & 0xff));
				cout << ", prot_dstIP, " << proto << ", " << (uint32_t) hpgdata[i + 2].eightbytevalue.data << endl;
				break;
			case dstIP_srcPort: // srcPort
				cout << ", dstIP_srcPort, " << hpgdata[i + 1].data << ", " << (uint16_t) (hpgdata[i + 2].eightbytevalue.data & 0xffff) << endl;
				break;
			case srcPort_dstPort: // dstPort
				cout << ", srcPort_dstPort, " << (uint16_t) hpgdata[i + 1].eightbytevalue.data << ", " << (uint16_t) (hpgdata[i + 2].eightbytevalue.data & 0xffff)
				      << endl;
				break;
			case dstPort_dstIP: // dstIP
				cout << ", dstPort_dstIP, " << (uint16_t) hpgdata[i + 1].eightbytevalue.data << ", " << hpgdata[i + 2].data << endl;
				break;
			default:
				cerr << "ERROR: invalid rank encountered.\n";
				break;
		}
	}
}

#ifdef MAIN_TEST
/**
 *	Code for unit test.
 */
int main()
{
	cout << "\nUnit test of module gdata.cpp.\n";
	cout << "==============================\n\n";

	ChpgData cd1;

	// Fill data from filedata[]:
	cd1.read_hpg_memory(filedata1, sizeof(filedata1));
	cd1.hpg2dot(0, "test1.dot");
	cout << "Test output written to file test1.dot.\n";
	cout << "Check test file using: dot -Tpdf test1.dot -o test1.pdf.\n";

	ChpgData cd2;

	// Fill data from filedata[]:
	cd2.read_hpg_memory(filedata2, sizeof(filedata2));
	cd2.hpg2dot(0, "test2.dot");
	cout << "Test output written to file test2.dot.\n";
	cout << "Check test file using: dot -Tpdf test2.dot -o test2.pdf.\n";

	cout << "Expected graph is:\n\n";
	cout << "                 |--0.0.0.3-----7--|\n";
	cout << "         |--TCP--|                 |--10\n";
	cout << "0.0.0.1--|       |--0.0.0.4-----8--|\n";
	cout << "         |\n";
	cout << "         |                         |--11\n";
	cout << "         |--UDP-----0.0.0.5-----9--|\n";
	cout << "                                   |--12\n\n";

	cout << "Done.\n\n";
	return 0;
}
#endif

