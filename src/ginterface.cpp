/**
 *	\file ginterface.cpp
 *	\brief Interface to library version of HAPviewer.
 *	By use of this interface network traffic data can be visualized
 *	as a HAP graphlet.
 */
#include <unistd.h>
#include <netinet/in_systm.h>
#include <sys/socket.h>

#include "ginterface.h"
#include "gutil.h"

using namespace std;

#ifdef NDEBUG
const bool debug =false;
const bool debug2=false;
#else
const bool debug = true;
const bool debug2 = false;
#endif

/**
 *	Constructor: default
 */
CInterface::CInterface() {
	flowImport = NULL;
	hpgData = NULL;
	nodeInfos = NULL;
}

/**
 *	Destructor: clean up heap if needed
 */
CInterface::~CInterface() {
	if (hap4nfsen && nodeInfos != NULL) {
		delete nodeInfos;
	}
}

/**
 *	Process binary input data to binary graphlet description and store in a file using hpg format.
 *
 *	\param	in_filename Name of a traffic input file
 *	\param	out_filename Name of binray graph data output file
 *	\param	itype	File type of input file
 *	\param	localIP	IP address of host for which first graphlet has to be created (use 0 for first localIP)
 *							(the first localIP has always the lowest numeric value due to the sort order of the flowlist)
 *	\param	host_count Count of hosts (in terms of flows) to include in output file
 *
 *	\return	TRUE if conversion was successful
 */
bool CInterface::handle_binary_import(std::string & in_filename, std::string & out_filename, IPv6_addr localIP, int host_count) {
	if (flowImport != NULL) {
		delete flowImport;
		flowImport = NULL;
	}

	IPv6_addr local_net = localIP;
	IPv6_addr netmask = IPv6_addr::getNetmask(128);

	// Derive output from input file name and initialize import.
	try {
		flowImport = new CImport(in_filename, out_filename, prefs);
		flowImport->set_desummarized_roles(desum_role_nums);
		flowImport->set_no_reverse_index(); // Only needed for HAPviewer operation
	} catch (string & errtext) {
		// Upon failed open on filename given
		cerr << errtext << endl;
		return false;
	}

	// Import traffic data to memory-based flowlist.
	try {
		flowImport->read_file(localIP, netmask);
	} catch (string & errtext) {
		// Upon failed open on filename given
		cerr << errtext << endl;
		return false;
	}

	if (debug2)
		flowImport->print_flowlist(100);

	// Create HPG file from memory-based flowlist
	if (!flowImport->set_localIP(localIP, host_count))
		return false;

	try {
		flowImport->cflow2hpg();
	}
	catch(string & e) {
		cerr << e << endl;
		return false;
	}
	nodeInfos = flowImport->nodeInfos;

	return true;
}

/**
 *	Process a binary graphlet description to a text description using dot format.
 *
 *	\param	in_filename	Name of binary graph data file (of file type hpg)
 *	\param	out_filename Name of graph data output file (of file type dot)
 */
bool CInterface::handle_hpg_import(std::string & in_filename, std::string & out_filename) {
	// Dismiss old hpg model (if any)
	if (hpgData != NULL) {
		delete hpgData;
		hpgData = NULL;
	}

	// Read hpg data into memory and extract metadata
	try {
		hpgData = new ChpgData(in_filename);
		hpgData->read_hpg_file();
		hpgData->nodeInfos = nodeInfos;
		hpgData->hpg2dot(0, out_filename);
	} catch (string & errtext) {
		// Upon failed open on filename given
		cerr << "ERROR during processing of file " << in_filename << endl;
		cerr << errtext << endl;
		return false;
	}

	return true;
}

/**
 *	Process a traffic data input file to a GraphViz-compatible graphics description output file.
 *
 *	\param	in_filename		Name of traffic data input file 
 *	\param	hpg_filename	Name of intermediate binary graph description (in hpg format)
 *	\param	dot_filename	Name of GraphViz-compatible textual graph description file (in dot format)
 *	\param	IP_str			Dotted IP address of host for which graphlet has to be prepared
 *
 *	\return	bool				True if hpg creation ended successfully
 */
bool CInterface::handle_get_graphlet(std::string & in_filename, std::string & hpg_filename, std::string & dot_filename, std::string IP_str) {
	// Get binary representation of IP addresss
	IPv6_addr localIP;
	try {
		localIP = IP_str;
	} catch (string & e) {
		cerr << "ERROR: cannot recognize IP address <" << IP_str << ">: " << e << endl;
		return false;
	}

	// Now we are ready to import data from file

	//if (debug)
	cout << "localIP = " << localIP << endl;
	bool ok;
	ok = handle_binary_import(in_filename, hpg_filename, localIP, 1);

	if (ok)
		return handle_hpg_import(hpg_filename, dot_filename);
	return false;
}

/**
 *	Main interface function to obtain a GraphViz-compatible graphlet description from a binary traffic 
 *	data input file. Function taking input file and options and returning a graphviz .dot file for
 *	an external visualization.
 *
 *	\param	in_filename			Name of a traffic data file
 *	\param	dot_filename		Name of GraphViz-compatible graph description file (in dot format)
 *	\param	IP_str				Dotted IP address of host for which graphlet has to be prepared
 *	\param	summarize_flags	Configuration flags for summarization
 *	\param	filter_flags		Configuration flags for filtering
 *	\param	desum_role_nums	role numbers to be desummarized
 *
 *	\return	bool TRUE if dot file has been successfully prepared, FALSE otherwise
 */
bool CInterface::get_graphlet(std::string in_filename, std::string & dot_filename, std::string IP_str, summarize_flags_t summarize_flags,
      filter_flags_t filter_flags, const desummarizedRoles & desum_role_numbers) {
	// Set summarization options
	if (summarize_flags & summarize_client_roles) {
		prefs.summarize_clt_roles = true;
	} else {
		prefs.summarize_clt_roles = false;
	}
	if (summarize_flags & summarize_multi_client_roles) {
		prefs.summarize_multclt_roles = true;
	} else {
		prefs.summarize_multclt_roles = false;
	}
	if (summarize_flags & summarize_server_roles) {
		prefs.summarize_srv_roles = true;
	} else {
		prefs.summarize_srv_roles = false;
	}
	if (summarize_flags & summarize_p2p_roles) {
		prefs.summarize_p2p_roles = true;
	} else {
		prefs.summarize_p2p_roles = false;
	}
	prefs.summarize_biflows = true;
	prefs.summarize_uniflows = true;

	// Set filter options
	if (filter_flags & filter_biflows) {
		prefs.filter_biflows = true;
	} else {
		prefs.filter_biflows = false;
	}
	if (filter_flags & filter_uniflows) {
		prefs.filter_uniflows = true;
	} else {
		prefs.filter_uniflows = false;
	}
	if (filter_flags & filter_tcp) {
		prefs.filter_TCP = true;
	} else {
		prefs.filter_TCP = false;
	}
	if (filter_flags & filter_udp) {
		prefs.filter_UDP = true;
	} else {
		prefs.filter_UDP = false;
	}
	if (filter_flags & filter_icmp) {
		prefs.filter_ICMP = true;
	} else {
		prefs.filter_ICMP = false;
	}
	if (filter_flags & filter_other) {
		prefs.filter_OTHER = true;
	} else {
		prefs.filter_OTHER = false;
	}
	prefs.filter_unprod_inflows = false;
	prefs.filter_unprod_outflows = false;
	if (debug)
		prefs.show_prefs();

	string hpg_filename = in_filename + ".hpg";

	bool ok = false;

	desum_role_nums.insert(desum_role_numbers.begin(), desum_role_numbers.end());

	ok = handle_get_graphlet(in_filename, hpg_filename, dot_filename, IP_str);

	return ok;
}

/**
 *	Function taking input file in cflow_t format with options and returning a 
 *	graph database file stored in HPG format.
 *
 *	\param	in_filename Name of a traffic input file
 *	\param	hpg_filename Name of HPG binary graph data output file
 *	\param	localIP	IP address of host for which first graphlet has to be created (use 0 for first localIP)
 *							(the first localIP has always the lowest numeric value due to the sort order of the flowlist)
 *	\param	host_count Count of hosts (in terms of flows) to include in output file
 *
 *	\return	bool TRUE if conversion was successful
 */
bool CInterface::get_hpg_file(string in_filename, std::string & hpg_filename, IPv6_addr localIP, int host_count) {
	size_t gz_pos = in_filename.rfind(".gz");
	if (gz_pos == string::npos) {
		cerr << "\nERROR: file name suffix mismatch (expected, but not found: *.gz).\n\n";
		return false;
	}

	// At this point we know that input file name ends in *.gz
	// Replace .gz by .hpg for output file name.
	hpg_filename = in_filename.substr(0, in_filename.size() - 2);
	hpg_filename += "hpg";

	// Create graph database and store in file using HPG format.
	bool ok = handle_binary_import(in_filename, hpg_filename, localIP, host_count);

	return ok;
}

