/**
 *	\file		mk_cflows.cpp
 *	\brief	Create a series of flows from a text file specification
 *				and store them in a *.gz file using the cflow_t format.
 */
#include <iostream>
#include <sstream>
#include <arpa/inet.h>
#include <netinet/in.h>	// IP protocol type definitions
#include <boost/program_options.hpp>

#include "cflow.h"
#include "gfilter_cflow.h"

using namespace std;

uint8_t ip_proto(string & protostr, int flow_count) {
	if (protostr == "udp")
		return IPPROTO_UDP;
	if (protostr == "tcp")
		return IPPROTO_TCP;
	if (protostr == "icmp")
		return IPPROTO_ICMP;
	cerr << "ERROR: not supported protocol name \"" << protostr << "\" (flow: " << flow_count << ")\n\n";
	exit(1);
}

uint8_t flowdir2flowtype(string flowdir, int flow_count) {
	if (flowdir == "in")
		return (flow_type_t) inflow;
	if (flowdir == "out")
		return (flow_type_t) outflow;
	if (flowdir == "bi")
		return (flow_type_t) biflow;
	if (flowdir == "qin")
		return ((flow_type_t) inflow | (flow_type_t) unibiflow);
	if (flowdir == "qout")
		return ((flow_type_t) outflow | (flow_type_t) unibiflow);
	cerr << "ERROR: not supported flow direction \"" << flowdir << "\" (flow: " << flow_count << ")\n";
	exit(1);
}

/**
 *	Convert UTC date/time string to unix seconds.
 *
 *	\param timestring UTC date/time string using format YYYYMMDD.hhmm or YYYYMMDD.hhmmss
 *
 *	\return Unix seconds
 */
int string2utime(string timestring) {
	static struct tm tm;
	static time_t t;

	if (timestring.size() == 13) {
		// Short format: seconds are missing (YYYYMMDD.hhmm)
		if (strptime(timestring.c_str(), "%Y%m%d.%H%M", &tm) == NULL) {
			printf("\nERROR: invalid date/time string (strptime() failed).!\n\n");
			exit(1);
		}
	} else { // Must be long format (YYYYMMDD.hhmmss)
		// Short format: seconds are missing (YYYYMMDD.hhmm)
		if (strptime(timestring.c_str(), "%Y%m%d.%H%M%S", &tm) == NULL) {
			printf("\nERROR: invalid date/time string (strptime() failed).!\n\n");
			exit(1);
		}
	}

	tm.tm_isdst = -1; /* Not set by strptime(); tells mktime()
	 to determine whether daylight saving time
	 is in effect */
	t = mktime(&tm);
	if (t == -1) {
		printf("\nERROR: mktime() failed.!\n\n");
		exit(1);
	}

	uint32_t time = t;
	return time;
}

void line_error() {
	cerr << "ERROR: invalid input format.\n\n";
	exit(1);
}

int main(int argc, char * argv[]) {
	// 1. Process command line
	// ***********************
	//
	// Check for needed command line arguments and process supported command line options
	boost::program_options::variables_map variablesMap;
	boost::program_options::options_description desc("Allowed options");

	int formatType;
	string outputFile;

	try {
		desc.add_options()
				("inputfile,i", boost::program_options::value<string>(), "File to read")
				("outputfile,o", boost::program_options::value<string>(&outputFile)->default_value("flows.gz"),"Name of output file")
				("formattype,t", boost::program_options::value<int>(&formatType)->default_value(1), "Input format type")
				("verbose,v", "Verbose output")
				("help,h", "show this help message")
		;

		boost::program_options::positional_options_description posOpt;
		posOpt.add("inputfile", 1);

		boost::program_options::store(boost::program_options::parse_command_line(argc, argv, desc), variablesMap);
		boost::program_options::store(boost::program_options::command_line_parser(argc, argv).options(desc).positional(posOpt).run(), variablesMap);
		boost::program_options::notify(variablesMap);
	} catch (std::exception & e) {
		std::cerr << "Error: " << e.what() << std::endl;
		exit(1);
	}

	if (variablesMap.count("help")) {
		cerr << desc;
		exit(0);
	}

	if (!variablesMap.count("inputfile")) {
		cerr << desc;
		exit(1);
	}

	bool verbose = variablesMap.count("verbose");
	bool debug = variablesMap.count("debug");
	string infilename = variablesMap["inputfile"].as<string>();
	int intype = variablesMap["formattype"].as<int>();

	// Open input file
	ifstream infs;
	infs.open(variablesMap["inputfile"].as<string>().c_str(), ios::in);
	if (!infs.is_open()) {
		cerr << "ERROR: could not open input file \"" << infilename << "\".\n";
		return 1;
	}

	// Parse input file for flow specifications and make flows out of them.

	if (verbose)
		cout << "Input file type: " << intype << endl;

	int flow_count = 0;
	CFlowList flowlist;
	while (infs.good()) {

		// Get next line and extract feature specs
		//
		// Defined are 3 types of input data: 
		// type 1: localIP, localPort, remotePort, remoteIP, protocol, flowdirection
		// type 2: localIP, localPort, remotePort, remoteIP, protocol, flowdirection, bytes, packets
		// type 3: localIP, localPort, remotePort, remoteIP, protocol, flowdirection, bytes, packets, start, startms, lengthms
		// with:
		// protocol: 3-letter code, one out of [udp, tcp, icmp]
		// flowdirection: code, one out of [in, out, bi, qin, qout]
		// start: YYYYMMDD-hh:mm:ss
		// startms: milliseconds part of start time
		// lengthms: flow length in ms (integer value)

		char s[256];
		infs.getline(s, 256);
		// Remove any commas
		string rawline(s);
		string line0("");

		for (unsigned int i = 0; i < rawline.size(); i++) {
			char c = rawline[i];
			if (c == ',') {
				line0 += ' ';
			} else {
				line0 += c;
			}
		}
		stringstream line;
		line << line0;

		if (debug)
			cout << "refined input line: " << line0 << endl;

		string localIPstr, protostr, remoteIPstr, flowdir;
		uint16_t localPort, remotePort;

		line >> localIPstr;
		if (!line.good()) {
			if (line.eof())
				break; // Empty line
			line_error(); // Some other error
		}
		if (verbose)
			cout << "\nflow " << flow_count << ": ";
		if (verbose)
			cout << localIPstr << ", ";

		line >> localPort;
		if (verbose)
			cout << localPort << ", ";
		if (!line.good())
			line_error(); // Probably an incomplete line

		line >> remoteIPstr;
		if (verbose)
			cout << remoteIPstr << ", ";
		if (!line.good())
			line_error(); // Probably an incomplete line

		line >> remotePort;
		if (verbose)
			cout << remotePort << ", ";
		if (!line.good())
			line_error(); // Probably an incomplete line

		line >> protostr;
		if (verbose)
			cout << protostr << ", ";
		if (!line.good())
			line_error(); // Probably an incomplete line

		line >> flowdir;
		if (verbose)
			cout << flowdir;

		uint32_t dPkts = 0;
		uint64_t dOctets = 0;
		if (intype >= 2) {
			if (!line.good())
				line_error(); // Probably an incomplete line

			line >> dOctets;
			if (verbose)
				cout << ", " << dOctets << ", ";
			if (!line.good())
				line_error(); // Probably an incomplete line

			line >> dPkts;
			if (verbose)
				cout << dPkts;
		} else {
			dOctets = 1;
			dPkts = 1;
		}

		string start_dt;
		int unixseconds;
		uint64_t startMs;
		uint32_t durationMs;

		if (intype == 3) {
			if (!line.good())
				line_error(); // Probably an incomplete line

			line >> start_dt;
			if (verbose)
				cout << ", " << start_dt << ", ";
			if (!line.good())
				line_error(); // Probably an incomplete line
			unixseconds = string2utime(start_dt);

			uint32_t startms;
			line >> startms;
			if (verbose)
				cout << startms << ", ";
			if (!line.good())
				line_error(); // Probably an incomplete line
			startMs = (((uint64_t) unixseconds) * 1000) + startms;

			line >> durationMs;
			if (verbose)
				cout << durationMs;
		}

		// Make a flow from specs
		// NOTE: test flows must implement biflow-pairing (i.e. there should not
		// be unmerged mergable flows)
		// Otherwise they can not be correctly processed by HAPviewer.
		cflow_t flow;
		switch (intype) {
		case 3:
			flow.startMs = startMs;
			flow.durationMs = durationMs;
		case 1:
			flow.dOctets = dOctets;
			flow.dPkts = dPkts;
			// Short spec
			flow.localIP = localIPstr;
			flow.localPort = localPort;
			flow.remoteIP = remoteIPstr;
			flow.remotePort = remotePort;
			flow.prot = ip_proto(protostr, flow_count);
			flow.flowtype = flowdir2flowtype(flowdir, flow_count);
			break;
		default:
			cerr << "ERROR: unsupported input format type (valid are 1, 2 or 3)." << endl;
			exit(1);
		}
		flowlist.push_back(flow);
		flow_count++;
	}
	GFilter_cflow6 tmpGFcflow6;
	tmpGFcflow6.write_file(outputFile, flowlist, false);
	infs.close();
	cout << endl << flow_count << " flows written to file \"" << outputFile << "\"" << endl;

	return 0;

}

