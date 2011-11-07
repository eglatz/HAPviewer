/**
 *	\file	mk_test_cflows.cpp
 *	\brief Create a series of test flows and store them in a *.gz file using cflow_t format.
 */

#include <iostream>
#include <arpa/inet.h>
#include <netinet/in.h>		// IP protocol type definitions

#include <boost/program_options.hpp>

#include "cflow.h"
#include "IPv6_addr.h"
#include "gfilter_cflow.h"

using namespace std;

int main(int argc, char * argv[]) {

	// 1. Process command line
	// ***********************
	//
	// Check for needed command line arguments and process supported command line options
	boost::program_options::variables_map variablesMap;
	boost::program_options::options_description desc("Allowed options");

	string outputFile;
	unsigned int max_flow_count = -1;
	bool append = false;
	bool debug = false;

	try {
		desc.add_options()
				("count,c", boost::program_options::value<unsigned int>(), "Maximal count of flows to write")
				("outputfile,o", boost::program_options::value<string>(&outputFile)->default_value("flows.gz"),"Name of output file")
				("help,h", "show this help message")
				("debug,d", "print some debug information")
				("append,a", "Try to append to a possibly already existing file");

		boost::program_options::positional_options_description posOpt;
		posOpt.add("outputfile", 1);

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

	if (!variablesMap.count("outputfile")) {
		cerr << desc;
		exit(1);
	}

	if(variablesMap.count("count"))
		max_flow_count = variablesMap["count"].as<unsigned int>();

	if(variablesMap.count("append"))
		append = true;

	if(variablesMap.count("debug"))
		debug = true;

	if(debug)
		cout << "sizeof(cflow_t): " << sizeof(cflow_t) << endl;

	// NOTE: test flows must include biflow-pairing 
	// ********************************************
	// Otherwise they can not be correctly processed by HAPviewer.

	CFlowList flowlist;
	// Host 0
	// ======
	// Group 0: server role TCP
	flowlist.push_back(cflow_t(IPv6_addr("10.0.1.1"), 80, IPv6_addr("10.0.99.1"), 1100, IPPROTO_TCP, inflow, 0, 0, 1000, 1));
	flowlist.push_back(cflow_t(IPv6_addr("10.0.1.1"), 80, IPv6_addr("10.0.99.2"), 1100, IPPROTO_TCP, biflow, 0, 0, 2000, 2));
	flowlist.push_back(cflow_t(IPv6_addr("10.0.1.1"), 80, IPv6_addr("10.0.99.2"), 1101, IPPROTO_TCP, unibiflow | outflow, 0, 0, 5000, 5));

	// Group 1: client role TCP
	flowlist.push_back(cflow_t(IPv6_addr("10.0.1.1"), 2000, IPv6_addr("10.0.99.3"), 4000, IPPROTO_TCP, outflow, 0, 0, 100, 1));
	flowlist.push_back(cflow_t(IPv6_addr("10.0.1.1"), 2001, IPv6_addr("10.0.99.3"), 4000, IPPROTO_TCP, outflow, 0, 0, 100, 1));
	flowlist.push_back(cflow_t(IPv6_addr("10.0.1.1"), 2002, IPv6_addr("10.0.99.3"), 4000, IPPROTO_TCP, biflow, 0, 0, 200, 2));
	flowlist.push_back(cflow_t(IPv6_addr("10.0.1.1"), 2003, IPv6_addr("10.0.99.3"), 4000, IPPROTO_TCP, inflow | unibiflow, 0, 0, 500, 5));

	// Group 2: client role UDP
	flowlist.push_back(cflow_t(IPv6_addr("10.0.1.1"), 2000, IPv6_addr("10.0.99.3"), 4000, IPPROTO_UDP, outflow, 0, 0, 200, 1));
	flowlist.push_back(cflow_t(IPv6_addr("10.0.1.1"), 2001, IPv6_addr("10.0.99.3"), 4000, IPPROTO_UDP, biflow, 0, 0, 400, 2));
	flowlist.push_back(cflow_t(IPv6_addr("10.0.1.1"), 2003, IPv6_addr("10.0.99.3"), 4000, IPPROTO_UDP, inflow | unibiflow, 0, 0, 1000, 5));

	// Host 1
	// ======
	// Group 0: P2P role UDP
	flowlist.push_back(cflow_t(IPv6_addr("10.0.1.2"), 1300, IPv6_addr("10.0.99.3"), 3000, IPPROTO_UDP, biflow, 0, 0, 10000, 10));
	flowlist.push_back(cflow_t(IPv6_addr("10.0.1.2"), 1301, IPv6_addr("10.0.99.4"), 3000, IPPROTO_UDP, biflow, 0, 0, 20000, 20));
	flowlist.push_back(cflow_t(IPv6_addr("10.0.1.2"), 1302, IPv6_addr("10.0.99.5"), 3000, IPPROTO_UDP, biflow, 0, 0, 30000, 30));
	flowlist.push_back(cflow_t(IPv6_addr("10.0.1.2"), 1303, IPv6_addr("10.0.99.6"), 3000, IPPROTO_UDP, biflow, 0, 0, 40000, 40));

	// Group 1: TCP in + ICMP reply, ICMP receive
	flowlist.push_back(cflow_t(IPv6_addr("10.0.1.2"), 135, IPv6_addr("10.0.99.3"), 1333, IPPROTO_TCP, inflow, 0, 0, 52, 1));
	flowlist.push_back(cflow_t(IPv6_addr("10.0.1.2"), 0, IPv6_addr("10.0.99.3"), 0, IPPROTO_ICMP, outflow, 0, 0, 100, 1));
	flowlist.push_back(cflow_t(IPv6_addr("10.0.1.2"), 0, IPv6_addr("10.0.99.9"), 0, IPPROTO_ICMP, inflow, 0, 0, 100, 1));

	// Host 2
	// ======
	// Group 0: client role to TCP remote port 80
	flowlist.push_back(cflow_t(IPv6_addr("10.0.1.3"), 9300, IPv6_addr("10.0.99.3"), 80, IPPROTO_TCP, biflow, 0, 0, 10000, 10));
	flowlist.push_back(cflow_t(IPv6_addr("10.0.1.3"), 9301, IPv6_addr("10.0.99.3"), 80, IPPROTO_TCP, biflow, 0, 0, 20000, 20));
	flowlist.push_back(cflow_t(IPv6_addr("10.0.1.3"), 9302, IPv6_addr("10.0.99.3"), 80, IPPROTO_TCP, biflow, 0, 0, 30000, 30));
	flowlist.push_back(cflow_t(IPv6_addr("10.0.1.3"), 9303, IPv6_addr("10.0.99.3"), 80, IPPROTO_TCP, biflow, 0, 0, 40000, 40));
	flowlist.push_back(cflow_t(IPv6_addr("10.0.1.3"), 9304, IPv6_addr("10.0.99.3"), 80, IPPROTO_TCP, inflow, 0, 0, 112, 40));

	// Group 1: TCP in + ICMP reply, ICMP receive
	flowlist.push_back(cflow_t(IPv6_addr("10.0.1.3"), 135, IPv6_addr("10.0.99.3"), 1333, IPPROTO_TCP, inflow, 0, 0, 52, 1));
	flowlist.push_back(cflow_t(IPv6_addr("10.0.1.3"), 0, IPv6_addr("10.0.99.3"), 0, IPPROTO_ICMP, outflow, 0, 0, 100, 1));
	flowlist.push_back(cflow_t(IPv6_addr("10.0.1.3"), 0, IPv6_addr("10.0.99.9"), 0, IPPROTO_ICMP, inflow, 0, 0, 100, 1));

	// Group 2: client role to UDP remote port 80
	flowlist.push_back(cflow_t(IPv6_addr("10.0.1.3"), 9300, IPv6_addr("10.0.99.3"), 80, IPPROTO_UDP, biflow, 0, 0, 10000, 10));
	flowlist.push_back(cflow_t(IPv6_addr("10.0.1.3"), 9301, IPv6_addr("10.0.99.3"), 80, IPPROTO_UDP, biflow, 0, 0, 20000, 20));
	flowlist.push_back(cflow_t(IPv6_addr("10.0.1.3"), 9302, IPv6_addr("10.0.99.3"), 80, IPPROTO_UDP, biflow, 0, 0, 30000, 30));
	flowlist.push_back(cflow_t(IPv6_addr("10.0.1.3"), 9303, IPv6_addr("10.0.99.3"), 80, IPPROTO_UDP, biflow, 0, 0, 40000, 40));
	flowlist.push_back(cflow_t(IPv6_addr("10.0.1.3"), 9304, IPv6_addr("10.0.99.3"), 80, IPPROTO_UDP, inflow | unibiflow, 0, 0, 112, 40));

	// Host 3
	// ======
	// Group 0: server role TCP
	flowlist.push_back(cflow_t(IPv6_addr("10.0.1.4"), 80, IPv6_addr("10.0.99.1"), 1100, IPPROTO_TCP, biflow, 0, 0, 1000, 1));
	flowlist.push_back(cflow_t(IPv6_addr("10.0.1.4"), 80, IPv6_addr("10.0.99.1"), 1101, IPPROTO_TCP, biflow, 0, 0, 2000, 2));
	flowlist.push_back(cflow_t(IPv6_addr("10.0.1.4"), 80, IPv6_addr("10.0.99.1"), 1102, IPPROTO_TCP, biflow, 0, 0, 5000, 5));

	// Group1: server role TCP
	flowlist.push_back(cflow_t(IPv6_addr("10.0.1.4"), 81, IPv6_addr("10.0.99.2"), 1110, IPPROTO_TCP, biflow, 0, 0, 1000, 1));
	flowlist.push_back(cflow_t(IPv6_addr("10.0.1.4"), 81, IPv6_addr("10.0.99.2"), 1111, IPPROTO_TCP, biflow, 0, 0, 2000, 2));
	flowlist.push_back(cflow_t(IPv6_addr("10.0.1.4"), 81, IPv6_addr("10.0.99.2"), 1112, IPPROTO_TCP, unibiflow | outflow, 0, 0, 5000, 5));
	flowlist.push_back(cflow_t(IPv6_addr("10.0.1.4"), 81, IPv6_addr("10.0.99.3"), 1110, IPPROTO_TCP, biflow, 0, 0, 1000, 1));
	flowlist.push_back(cflow_t(IPv6_addr("10.0.1.4"), 81, IPv6_addr("10.0.99.3"), 1111, IPPROTO_TCP, biflow, 0, 0, 2000, 2));

	// Group2: server role UDP
	flowlist.push_back(cflow_t(IPv6_addr("10.0.1.4"), 88, IPv6_addr("10.0.99.4"), 1112, IPPROTO_TCP, unibiflow | outflow, 0, 0, 5000, 5));
	flowlist.push_back(cflow_t(IPv6_addr("10.0.1.4"), 88, IPv6_addr("10.0.99.4"), 1110, IPPROTO_TCP, biflow, 0, 0, 1000, 1));
	flowlist.push_back(cflow_t(IPv6_addr("10.0.1.4"), 88, IPv6_addr("10.0.99.4"), 1111, IPPROTO_TCP, biflow, 0, 0, 2000, 2));

	GFilter_cflow6 gfilter_cflow6;
	if(flowlist.size() > max_flow_count)
		flowlist.resize(max_flow_count);
	try {
		gfilter_cflow6.write_file(outputFile, flowlist, append);
	}
	catch(string & e) {
		cerr << e << endl;
		exit(1);
	}
	cout << flowlist.size() << " test flows written to file \"" << outputFile << "\"" << endl;

	return 0;

}

