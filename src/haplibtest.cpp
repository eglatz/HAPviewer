/**
 *	\file haplibtest.cpp
 *	\brief Test program for HAPviewer library.
 */

#include <iostream>
#include <set>
#include <boost/program_options.hpp>
#include <stdint.h>

#include "ginterface.h"

using namespace std;

int main(int argc, char * argv[]) {
	// 1. Process command line
	// ***********************
	//
	// Check for needed command line arguments and process supported command line options
	boost::program_options::variables_map variablesMap;
	boost::program_options::options_description desc("Allowed options");

	string outfilename; ///< Output filename (Default: test.dot)
	CInterface::filter_flags_t filters = static_cast<CInterface::filter_flags_t>(0); ///< Filtersettings

	CInterface libif; ///< Provides access to the HAPviewer functionality
	CInterface::summarize_flags_t sum_flags = CInterface::summarize_all; ///< Summary filter flags

	set<uint32_t> role_nums; ///< Set of roles to unsummarize
	unsigned int filter_up_to_rolenum;
	string IP_str;

	try {
		desc.add_options()
				("inputfile,i", boost::program_options::value<string>(), "File to read")
				("outputfile,o", boost::program_options::value<string>(&outfilename)->default_value("test.dot"),"Name of output file")
				("ip", boost::program_options::value<string>(), "Host IP address")
				("rolenum", boost::program_options::value<unsigned int>(&filter_up_to_rolenum)->default_value(0), "Unsummarize any role up to rolenum")

				("notcp", "Filter TCP traffic, overrides the tcponly flags")
				("noicmp", "Filter ICMP traffic, overrides the udponly flags")
				("noudp", "Filter UDP traffic, overrides the icmponly flags")
				("noother", "Filter UDP traffic, overrides the otheronly flags")

				("tcponly", "Show only TCP traffic")
				("udponly", "Show only UDP traffic")
				("icmponly", "Show only ICMP traffic")
				("otheronly", "Show only non TCP/ICMP/UDP traffic")

				("nosummarize", "Do not summarize per default (default: summarize all roles)")

				("nosumserverroles", "Summarize server roles")
				("nosumclientroles", "Summarize client roles")
				("nosump2proles", "Summarize peer 2 peer roles")
				("nosummulticlientroles", "Summarize multiclient roles")

				("sumserverroles", "Summarize server roles")
				("sumclientroles", "Summarize client roles")
				("sump2proles", "Summarize peer 2 peer roles")
				("summulticlientroles", "Summarize multiclient roles (default: summarize all roles)")

				("help,h", "show this help message")
			;

		boost::program_options::positional_options_description posOpt;
		posOpt.add("inputfile", 1);
		posOpt.add("ip", 1);

		boost::program_options::store(boost::program_options::parse_command_line(argc, argv, desc), variablesMap);
		boost::program_options::store(boost::program_options::command_line_parser(argc, argv).options(desc).positional(posOpt).run(), variablesMap);
		boost::program_options::notify(variablesMap);
	} catch (std::exception & e) {
		std::cerr << "Error: " << e.what() << std::endl;
		exit(1);
	}

	// Set stuff up as requested by the user
	if (variablesMap.count("help")) {
		cerr << desc;
		exit(0);
	}

	if (!variablesMap.count("inputfile")) {
		cerr << desc;
		exit(1);
	}

	if (!variablesMap.count("ip")) {
		cerr << desc;
		exit(1);
	}

	IP_str = variablesMap["ip"].as<string>();
	string in_filename = variablesMap["inputfile"].as<string>();
	filter_up_to_rolenum = variablesMap["rolenum"].as<unsigned int>();

	if((variablesMap.count("tcponly") + variablesMap.count("udponly") + variablesMap.count("icmponly") + variablesMap.count("otheronly")) > 1) {
		cerr << "Please use only one \"*only\" flag per call" << endl;
		exit(1);
	}

	if(variablesMap.count("tcponly")) {
		filters = static_cast<CInterface::filter_flags_t>(CInterface::filter_icmp + CInterface::filter_other + CInterface::filter_udp);
	} else if(variablesMap.count("udponly")) {
		filters = static_cast<CInterface::filter_flags_t>(CInterface::filter_icmp + CInterface::filter_other + CInterface::filter_tcp);
	} else if(variablesMap.count("icmponly")) {
		filters = static_cast<CInterface::filter_flags_t>(CInterface::filter_udp + CInterface::filter_other + CInterface::filter_tcp);
	} else if(variablesMap.count("otheronly")) {
		filters = static_cast<CInterface::filter_flags_t>(CInterface::filter_udp + CInterface::filter_icmp + CInterface::filter_tcp);
	}

	if(variablesMap.count("notcp")) {
		filters = static_cast<CInterface::filter_flags_t>(filters ^ CInterface::filter_tcp);
	}
	if(variablesMap.count("noudp")) {
		filters = static_cast<CInterface::filter_flags_t>(filters ^ CInterface::filter_udp);
	}
	if(variablesMap.count("noicmp")) {
		filters = static_cast<CInterface::filter_flags_t>(filters ^ CInterface::filter_icmp);
	}
	if(variablesMap.count("noother")) {
		filters = static_cast<CInterface::filter_flags_t>(filters ^ CInterface::filter_other);
	}

	/*
		("nosummarize", "Do not summarize per default (default: summarize all roles)")
	 */

	if(variablesMap.count("nosummarize")) {
		sum_flags = static_cast<CInterface::summarize_flags_t>(0);
	}

	/*
		("sumserverroles", "Summarize server roles (default: summarize all roles)")
		("sumclientroles", "Summarize client roles (default: summarize all roles)")
		("sump2proles", "Summarize peer 2 peer roles (default: summarize all roles)")
		("summulticlientroles", "Summarize multiclient roles (default: summarize all roles)")
	 */
	if(variablesMap.count("sumserverroles")) {
			sum_flags = static_cast<CInterface::summarize_flags_t>(sum_flags | CInterface::summarize_server_roles);
	}
	if(variablesMap.count("sumclientroles")) {
			sum_flags = static_cast<CInterface::summarize_flags_t>(sum_flags | CInterface::summarize_client_roles);
	}
	if(variablesMap.count("sump2proles")) {
			sum_flags = static_cast<CInterface::summarize_flags_t>(sum_flags | CInterface::summarize_p2p_roles);
	}
	if(variablesMap.count("summulticlientroles")) {
			sum_flags = static_cast<CInterface::summarize_flags_t>(sum_flags | CInterface::summarize_multi_client_roles);
	}

	/*
		("nosumserverroles", "Summarize server roles")
		("nosumclientroles", "Summarize client roles (default: summarize all roles)")
		("nosump2proles", "Summarize peer 2 peer roles (default: summarize all roles)")
		("nosummulticlientroles", "Summarize multiclient roles (default: summarize all roles)")
	 */
	if(variablesMap.count("nosumserverroles")) {
			sum_flags = static_cast<CInterface::summarize_flags_t>(sum_flags ^ CInterface::summarize_server_roles);
	}
	if(variablesMap.count("nosumclientroles")) {
			sum_flags = static_cast<CInterface::summarize_flags_t>(sum_flags ^ CInterface::summarize_client_roles);
	}
	if(variablesMap.count("nosump2proles")) {
			sum_flags = static_cast<CInterface::summarize_flags_t>(sum_flags ^ CInterface::summarize_p2p_roles);
	}
	if(variablesMap.count("nosummulticlientroles")) {
			sum_flags = static_cast<CInterface::summarize_flags_t>(sum_flags ^ CInterface::summarize_multi_client_roles);
	}

	for(unsigned int i = 0; i < filter_up_to_rolenum; i++)
			role_nums.insert(i);

	bool ok = libif.get_graphlet(in_filename, outfilename, IP_str, sum_flags, filters, role_nums);

	if (!ok) {
		cerr << "ERROR: could not create a dot file from input data.\n";
		return 1;
	} else {
		cout << "Successfully created file " << outfilename << endl;
	}

	return 0;
}

