/**
 *	\file gfilter_argus.cpp
 *	\brief Filter to import argus files
 */

#include "gfilter_argus.h"

#include <cstdio>
#include <sys/stat.h>
#include <iostream>
#include <fstream>

#include <netinet/in.h>

#include <boost/lexical_cast.hpp>
#include <boost/regex.hpp>
#include <netinet/in.h>

using namespace std;

/**
 *	Constructor
 *
 *	\param	formatName	Name of this format
 *	\param	humanReadablePattern	A simple name pattern for files of this type, used by e.g. the GUI
 *	\param	regexPattern	Regex pattern used internally
 */
GFilter_argus::GFilter_argus(std::string formatName, std::string humanReadablePattern, std::string regexPattern) :
	GFilter(formatName, humanReadablePattern, regexPattern) {
	// nothing to do here
}

/**
 *	Decide if this filter supports this file
 *
 *	\param in_filename Inputfilename
 *
 *	\return True if the file is supported by this filter
 *
 */
bool GFilter_argus::acceptFileForReading(std::string in_filename) const {
	// step 1: check if ra executable can be found
	char * val = getenv("PATH");
	if (val == NULL) {
		cout << "could not access env variable PATH" << endl;
		return false;
	}
	string paths = std::string(val);
	static const boost::regex re(":");
	set<string> path_set;
	boost::sregex_token_iterator i(paths.begin(), paths.end(), re, -1);
	boost::sregex_token_iterator j;
	while (i != j) {
		path_set.insert(*i);
		i++;
	}

	bool ra_found = false;
	struct stat stFileInfo;
	int intStat;
	for (set<string>::const_iterator it = path_set.begin(); it != path_set.end(); ++it) {
		string file_name(*it);
		file_name.append("/ra");
		intStat = stat(file_name.c_str(), &stFileInfo);
		if (intStat == 0) {
			if (stFileInfo.st_mode & S_IXUSR) {
				cout << "ra found: " << file_name << endl;
				ra_found = true;
				break;
			} else {
				cout << "no execute premissions for ra: " << file_name << endl;
			}
		}
	}
	if (!ra_found) {
		cerr << "ra executable could not be found. Please ensure that argus client tools are installed on the system and accessable and in the users' PATH"
		      << endl;
		return false;
	}

	// step 2: check if file name looks like a valid argus file name
	static const boost::regex file_pattern(".*\\.log");
	if (!regex_match(in_filename, file_pattern)) {
		cout << "argus file does not match expected file pattern" << endl;
		return false;
	}

	// step 3: check if file is a valid argus file containing at least one ip record
	static const boost::regex flow_direction_pattern("[<-|\\?>]+");
	stringstream ss;
	ss << "ra -N 1 -r ";
	ss << in_filename;
	ss << " - ip";
	FILE * fp;
	if ((fp = popen(ss.str().c_str(), "r")) == NULL) {
		cerr << "failed to run ra" << endl;
		return false;
	}
	char buffer[8 * 1024];
	char* l = NULL;
	// request a single line from ra to check if file exists and can be read by argus
	while ((l = fgets(buffer, sizeof buffer, fp)) != NULL) {
		return true; // output found, contains direction information => file ok
		if (regex_match(in_filename, file_pattern)) {
			return true;
		}
	}
	cout << in_filename << " is not an argus file or does not contain a single ip record" << endl;
	return false;
}

/**
 *	Read argus data from file into memory-based temporary flow list.
 *	Converts argus flows into cflow_t flows.
 *	The temporary flow list is not yet sorted and uniflows are not yet qualified.
 *
 *	\param in_filename Inputfilename
 *	\param flowlist Reference to the flowlist
 *	\param local_net Local network address
 *	\param netmask Network mask for local network address
 *	\param append Future flag to allow the import of more than one file (not yet used)
 *
 * \exception string Errortext
 */
void GFilter_argus::read_file(std::string in_filename, CFlowList & flowlist, const IPv6_addr & local_net, const IPv6_addr & netmask, bool append) const {
	static const boost::regex re("\\s+"); // columns are separated by spaces

	stringstream ss;
	ss << "ra"; // ra command
	ss << " -e ascii -u -c -r ";
	ss << in_filename;
	ss << " -n -s startime dur proto saddr daddr dir sport dport spkts dpkts sbytes dbytes stos dtos - ip"; // filters and columns
	string ra_cmd = ss.str();
	cout << "importing argus data using ra:\t" << ra_cmd << endl;
	FILE * fp;
	if ((fp = popen(ra_cmd.c_str(), "r")) == NULL) {
		throw "failed to run ra";
	}

	flowlist.get_allocator().allocate(1000);
	char buffer[8 * 1024];
	char* l = NULL;
	while ((l = fgets(buffer, sizeof buffer, fp)) != NULL) {
		if (flowlist.size() > 0 && (flowlist.size() % 1000) == 0) {
			cout << flowlist.size() << " argus records read so far" << endl;
		}
		string line(l);
		cflow_t argus_flow;
		boost::sregex_token_iterator i(line.begin(), line.end(), re, -1);
		boost::sregex_token_iterator j;
		uint8_t match_id = 0;
		try {
			while (i != j) {
				switch (match_id) {
					case START_TS:
						argus_flow.startMs = (uint32_t) boost::lexical_cast<double>(*i);
						break;
					case DURATION:
						argus_flow.durationMs = (uint32_t) boost::lexical_cast<double>(*i);
						break;
					case PROTOCOL:
						argus_flow.prot = proto_string_to_proto_num(*i);
						break;
					case SRC_IP:
						argus_flow.localIP = IPv6_addr(*i);
						break;
					case DST_IP:
						argus_flow.remoteIP = IPv6_addr(*i);
						break;
					case DIRECTION:
						argus_flow.dir = flow_dir_string_to_flow_dir(*i);
						break;
					case SRC_PORT:
						if (argus_flow.prot == ICMP) {
							argus_flow.localPort = 0;
						} else {
							argus_flow.localPort = boost::lexical_cast<uint16_t>(*i);
						}
						break;
					case DST_PORT:
						if (argus_flow.prot == ICMP) {
							argus_flow.remotePort = 0;
						} else {
							argus_flow.remotePort = boost::lexical_cast<uint16_t>(*i);
						}
						break;
					case SRC_PACKETS:
						argus_flow.dPkts += boost::lexical_cast<uint32_t>(*i);
						break;
					case DST_PACKETS:
						argus_flow.dPkts += boost::lexical_cast<uint32_t>(*i);
						break;
					case SRC_BYTES:
						argus_flow.dOctets += boost::lexical_cast<uint32_t>(*i);
						break;
					case DST_BYTES:
						argus_flow.dOctets += boost::lexical_cast<uint32_t>(*i);
						break;
					case SRC_TOS:
						argus_flow.tos_flags |= (uint8_t) boost::lexical_cast<uint16_t>(*i);
						break;
					case DST_TOS:
						argus_flow.tos_flags |= (uint8_t) boost::lexical_cast<uint16_t>(*i);
						break;
					default:
						cout << "unknown column detected(" << *i << ")" << endl;
				}
				i++;
				match_id++;
			}
		} catch (boost::bad_lexical_cast & e) {
			stringstream error_msg;
			error_msg << "argus parse error in (";
			error_msg << line;
			error_msg << "), column_id: ";
			error_msg << ((int) match_id);
			error_msg << " column_value: ";
			error_msg << (*i);
			error_msg << " error: ";
			error_msg << e.what();
			throw error_msg.str();
		}
		invert_flow_if_needed(argus_flow, local_net, netmask);
		flowlist.push_back(argus_flow);
	}
	cout << "end of argus import" << endl;
}

/**
 * Invert flow if required
 *
 * \param flow Flow to be inverted
 * \param local_net Local network address
 * \param netmask (Bit) mask for ip addresses
 */
void GFilter_argus::invert_flow_if_needed(cflow_t& flow, const IPv6_addr& local_net, const IPv6_addr& netmask) {
	IPv6_addr flow_net(flow.localIP & netmask);
	if (flow_net != local_net) {
		// must be an inflow => invert flow direction
		cflow_t flow_cpy = flow;
		// ip addresses
		flow.remoteIP = flow_cpy.localIP;
		flow.localIP = flow_cpy.remoteIP;
		// ports
		flow.remotePort = flow_cpy.localPort;
		flow.localPort = flow_cpy.remotePort;
		// flow_direction
		if (flow.flowtype != biflow) { // biflow contain no direction information and do not need to be updated
			flow.flowtype ^= inflow;
			flow.flowtype ^= outflow;
		}
	}
}

/**
 *	Return the protocol number of a protocol represented by a string
 *
 *	\param p_str Textual representation of a protocol
 *
 *	\return uint8_t Protocol number
 *
 *	\exception string Errortext
 */
uint8_t GFilter_argus::proto_string_to_proto_num(const std::string & p_str) {
	string lc_p_str(p_str);
	std::transform(lc_p_str.begin(), lc_p_str.end(), lc_p_str.begin(), ::tolower);
	if (lc_p_str == "icmp") {
		return IPPROTO_ICMP;
	}
	if (lc_p_str == "tcp") {
		return IPPROTO_TCP;
	}
	// argus automatically tries to detect RCP and RTCP and displays this instead of UDP
	// 	http://www.qosient.com/argus/index.shtml
	if (lc_p_str == "udp" || lc_p_str == "rtp" || lc_p_str == "rtcp") {
		return IPPROTO_UDP;
	}
	if (lc_p_str == "igmp") {
		return IPPROTO_IGMP;
	}
	stringstream error_message;
	error_message << "unknown protocol detected(";
	error_message << p_str;
	error_message << "). to add support, add a mapping to GFilter_argus::proto_string_to_proto_num";
	throw error_message.str();
}

/**
 *	Return the flow direction as uint8_t (flow_type_t) from a variable representing the flowdir as a string
 *
 *	\param fd_str Textual representation of a flow direction
 *
 *	\return uint8_t Flow number
 *
 *	\exception string Errortext
 */
uint8_t GFilter_argus::flow_dir_string_to_flow_dir(const std::string & fd_str) {
	// basic information about argus flow directions:
	//
	// Argus direction identifiers use the following symbols:
	//
	// direction:
	// >   = outflow
	// <   = inflow
	// < > = biflow
	//
	// transactions:
	// - = normal transaction
	// | = transaction reset
	// o = transaction time out
	//
	// special:
	// ? = transaction direction was detected with low confidence
	//
	// for more details, see:
	// flow directions containing -,o,|: http://linux.die.net/man/1/ra
	// flow directions containing ?:     http://comments.gmane.org/gmane.network.argus/7923
	// argus website:                    http://www.qosient.com/argus/index.shtml

	if (fd_str == "<->" || fd_str == "<|>" || fd_str == "<o>") {
		return biflow;
	}
	if (fd_str == "->" || fd_str == "|>" || fd_str == "o>") {
		return outflow;
	}
	if (fd_str == "<-" || fd_str == "<|" || fd_str == "<o") {
		return inflow;
	}
	cout << "flow direction(" << fd_str << ") has been detected with low confidence. using argus' suggestion" << endl;
	if (fd_str == "<?>") {
		return biflow;
	}
	if (fd_str == "?>") {
		return outflow;
	}
	if (fd_str == "<?") {
		return inflow;
	}
	stringstream error_msg;
	error_msg << "unknown flow direction:\t";
	error_msg << fd_str;
	throw error_msg.str();
}
