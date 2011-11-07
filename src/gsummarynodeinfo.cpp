/**
 * \file gsummarynodeinfo.cpp
 *	\brief Allows to print additional information to the DOT graph as comment which is used by the HAP4NfSen Plugin to desummarize nodes.
 *
 * If the hap4nfsen flag is set, additional information will be added to the end of the DOT file.
 * This information is written in form of a multiline comment and does not affect the graph definition.
 * The comments use the following format:
 * - every summary node description is on its own line.
 * - every line starts with " * " followed by the node name and "="
 * - every line without a "=" is currently ignored by the plugin
 * - the data contains information for all five partitions(and two optional fields). partitions are separated by ";"(previous version used ":").
 *   example(values in curly brackets are placeholders, everything in square brackets is optional):
 *     {host ip info};{proto info};{local port info};{remote port info};{remote ip info}[;{flow direction};{desummarized role types}]
 * - flow direction(if set and not empty) is inflow, outflow, biflow, unibiflow, unibiflow_out or unibiflow_in
 * - desummarized role types can be empty or contain one of the following values:
 *   s,c,m,p (= server roles, client roles, multi-client roles, p2p roles)
 * - multiple values in a partition are separated by ","
 *   example for local ports:
 *     {host ip info};{proto info};80,21,443;{remote port info};{remote ip info}[;{flow direction};{desummarized role types}]
 * - empty partitions contain no filter information. they will match any value.
 *   example for local ports(matches any local port):
 *     {host ip info};{proto info};;{remote port info};{remote ip info}[;{flow direction};{desummarized role types}]
 */

#include <sstream>
#include <string>
#include <set>

#include "gutil.h"
#include "gsummarynodeinfo.h"

using namespace std;

/**
 * Default constructor, initializes role type field. Constructor is private and cannot be called by external code.
 * To generate CSummaryNodeInfo objects, generate_node_info should be used.
 */
CSummaryNodeInfo::CSummaryNodeInfo() {
	role_type = no_role_type;
	filter_generated = false;
}

/**
 * Generates the filter part of a node id filter comment in the .dot file
 *
 * \return	A string representation of the filters
 */
string CSummaryNodeInfo::get_filter() {
	if (filter_generated) {
		return filter;
	}
	stringstream ss;
	bool has_role_info = (role_type != no_role_type && role_type != 'f' && ((pattern & partition) == partition)); // last check works because summarized = 0x1
	bool has_flow_direction = has_role_info || (flow_direction != "");

	// partition 1: protocol
	ss << protocol;
	ss << partition_delimiter;

	// partition 2: local port
	implode_ports(local_ports, ss);
	ss << partition_delimiter;

	// partition 3: remote port
	implode_ports(remote_ports, ss);
	ss << partition_delimiter;

	// partition 4: remote ip
	implode_ips(remote_ips, ss);

	if (has_flow_direction) {
		// partition 5: flow direction
		ss << partition_delimiter;
		ss << flow_direction;
	}
	if (has_role_info) {
		// partition 6: role type
		ss << partition_delimiter;
		ss << role_type;
	}
	filter = ss.str();
	filter_generated = true;
	return filter;
}

/**
 * Converts a set of ports(unsigned 16 bit integers) into a string containing all values, delemited by value_delimiter
 *
 * \param	ips Set containing ports
 * \param	out Stringstream used to write output to
 */
inline void CSummaryNodeInfo::implode_ports(const set<uint16_t> & ports, stringstream& out) {
	bool first_entry = true;
	for (set<uint16_t>::const_iterator iter = ports.begin(); iter != ports.end(); iter++) {
		if (first_entry) {
			first_entry = false;
		} else {
			out << value_delimiter;
		}
		out << *iter;
	}
}

/**
 * Converts a set of ip addresses into a string containing all values, delemited by value_delimiter
 *
 * \param	ips Set containing IPv6_addr
 * \param	out Stringstream used to write output to
 */
inline void CSummaryNodeInfo::implode_ips(const set<IPv6_addr> & ips, stringstream& out) {
	bool first_entry = true;
	for (set<IPv6_addr>::const_iterator iter = ips.begin(); iter != ips.end(); iter++) {
		if (first_entry) {
			first_entry = false;
		} else {
			out << value_delimiter;
		}
		out << *iter;
	}
}

/**
 * Helper function used to convert flow-types to strings
 *
 * \param	flowtype A flow-type as specified in flow_type_t(cflow_t.h)
 * \return	A string representation of the specified flow type
 */
inline string CSummaryNodeInfo::flowtype2string(const uint8_t flowtype) {
	switch (flowtype) {
	case biflow:
		return "biflow";
	case inflow:
		return "inflow";
	case outflow:
		return "outflow";
	case unibiflow:
		return "unibiflow";
	case (unibiflow + outflow):
		return "unibiflow_out";
	case (unibiflow + inflow):
		return "unibiflow_in";
	default:
		return "";
	}
}

/**
 * Generates a new CSummaryNodeInfo object using the specified information.
 * Simplified interface for single flows, calls generate_node_info with 4 parameters.
 *
 * \param	partition Graphlet partition of the node(e.g. remote_port)
 * \param	flow Flow to generate node info for
 * \return	A CSummaryNodeInfo with all fields initialized and set
 */
CSummaryNodeInfo CSummaryNodeInfo::generate_node_info(const graphlet_partition partition, const cflow_t & flow) {
	CFlowList flows;
	set<int> flow_ids;
	flows.push_back(flow);
	flow_ids.insert(0);
	assert(flow_ids.size() == 1);
	assert(flows.size() == 1);
	return generate_node_info(partition, 'f', single_flow, flow_ids, Subflowlist(flows.begin(), flows.end()));
}

/**
 * Generates a new CSummaryNodeInfo object using the specified information
 *
 * \param	partition Graphlet partition of the node(e.g. remote_port)
 * \param	role_type A character representing the role type, e.g. f for single flow
 * \param   pattern pattern used by the role
 * \param	flow_ids Set containing flow list references
 * \param	flow_list List containing CFlows
 * \return	A CSummaryNodeInfo with all fields initialized and set
 */
CSummaryNodeInfo CSummaryNodeInfo::generate_node_info(const graphlet_partition partition, const char role_type, const role_pattern pattern,
      const set<int>& flow_ids, Subflowlist flow_list) {
	assert(flow_ids.size() >= 1);
	CSummaryNodeInfo sni;
	sni.partition = partition;
	sni.pattern = pattern;

	if (partition == local_ip) { // no additional filters needed
		return sni;
	}

	set<int>::const_iterator flow_iter;
	if (partition == proto) { // filter only contains protocol
		flow_iter = flow_ids.begin(); // only need to read a single flow
		sni.protocol = util::ipV6ProtocolToString(flow_list[(*flow_iter)].prot);
		return sni;
	}

	for (flow_iter = flow_ids.begin(); flow_iter != flow_ids.end(); flow_iter++) { // need to read all flows
		int flow_id = (*flow_iter);
		sni.protocol = util::ipV6ProtocolToString(flow_list[flow_id].prot);
		sni.local_ports.insert(flow_list[flow_id].localPort);
		sni.role_type = role_type;
		if (partition == local_port) { // filter uses protocol&local port
			// already set since proto&local&role_type port are required for all cases
		}
		if (partition == remote_port || partition == remote_ip) { // filter uses all fields
			sni.remote_ports.insert(flow_list[flow_id].remotePort);
			sni.remote_ips.insert(flow_list[flow_id].remoteIP);
			sni.flow_direction = flowtype2string(flow_list[flow_id].flowtype);
		}
	}
	return sni;
}

/**
 * returns string containing all node ids information used by the HAP4NfSen plugin
 *
 *	\return	a .dot comment containing all information to perform HAP4NfSen drilldown actions
 */
string CSummaryNodeInfos::printNodeInfos() {
	stringstream ss;
	ss << "/* Comments for HAP4NFSEN v2.0" << endl;
	for (multimap<string, CSummaryNodeInfo>::iterator it = nodeInfos.begin(); it != nodeInfos.end(); ++it) {
		string id_prefix = "";
		switch ((*it).second.partition) {
		case local_ip:
			id_prefix = "k1_";
			break;
		case proto:
			id_prefix = "k2_";
			break;
		case local_port:
			id_prefix = "k3_";
			break;
		case remote_port:
			id_prefix = "k4_";
			break;
		case remote_ip:
			id_prefix = "k5_";
			break;
		default:
			assert(false);
		}
		ss << " * " << id_prefix << (*it).first << "=" << (*it).second.get_filter() << endl;
	}
	ss << "*/";
	return ss.str();
}

/**
 * Add an additional CSummaryNodeInfo to a CSummaryNodeInfos
 *
 * \param	nodeinfo	CSummaryNodeInfo to be added
 * \param	nodeName	Id used to ideftify the Node in the .dot graph definition
 */
void CSummaryNodeInfos::addNodeInfo(CSummaryNodeInfo nodeinfo, const string& nodeName) {
	// generate hash for key&value
	stringstream ss;
	ss << nodeName;
	ss << nodeinfo.get_filter();
	long key = string_hasher(ss.str());
	if (filter_hashes.find(key) != filter_hashes.end()) {
		return; // key-value pair already exists
	}

	// insert key<->value pair
	nodeInfos.insert(pair<string, CSummaryNodeInfo>(nodeName, nodeinfo));
	// insert hash
	filter_hashes.insert(key);
}
