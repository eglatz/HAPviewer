/**
 * \file gsummarynodeinfo.h
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

#ifndef GSUMMARYNODEINFO_H_
#define GSUMMARYNODEINFO_H_

#include <set>
#include <map>
#include <string>
#include <boost/functional/hash.hpp>
#include <stdint.h>

#include "IPv6_addr.h"
#include "grole.h"

class CRoleMembership;
class CSummaryNodeInfo;
class CSummaryNodeInfos;

class CSummaryNodeInfo {
	public:
		std::string get_filter();
		static CSummaryNodeInfo generate_node_info(const graphlet_partition partition, const char role_type, const role_pattern pattern,
		      const std::set<int> & flow_ids, Subflowlist flow_list);
		static CSummaryNodeInfo generate_node_info(const graphlet_partition partition, const cflow_t & flow);
		friend class CSummaryNodeInfos;

	private:
		static const char partition_delimiter = ';';
		static const char value_delimiter = ',';
		static const char no_role_type = ' ';
		graphlet_partition partition;
		role_pattern pattern;
		std::string protocol;
		std::set<uint16_t> local_ports;
		std::set<uint16_t> remote_ports;
		std::set<IPv6_addr> remote_ips;
		std::string flow_direction;
		char role_type;
		std::string filter;
		bool filter_generated;

		CSummaryNodeInfo();
		inline void implode_ports(const std::set<uint16_t>& ports, std::stringstream & out);
		inline void implode_ips(const std::set<IPv6_addr>& ips, std::stringstream & out);
		inline static std::string flowtype2string(const uint8_t flowtype);
};

class CSummaryNodeInfos {
	public:
		void addNodeInfo(CSummaryNodeInfo nodeinfo, const std::string & nodeName);
		std::string printNodeInfos();
	private:
		std::multimap<std::string, CSummaryNodeInfo> nodeInfos;
		std::set<long> filter_hashes; ///< used to check if a key-value pair already exists in the nodeinfo multi-map
		boost::hash<std::string> string_hasher;
};

#endif /* GSUMMARYNODEINFO_H_ */
