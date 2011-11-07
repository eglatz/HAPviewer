#ifndef GIMPORT_H
#define GIMPORT_H
/**
 *	\file gimport.h
 *	\brief Binary traffic data import, and
 *	inference of hpg (host profile graphlet) data from flow data.
 */

#include <boost/iostreams/filtering_streambuf.hpp>
#include <boost/iostreams/filter/gzip.hpp>
#include <boost/iostreams/filtering_stream.hpp>
#include <boost/iostreams/device/file.hpp>

#include <stdlib.h>
#include <string>
#include <arpa/inet.h>
#include <vector>
#include <iostream>

#ifdef GUI
#include <gtkmm.h>
#endif

#include "cflow.h"
#include "HashMapE.h"
#include "global.h"
#include "gutil.h"
#include "ggraph.h"

#include "grole.h"
#include "gfilter.h"

// ******************************************************************************************

/**
 *	\class ChostMetadata
 *	\brief Data class for graphlet properties (host metadata).
 *
 *	This metadata is derived from sorted flow data (as read from a cflow file or derived from
 *	a pcap/ipfix/etc. file.
 */
class ChostMetadata {
	public:
		IPv6_addr IP; ///< localIP (IP address of host)
		unsigned int graphlet_number; ///< graphlet number as read from file
		unsigned int flow_count; ///< Count of all flows to/from host
		unsigned int uniflow_count; ///< Count of uniflows to/from host
		unsigned int prot_count; ///< Total count of used protocols
		unsigned int packet_count; ///< Count of packets to/from host
		unsigned int index; ///< Index into data array: points to first edge
		uint64_t bytesForAllFlows; ///< Total byte count of all flows involved

		ChostMetadata();
};

// ******************************************************************************************

// Hash keys & maps for assembling packets into unidirectional flows
// *****************************************************************
// For assembling packets into flows
// key = 5-tuple {srcIP, dstIP, srcPort, dstPort, protocol}
// data = references to flowlist records
//
typedef HashKeyIPv6_5T flowHashKey;
typedef hash_map<HashKeyIPv6_5T, cflow_t *, HashFunction<HashKeyIPv6_5T> , HashFunction<HashKeyIPv6_5T> > flowHashMap;

// For lookup of all traffic between a host pair: to identify unibiflow property
// key = 2-tuple {IP1, IP2}
// data = sample id
//
typedef HashKeyIPv6Pair FlowHashKeyHostPair;
typedef hash_map<HashKeyIPv6Pair, int, HashFunction<HashKeyIPv6Pair> , HashFunction<HashKeyIPv6Pair> > FlowHashMapHostPair;

/**
 *	\class CImport
 *	\brief Import of binary data from gzipped cflow_t binary files or from pcap binary files
 */
class CImport {

	// Functions to import flows
	public:
		static bool acceptForImport(const std::string & in_filename);
		static bool acceptForExport(const std::string & out_filename);
		void read_file(const IPv6_addr & local_net = IPv6_addr(), const IPv6_addr & netmask = IPv6_addr());
		void write_file(std::string out_filename, const CFlowList & flowlist, bool appendIfExisting);
		void write_file(std::string out_filename, const Subflowlist & subflowlist, bool appendIfExisting);
		static std::string getFormatName(std::string & in_filename);
		static std::vector<std::string> getAllFormatNames();
		static std::vector<std::string> getAllHumanReadablePatterns();
		static std::ostream & printAllTypeNames(std::ostream & os);
		static std::string getFormatNamesAsString();
		static unsigned int initInputfilters();

	private:
		static std::vector<GFilter *> inputfilters; ///< Holds all enabled GFilter as configured

	public:
		CImport(const std::string & in_filename, const std::string & out_filename, const prefs_t & prefs);
		CImport(const CFlowList & _flowlist, const prefs_t & newprefs);

		void cflow2hpg();

		// Flow helper functions
		void print_flowlist(unsigned int linecount);

		// Flow set/get
		Subflowlist get_flow(unsigned int flIndex, unsigned int flow_count) const;
		const CFlowList get_outside_graphlet_flows(IPv6_addr remoteIP);

		int get_flow_count() const;

		void set_no_reverse_index();

		bool set_localIP(IPv6_addr IP, int host_count);
		const desummarizedRoles get_desummarized_roles();
		void set_desummarized_roles(const desummarizedRoles & role_set);
		void add_desummarized_roles(const desummarizedRoles & role_set);
		void clear_desummarized_roles();

		// Handling of host graphlet metadata
		void get_hostMetadata(void);
		const ChostMetadata & get_first_host_metadata();
		const ChostMetadata & get_next_host_metadata();
		std::string get_hpg_filename() const;
		std::string get_in_filename() const;

		CSummaryNodeInfos * nodeInfos; ///< Storage for nodeinfos

		Subflowlist getActiveFlowlist();
		void invalidate();
		void setBegin(unsigned int start);
		void setEnd(unsigned int last);

#ifdef GUI
		// Callbacks for progress bar
		sigc::signal<void, double> signal_show_progressbar;///< Parameter is initial progress
		sigc::signal<void, double> signal_set_progress;///< Parameter is fraction done so far
		sigc::signal<void> signal_hide_progressbar;///< Un-display progress bar
#endif

	protected:
		std::string in_filename; ///< Input file name
		std::string hpg_filename; ///< Name for hpg file

		// "full flowlist": as loaded from file; "active_flowlist": as used for transformations
		CFlowList full_flowlist; ///< Flowlist containg all loaded localIPs ("full flowlist")
		Subflowlist active_flowlist; ///< Flowlist containg a part of all loaded localIPs ("active flowlist")
		Subflowlist::const_iterator next_host_idx; ///< Flowlist iterator of first flow of next host

		Subflowlist::size_type getActiveFlowlistSize() {
			return active_flowlist.size();
		}
		std::vector<int> remoteIP_index; ///< Index into flowlist for sorted remoteIPs
		bool use_reverse_index; ///< TRUE if a reverse index is needed (default:TRUE)

		std::vector<ChostMetadata> hostMetadata; ///< Vector of metadata objects
		int next_host; ///< Auxiliary counter for get_first/next_host functions

		const prefs_t & prefs; ///< Preferences settings

	private:
		desummarizedRoles desummarizedRolesSet; ///< set of rolenumbers which should not be summarized
		desummarizedRoles desummarizedMultiNodeRolesSet; ///< set of multirolenumbers which should not be summarized
		void prepare_flowlist();
		void calculate_multi_summary_node_desummarizations(CRoleMembership & roleMembership);

	protected:
		void prepare_reverse_index();
};

#endif /* GIMPORT_H */
