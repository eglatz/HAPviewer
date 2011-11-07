#ifndef GHPGDATA_H
#define GHPGDATA_H

/**
 *	\file ghpgdata.h
 *	\brief Metadata storage and host profile graphlet data storage.
 *
 *	Implements HPG to DOT transformation of graphlet data.
 *	HPG: a specific type of graphlet description (two versions exist, for details see ghpgdata.cpp).
 *	DOT: graph data description format as defined by Graphviz ("dot-language").
 */

#ifdef GUI
#include "giomm.h"
#endif

#include <stdlib.h>
#include <string>
#include <arpa/inet.h>

#include "gutil.h"
#include "hpg.h"
#include "gsummarynodeinfo.h"

/**
 *	\struct node_hm_value
 *	\brief Struct for a uint32_t rank and a hpg_field.
 */
struct node_hm_value {
		uint32_t rank;
		hpg_field value;
};

// ******************************************************************************************

/**
 *	\class ChpgMetadata
 *	\brief Data class for graphlet properties (hpg metadata).
 *
 *	This metadata is derived from host profile graphlet (hpg) data.
 */
class ChpgMetadata {
	public:
		unsigned int graphlet_nr; ///< graphlet number as read from file
		unsigned int edge_count; ///< Total count graphlet edges
		unsigned int prot_count; ///< Total count of used protocols
		unsigned int dstIP_cnt; ///< Total count of used destination IP addresses
		unsigned int srcPort_cnt; ///< Total count of used source ports
		unsigned int dstPort_cnt; ///< Total count of used destination ports
		unsigned int index; ///< Index into hpgdata array: points to first edge
		uint64_t bytesForAllFlows; ///< Total byte count of all flows involved

		ChpgMetadata() {
			graphlet_nr = 0;
			edge_count = 0;
			prot_count = 0;
			dstIP_cnt = 0;
			srcPort_cnt = 0;
			dstPort_cnt = 0;
			index = 0;
			bytesForAllFlows = 0;
		}
		;
		~ChpgMetadata() {
		}
		;
};

// ******************************************************************************************

/**
 *	\class ChpgData
 *	\brief Keeps any hpg (host profile graphlet) data read.
 *
 *	Implements HPG to DOT transformation of graphlet data.
 *	HPG: a specific type of graphlet description (two versions exist, for details see ghpgdata.cpp).
 *	DOT: graph data description format as defined by Graphviz ("dot-language").
 */
class ChpgData {
	public:
		ChpgData();
		ChpgData(const std::string & filename);
		~ChpgData();

		void read_hpg_file();
		void read_hpg_memory(hpg_field * memdata, int size);
		void get_hpgMetadata(void);
		int get_num_graphlets();
		void hpg2dot(int index, std::string & outfilename);
		void hpg2dot3(int index, std::string & outfilename);
		ChpgMetadata * get_first_graphlet();
		ChpgMetadata * get_next_graphlet();
		int get_index(unsigned int graphlet_nr);
		int get_edges();
		void show_edge_data(hpg_field * value);
		void show_data(int index1, int index2);

		CSummaryNodeInfos* nodeInfos; ///< Storage for nodeid filter (needed by HAP4NfSen)

#ifdef GUI
		// Callbacks for progress bar
		sigc::signal<void, double> signal_show_progressbar; ///< Parameter is initial progress
		sigc::signal<void, double> signal_set_progress; ///< Parameter is fraction done so far
		sigc::signal<void> signal_hide_progressbar; ///< Un-display progress bar
#endif

	private:
		std::string dot_filename; ///< Default dot file name
		std::string gif_filename; ///< Default gif file name
		std::string fname; ///< Name for hpg file
		hpg_field * hpgdata; ///< Array where HPG file data is stored
		bool hpgdata_allocated; ///< Set true when data has been allocated. This is only the case when cstor with file name has been used)
		bool show_packet_counts; ///< If true the bytes and packets edge annotations are used

		int elements; ///< Size of array "data" in number of entries
		int rows; ///< Count of rows (each containing 3 elements)
		int elements_read; ///< Total count of elements (uint32_t values) read from file
		int next_graphlet; ///< Auxiliary counter for get_first/next_graphlet functions

		int graphlet_cnt; ///< Count for graphlets
		ChpgMetadata ** hpgMetadata; ///< Array of ptrs to graphlet metadata objects
		int graphlet_version; ///< Graphlet profile format version (1, 2)

		void get_hpgMetadata3(void);

		bool partition_changed3(rank_t rank, rank_t last_rank);
		int rank2partition(rank_t rank);

		void show_edge_data0(hpg_field * value);
		void show_edge_data1(hpg_field * value);
		void show_edge_data2(hpg_field * value);

		// helper functions for dot output
		static std::string getConnectionsString(const uint32_t connection_count);
		static std::string getHostsString(const uint32_t host_count);
		static std::string getGenericCountString(const std::string & type, const uint32_t count); // should not be called directly
		static std::string getRoleNrString(const uint32_t role_nr);
		static uint32_t getConnectionCount(const hpg_field & field);
		static uint32_t getRoleNumber(const hpg_field & field);
		static uint16_t getGraphletNumber(const hpg_field & field);
		static rank_t getRank(const hpg_field& field);
		static std::string getRoleNumProperty(const uint32_t role_number);
		static std::string getIpProperty(const IPv6_addr & ip);
};

#endif /* GHPGDATA_H */
