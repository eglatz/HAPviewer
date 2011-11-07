#ifndef GINTERFACE_H
#define GINTERFACE_H
/**
 *	\file ginterface.h
 *	\brief Interface to library version of HAPviewer.
 *	By use of this interface network traffic data can be visualized
 *	as a HAP graphlet.
 */

#include <string>

#include "gimport.h"
#include "ghpgdata.h"
#include "grole.h"

/**
 *	\class CInterface
 *	\brief Provides everything needed to use the HAPviewer as a library
 */
class CInterface {
	private:
		CImport * flowImport; ///< Ref to data for HOST list model
		ChpgData * hpgData; ///< Data for HPG model
		prefs_t prefs; ///< Preferences settings

	public:
		CInterface();
		~CInterface();

		// Assign powers of two for OR-ing of option values
		enum summarize_flags_t {
			summarize_client_roles = 1, summarize_multi_client_roles = 2, summarize_server_roles = 4, summarize_p2p_roles = 8, summarize_all = (1 + 2 + 4 + 8)
		};

		enum filter_flags_t {
			filter_biflows = 1, filter_uniflows = 2, filter_tcp = 4, filter_udp = 8, filter_icmp = 16, filter_other = 32
		};

		bool get_graphlet(std::string in_filename, std::string & outfile, std::string IP_str, summarize_flags_t summarize_flags, filter_flags_t filter_flags,
		      const std::set<uint32_t> & desum_role_nums);
		bool get_hpg_file(std::string in_filename, std::string & outfile, IPv6_addr localIP, int host_count);

	private:
		bool handle_get_graphlet(std::string & in_filename, std::string & hpg_filename, std::string & dot_filename, std::string IP_str);
		bool handle_hpg_import(std::string & in_filename, std::string & out_filename);
		bool handle_binary_import(std::string & in_filename, std::string & out_filename, IPv6_addr localIP, int host_count);
		CSummaryNodeInfos* nodeInfos; ///< Storage for nodeid filter (needed by HAP4NfSen)
		desummarizedRoles desum_role_nums; ///< Desummarized role number
};

#endif

