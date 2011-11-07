#ifndef GLOBAL_H
#define GLOBAL_H
/**
 *	\file global.h
 *	\brief Global definitions.
 */

#include <iostream>

/**
 *	\class	prefs_t
 *	\brief	Stores the settings relevant to the creation of a graph
 */
class prefs_t {
	public:
		bool summarize_clt_roles; ///< True when client roles should be summarized
		bool summarize_multclt_roles; ///< True when multi client roles should be summarized
		bool summarize_srv_roles; ///< True when server roles should be summarized
		bool summarize_p2p_roles; ///< True when P2P roles should be summarized

		bool summarize_biflows; ///< True when biflows should be summarized
		bool summarize_uniflows; ///< True when uniflows should be summarized

		bool filter_biflows; ///< True when biflows should be filtered
		bool filter_uniflows; ///< True when all uniflows should be filtered
		bool filter_unprod_inflows; ///< True when unproductive inflows should be filtered
		bool filter_unprod_outflows; ///< True when unproductive outflows should be filtered
		bool filter_TCP; ///< True when TCP flows should be filtered
		bool filter_UDP; ///< True when UDP flows should be filtered
		bool filter_ICMP; ///< True when ICMP flows should be filtered
		bool filter_OTHER; ///< True when OTHER flows should be filtered

		bool warn_oversized_graphlet; ///< True when user should be warned before oversized graphlets

		/**
		 *	Constructor: Default constructor. Initializes to 0 and sets magic to CFLOW_6_MAGIC_NUMBER
		 */
		prefs_t() {
			summarize_clt_roles = true;
			summarize_multclt_roles = true;
			summarize_srv_roles = true;
			summarize_p2p_roles = true;

			summarize_biflows = true;
			summarize_uniflows = true;

			filter_biflows = false;
			filter_uniflows = false;
			filter_unprod_inflows = false;
			filter_unprod_outflows = false;
			filter_TCP = false;
			filter_UDP = false;
			filter_ICMP = false;
			filter_OTHER = false;
		}

		/**
		  *	Print the preferences to std::cout
		  */
		void show_prefs() {
			std::cout << "summarize_clt_roles:     " << (summarize_clt_roles ? "true" : "false") << std::endl;
			std::cout << "summarize_multclt_roles: " << (summarize_multclt_roles ? "true" : "false") << std::endl;
			std::cout << "summarize_srv_roles:     " << (summarize_srv_roles ? "true" : "false") << std::endl;
			std::cout << "summarize_p2p_roles:     " << (summarize_p2p_roles ? "true" : "false") << std::endl;
			std::cout << std::endl;
			std::cout << "summarize_biflows:       " << (summarize_biflows ? "true" : "false") << std::endl;
			std::cout << "summarize_uniflows:      " << (summarize_uniflows ? "true" : "false") << std::endl;
			std::cout << std::endl;
			std::cout << "filter_biflows:          " << (filter_biflows ? "true" : "false") << std::endl;
			std::cout << "filter_uniflows:         " << (filter_uniflows ? "true" : "false") << std::endl;
			std::cout << "filter_unprod_inflows:   " << (filter_unprod_inflows ? "true" : "false") << std::endl;
			std::cout << "filter_unprod_outflows:  " << (filter_unprod_outflows ? "true" : "false") << std::endl;
			std::cout << std::endl;
			std::cout << "filter_TCP:              " << (filter_TCP ? "true" : "false") << std::endl;
			std::cout << "filter_UDP:              " << (filter_UDP ? "true" : "false") << std::endl;
			std::cout << "filter_ICMP:             " << (filter_ICMP ? "true" : "false") << std::endl;
			std::cout << "filter_OTHER:            " << (filter_OTHER ? "true" : "false") << std::endl;
			std::cout << std::endl;
			std::cout << "warn_oversized_graphlet: " << (warn_oversized_graphlet ? "true" : "false") << std::endl;
		}
};
#endif /* GLOBAL_H */
