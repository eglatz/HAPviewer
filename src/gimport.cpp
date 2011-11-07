/**
 *	\file gimport.cpp
 *	\brief Binary traffic data import, and
 *	inference of hpg (host profile graphlet) data from flow data.
 */

#include <iostream>
#include <fstream>
#include <sstream>
#include <set>
#include <string>
#include <iterator>

#include <cstdio>
#include <cstdlib>
#include <cstring>

#include <assert.h>
#include <time.h>
#include <errno.h>

#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <arpa/inet.h>			// Library functions, e.g. ntoh()
// Protocol header definitions
#include <netinet/in_systm.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip.h>			// IPv4 header
#include <netinet/ip6.h>		// IPv6 header
#include <netinet/tcp.h>		// TCP header
#include <netinet/udp.h>		// UDP header
#include <netinet/in.h>			// IP protocol types
#ifdef __linux__
#include <linux/if_ether.h>	// Ethernet header, ethernet protocol types
#else
#include <netinet/if_ether.h>	// Ethernet header, ethernet protocol types
#endif // __linux__
#include "gimport.h"
#include "gimport_config.h"
#include "heapsort.h"
#include "hpg.h"
#include "gutil.h"
#include "ggraph.h"
#include "HAPviewer.h"
#include "cflow.h"
#include "gfilter.h"

using namespace std;

#ifdef NDEBUG
bool debug =false;
bool debug2=false;
bool debug3=false;
bool debug4=false;
bool debug5=false;
bool debug6=false;
#else
bool debug = false;
bool debug2 = false;
bool debug3 = true;
bool debug4 = true;
bool debug5 = true;
bool debug6 = true;
#endif

/**
 *	Default constructor
 */
ChostMetadata::ChostMetadata() {
	IP = IPv6_addr();
	flow_count = 0;
	prot_count = 0;
	packet_count = 0;
	index = 0;
	bytesForAllFlows = 0;
}

/**
 *	Simple constructor: pick data from memory instead from input file.
 *
 *	\param flowlist Source flowlist.
 * \param newprefs Preferences settings
 */
CImport::CImport(const CFlowList & flowlist, const prefs_t & newprefs) :
	full_flowlist(flowlist), active_flowlist(full_flowlist.begin(), full_flowlist.end()), prefs(newprefs) {
	next_host_idx = full_flowlist.begin();

	use_reverse_index = true;
	hpg_filename = default_hpg_filename; // No input file name to derive hpg file name from
	next_host = 0;
}

/**
 *	Constructor: initialize
 *
 *	\param in_filename Name of data input file.
 *	\param out_filename Name of data ouput file (*.hpg).
 * \param newprefs Preferences settings
 */
CImport::CImport(const std::string & in_filename, const std::string & out_filename, const prefs_t & newprefs) :
	prefs(newprefs) {
	// Store parameter for later use
	this->in_filename = in_filename;

	//	prefs->show_prefs();

	if (!acceptForImport(in_filename)) {
		string errtext = "Invalid file name: " + in_filename;
		throw errtext;
	}

	hpg_filename = out_filename;
	cout << "out_filename: " << out_filename << endl;

	// Initialize flow list
	next_host_idx = full_flowlist.begin();
	//	flowlist_allocated = false;
	use_reverse_index = true;

	next_host = 0;
}

/**
 *	Prepare r_index for outside graphlets.
 *
 *	By use of the r_index it is possible to construct graphlets from the outside
 *	perspective. This is used by the IP-based graphlet search function (go to IP address).
 */
void CImport::prepare_reverse_index() {
	cout << "Preparing index for remote IP-based outside graphlet look-up.\n";
	// Use 2 auxiliary arrays for sorting
	vector<IPv6_addr> IPs(full_flowlist.size());
	remoteIP_index.resize(full_flowlist.size());
	// Initialize sorting indices
	// IPs = localIP
	// r_index = index into all_flowlist
	for (unsigned int j = 0; j < full_flowlist.size(); j++) {
		IPs[j] = full_flowlist[j].remoteIP;
		remoteIP_index[j] = j;
	}
	// Now sort arrays such that IPs have ascending order
	// ({IP, index} pairs are preserved)
	heapSort(IPs, remoteIP_index);
	cout << "Done.\n";
}

/**
 *	Prepare all_flowlist.
 *	This includes sorting by ascending order of localIP,
 *	and qualifying uniflows exchanged between host pairs that
 *	otherwise communicate bidirectionally.
 *
 */
void CImport::prepare_flowlist() {
	// (3) Fill final flowlist
	// ***********************
	// The final all_flowlist has to be sorted in ascending order of localIPs.
	// Additionally, uniflow qualification is performed, i.e. uniflows exchanged between
	// hosts which also exchange biflows, are marked as "potential productive uniflows"

	// a) Sort arrays such that IPs have ascending order
	sort(full_flowlist.begin(), full_flowlist.end()); // Not necessary on cflow lists but still leave it here as we got way too many unsorted examples

	active_flowlist.invalidate();
	active_flowlist.setBegin(full_flowlist.begin());
	active_flowlist.setEnd(full_flowlist.end());

	// b) Perform uniflow qualification
	// --------------------------------
	// As a result we know which uniflows are productive, i.e. involve
	// a host pair that also exchanges biflows.

	// Loop 1:
	// Go through flowlist and store each host pair in hash map "flowHmHostPair"
	// key = {IP1,IP2 }, value=biflow count

	FlowHashMapHostPair * flowHmHostPair = new FlowHashMapHostPair();
	FlowHashMapHostPair::iterator FlowHashMapHostPairIterator;

	cout << "Preparing for qualification of uniflows." << endl;

	int host_pairs = 0;
	for (CFlowList::iterator flowiterator = full_flowlist.begin(); flowiterator != full_flowlist.end(); flowiterator++) { // Go through all flows
		// Show progress on console
		static int i = 0;
		if (((i++ % 100000) == 0) && (i > 0)) {
			cout << ".";
			cout.flush();
		}

		int biflow_inc = ((flowiterator->flowtype & biflow) != 0) ? 1 : 0;

		FlowHashKeyHostPair hostPairKey((flowiterator->localIP), (flowiterator->remoteIP));
		FlowHashMapHostPairIterator = flowHmHostPair->find(hostPairKey);
		if (FlowHashMapHostPairIterator == flowHmHostPair->end()) {
			// New host pair
			(*flowHmHostPair)[hostPairKey] = biflow_inc;
			host_pairs++;
		} else {
			// An entry exists
			FlowHashMapHostPairIterator->second = FlowHashMapHostPairIterator->second + biflow_inc; // Update entry by biflow count
		}
	}

	// Loop 2:
	// For each uniflow check if there has been at least one biflow between the involved host pair.
	// If yes then mark flow as flow type "unibiflow".

	int uniflow_count = 0;
	int unibiflow_count = 0;
	int uIP_error = 0;

	for (CFlowList::iterator flowiterator = full_flowlist.begin(); flowiterator < full_flowlist.end(); flowiterator++) { // Go through all flows

		// Show progress on console
		static int i = 0;
		if (((i++ % 100000) == 0) && (i > 0)) {
			cout << ".";
			cout.flush();
		}

		if ((flowiterator->flowtype & uniflow) != 0) {
			uniflow_count++;

			FlowHashKeyHostPair hostPairKey((flowiterator->localIP), (flowiterator->remoteIP));
			FlowHashMapHostPairIterator = flowHmHostPair->find(hostPairKey);
			if (FlowHashMapHostPairIterator != flowHmHostPair->end()) {
				// Host pair found
				if (FlowHashMapHostPairIterator->second > 0) {
					// There is at least one biflow between involved host pair: qualify flow
					flowiterator->flowtype |= unibiflow;
					unibiflow_count++;
				}
			}
		}
	}
	delete flowHmHostPair;

	cout << "Done (qualified a total of " << unibiflow_count << " of " << uniflow_count << " uniflows)";
	cout << " out of a total of " << full_flowlist.size() << " flows. We have a total of " << host_pairs << " host pairs.\n";
	if (uIP_error > 0)
		cerr << "\n\nERROR: found " << uIP_error << " unexpected new IP address(es) in " << __func__ << "()..\n\n";

	if (false) { // was debug 2
		char text[200];
		for (unsigned int i = 0; i < full_flowlist.size(); i++) {
			util::record2String(full_flowlist[i], text);
			cout << text;
		}
	}

	// (4) Prepare r_index for outside graphlets
	// *****************************************
	prepare_reverse_index();
}

/**
 *	Set active flowlist to section starting with a particular local IP address
 *	and ending after all flows belonging to host_count hosts.
 *
 *	\param	IP	IP address to be used for local IP (use 0 to specify first localIP found)
 *	\param	host_count Count of hosts relevant to set new flowlist end (-1: reset to full flowlist)
 *
 *	\return	bool TRUE if success, false if IP not found in flowlist
 */
bool CImport::set_localIP(IPv6_addr newLocalIP, int host_count) {
	if (host_count < 0) {
		// IP=0 is reserved to reset active flowlist to full flowlist
		active_flowlist.invalidate();
		active_flowlist.setBegin(full_flowlist.begin());
		active_flowlist.setEnd(full_flowlist.end());
		return true;
	}

	// Search for first flow belonging to requested IP
	// (this flow will have final value of variable flowlistIterator_start)
	CFlowList::iterator flowlistIterator_start = full_flowlist.begin();
	while (flowlistIterator_start != full_flowlist.end()) {
		if (flowlistIterator_start->localIP == newLocalIP) {
			break;
		} else {
			flowlistIterator_start++;
		}
	}

	// Check if requested IP has been found or not.
	if (flowlistIterator_start != full_flowlist.end()) {
		// We have found requested IP:
		// Now, search for first flow belonging to a host after we have
		// seen flows belonging to a total of "host_count" hosts.
		// (this flow will have final value of variable j)
		CFlowList::iterator flowlistIterator_end = flowlistIterator_start;
		IPv6_addr lastIP = flowlistIterator_end->localIP;
		unsigned int hc = 0; // Host iterator
		while (hc < (unsigned int) host_count && flowlistIterator_end != active_flowlist.end()) {
			if (flowlistIterator_end->localIP != lastIP) {
				lastIP = flowlistIterator_end->localIP;
				hc++;
			}
			else
				flowlistIterator_end++;
		}

		if (flowlistIterator_end - flowlistIterator_start <= 0) {
			cerr << "ERROR: no flows found for requested IP.\n";
			return false;
		} else {
			// Found a valid sub-list: make it the new active flowlist
			active_flowlist.invalidate();
			active_flowlist.setBegin(flowlistIterator_start);
			active_flowlist.setEnd(flowlistIterator_end);
			cout << "This should be the same: " << distance(flowlistIterator_start, flowlistIterator_end) << "==" << getActiveFlowlistSize() << endl;
			cout << "i=" << distance(CFlowList::const_iterator(full_flowlist.begin()), active_flowlist.begin()) << ", j=" << distance(
			      CFlowList::const_iterator(full_flowlist.begin()), active_flowlist.end()) << ", flow_count=" << getActiveFlowlistSize() << endl;
			return true;
		}
	} else {
		cerr << "ERROR: IP not found.\n";
		return false;
	}
}

/**
 *	Transform flow data (from active_flowlist) of a single local hosts into host profile graphlet data.
 *
 *	If configured then transformation also includes role summarization (configurable per role type).
 *
 *	Precondition: the flow data stored in flowlist has to be sorted such that all flows belonging to the
 *	same localIP are grouped together. This is essential to separate graphlets from each other.
 *
 *	Result: output file containing graphlet database (= collection of graphlets described in binary form)
 *
 *	Overview:
 *
 *	(I) Initialize
 *	(II) Role Identification
 *		- for all flows identify candidates for client and server role
 *		- prune client and server candidates involved in roles not meeting requirements
 *		- for all flows identify candidates for p2p flows
 *		- from all p2p candidate flows identify candidate p2p roles
 *		- prune p2p candidates involved in roles not meeting requirements
 *		- rate roles to be able to resolve conflicts in step III
 *		- create sub-roles, used for desummarization
 *		- convert multi summary node desummarization to role desummarization
 *	(III) Transform flows & roles to binary "hpg" graphlets. For each localIP do
 *		- Firstly, detect and resolve role conflicts
 *		- Add all not summarized flows to graphlet
 *		- Then, add client/server/p2p role summaries to graphlet(node desummarization is done here)
 *		- Finally, create binary output data from edge information collected
 *
 *		\exception std::string Errorstring
 *
 */
void CImport::cflow2hpg() {
	// (I) Initialize
	// **************

	// Role identifiers needed for summarization:
	CRoleMembership roleMembership; // Manages groups of hosts having same role membership set

	CClientRole clientRole(active_flowlist, prefs);
	CServerRole serverRole(active_flowlist, prefs);
	CP2pRole p2pRole(active_flowlist, prefs);
	clientRole.register_rM(roleMembership);
	serverRole.register_rM(roleMembership);
	p2pRole.register_rM(roleMembership);

	//for (uint32_t role_id=1;role_id<100000;role_id++) {
	//	desummarizedRolesSet.insert(role_id);
	//}

	// For filtering by flow type and protocol
	CFlowFilter filter(active_flowlist, prefs);

	// Summarization by flow type
	// --------------------------
	// Define a mask that defines which flowtypes can participate in roles
	int sum_flow_mask = 0;
	if (prefs.summarize_biflows)
		sum_flow_mask = biflow;
	if (prefs.summarize_uniflows)
		sum_flow_mask |= uniflow;

	// (II) Role Identification
	// ************************

	// Client & server candidate role identification
	// =============================================
	// Go through flow list to check for candidate client and server roles.
	for (unsigned int i = 0; i < getActiveFlowlistSize(); i++) {
		if (filter.filter_flow(i))
			continue;
		//util::printFlow(active_flowlist[i]);
		if ((active_flowlist[i].flowtype & sum_flow_mask) != 0) {
			clientRole.add_candidate(i);
			if (prefs.summarize_srv_roles)
				serverRole.add_candidate(i);
		}
	}
	if (debug && prefs.summarize_srv_roles) {
		cout << " ** Found " << serverRole.get_role_count() << " potential server roles.\n";
	}
	if (debug && prefs.summarize_clt_roles) {
		cout << " ** Found " << clientRole.get_role_count() << " potential client roles\n";
	}

	//cout << "client & server pruning\n"; cout.flush();

	if (debug2) {
		cout << "\nBefore client pruning:\n";
		roleMembership.print_multi_members();
	}

	//	Client & server candidate role purging
	clientRole.prune_candidates();

	if (debug2) {
		cout << "\nAfter client pruning:\n";
		roleMembership.print_multi_members();
	}

	if (debug2) {
		cout << "\nBefore server pruning:\n";
		roleMembership.print_multi_members();
	}

	if (prefs.summarize_srv_roles)
		serverRole.prune_candidates();

	if (debug2) {
		cout << "\nAfter server pruning:\n";
		roleMembership.print_multi_members();
		cout << "First p2p role number: " << roleMembership.get_role_num() << endl;
	}

	const vector<uint32_t>& flow_server_role = serverRole.get_flow_role();
	if (prefs.summarize_multclt_roles) {
		clientRole.check_multiclient(flow_server_role, filter, prefs.summarize_srv_roles);
	}

	// P2P role summarization
	// ======================
	// - Identification of p2p candidate flows
	// - P2P candidate flows purging/ P2p candidate role identification
	// - P2P role purging
	const vector<uint32_t>& flow_client_role = clientRole.get_flow_role();
	if (prefs.summarize_p2p_roles) {

		// Firstly, construct a list of potential p2p flows
		for (unsigned int i = 0; i < getActiveFlowlistSize(); i++) {
			if (filter.filter_flow(i))
				continue;
			// Ignore already summarized flows
			if (flow_client_role[i] == 0 && flow_server_role[i] == 0)
				p2pRole.add_candidate(i);
		}
		if (debug)
			cout << " ** Found " << p2pRole.get_cand_flow_num() - 1 << " potential p2p flows.\n";

		// Secondly, decide which p2p flows to reject
		p2pRole.prune_candidates(clientRole, serverRole, filter);
	}

	// Finalize roles
	// **************
	const vector<uint32_t>& flow_p2p_role = p2pRole.get_flow_role();
	vector<uint32_t> single_flow_rolenum(getActiveFlowlistSize());

	for (unsigned int j = 0; j < getActiveFlowlistSize(); j++) {
		if (filter.filter_flow(j)) {
			single_flow_rolenum[j] = 0;
			continue;
		}

		if (flow_client_role[j] == 0 && flow_server_role[j] == 0 && flow_p2p_role[j] == 0) {
			single_flow_rolenum[j] = roleMembership.add_single_flow(active_flowlist[j].remoteIP, active_flowlist[j].dPkts);
		} else {
			single_flow_rolenum[j] = 0;
		}
	}

	p2pRole.cleanConsumedClientRoles(clientRole);
	roleMembership.fill_summaryNodeList();
	clientRole.cleanConsumedClientRoles();


	if (debug) {
		cout << "\nAfter p2p pruning:\n";
		roleMembership.print_multi_members();
		roleMembership.print_multisummary_rolecount();
	}

	// rate all generated roles
	clientRole.rate_roles(full_flowlist);
	serverRole.rate_roles(full_flowlist);
	p2pRole.rate_roles(full_flowlist);

	// create sub-roles required for part. desummarization for all flow types
	serverRole.create_sub_roles();
	// both client & multiclient
	clientRole.create_sub_roles();
	p2pRole.create_sub_roles();

	calculate_multi_summary_node_desummarizations(roleMembership);

	// (III) Process selected flows to "hpg" graphlet data
	// ***************************************************
	//
	// a) Firstly, go through all flows not being member of a client role and store edge information.
	// b) Secondly, add client/server/p2p role summaries as needed to edge information.
	// c) Finally, create hpg edges from edge information collected.

	CGraphlet * graphlet;
	try {
		graphlet = new CGraphlet(hpg_filename, roleMembership);
	} catch (string & e) {
		stringstream error;
		error << "Could not create CGraphlet with this file: " << hpg_filename;
		throw error.str();
	}

	uint32_t filtered_flows = 0;
	uint32_t summarized_flows = 0;

	IPv6_addr lastIP = active_flowlist[0].localIP; // Get 1. localIP
	uint32_t i = 0;
	uint32_t ambiguous_cs_roles_flows = 0;
	uint32_t ambiguous_cp2p_roles_flows = 0;
	uint32_t ambiguous_sp2p_roles_flows = 0;
	while (i < getActiveFlowlistSize()) {
		//
		// (IIIa) Fetch next flow and update current graphlet data
		// ******************************************************
		// Check for ambiguous roles (i.e. flows being members > 1 role)
		// -----===== conflict resolution start =====-----
		// We resolve role conflicts by comparing the previously calculated role ratings.
		// The role with the higher rating keeps the flow, the other one loses it.
		if ((flow_client_role[i] != 0) && (flow_server_role[i] != 0) && prefs.summarize_clt_roles && prefs.summarize_srv_roles) {
			float clt_rating = clientRole.getRating(flow_client_role[i]);
			float srv_rating = serverRole.getRating(flow_server_role[i]);
			if (debug6) {
				cout << "INFO: ambiguous roles (client(" << flow_client_role[i] <<  "," << clt_rating << ")+server(" << flow_server_role[i] <<  "," << srv_rating << ")) for flow: " << i << endl;
				cout << ((clt_rating < srv_rating)?"server":"client") << " wins" << endl;
			}
			CRole::role_t* client_role = clientRole.getRole(flow_client_role[i]);
			CRole::role_t* srv_role = serverRole.getRole(flow_server_role[i]);
			if (client_role == NULL || srv_role == NULL) { // can't resolve
				cerr << "unable to resolve role conflict between client and server(" << i << ")" << endl;
				ambiguous_cs_roles_flows++;
			} else { // conflict resolution
				bool was_successful;
				// try to resolve conflict with role rating information. if not possible, try to resolve it the other way round
				if (clt_rating < srv_rating) {
					was_successful = srv_role->removeFlow(i, active_flowlist, roleMembership) || client_role->removeFlow(i, active_flowlist, roleMembership);
				} else {
					was_successful = client_role->removeFlow(i, active_flowlist, roleMembership) || srv_role->removeFlow(i, active_flowlist, roleMembership);
				}
				if (!was_successful) {
					cerr << "role conflict resolution not successful" << endl;
				} else {
					if (debug6) {
						cout << "role conflict resolved" << endl;
					}
				}
			}
		} else if ((flow_client_role[i] != 0) && (flow_p2p_role[i] != 0) && prefs.summarize_clt_roles && prefs.summarize_p2p_roles) {
			float clt_rating = clientRole.getRating(flow_client_role[i]);
			float p2p_rating = p2pRole.getRating(flow_p2p_role[i]);
			if (debug6) {
				cout << "INFO: ambiguous roles (client(" << flow_client_role[i] <<  "," << clt_rating << ")+p2p(" << flow_p2p_role[i] <<  "," << p2p_rating << ")) for flow: " << i << endl;
				cout << ((clt_rating < p2p_rating)?"p2p":"client") << " wins" << endl;
			}
			CRole::role_t* client_role = clientRole.getRole(flow_client_role[i]);
			CRole::role_t* p2p_role = p2pRole.getRole(flow_p2p_role[i]);
			if (client_role == NULL || p2p_role == NULL) { // can't resolve
				cerr << "unable to resolve role conflict between client and p2p(" << i << ")" << endl;
				ambiguous_cp2p_roles_flows++;
			} else { // conflict resolution
				bool was_successful;
				// try to resolve conflict with role rating information. if not possible, try to resolve it the other way round
				if (clt_rating < p2p_rating) {
					was_successful = p2p_role->removeFlow(i, active_flowlist, roleMembership) || client_role->removeFlow(i, active_flowlist, roleMembership);
				} else {
					was_successful = client_role->removeFlow(i, active_flowlist, roleMembership) || p2p_role->removeFlow(i, active_flowlist, roleMembership);
				}
				if (!was_successful) {
					cerr << "role conflict resolution not successful" << endl;
				} else {
					if (debug6) {
						cout << "role conflict resolved" << endl;
					}
				}
			}
		} else if ((flow_server_role[i] != 0) && (flow_p2p_role[i] != 0) && prefs.summarize_srv_roles && prefs.summarize_p2p_roles) {
			float srv_rating = serverRole.getRating(flow_server_role[i]);
			float p2p_rating = p2pRole.getRating(flow_p2p_role[i]);
			if (debug6) {
				cout << "INFO: ambiguous roles (server(" << flow_server_role[i] <<  "," << srv_rating << ")+p2p(" << flow_p2p_role[i] <<  "," << p2p_rating << ")) for flow: " << i << endl;
				cout << ((srv_rating < p2p_rating)?"p2p":"server") << " wins" << endl;
			}
			CRole::role_t* srv_role = serverRole.getRole(flow_server_role[i]);
			CRole::role_t* p2p_role = p2pRole.getRole(flow_p2p_role[i]);
			if (srv_role == NULL || p2p_role == NULL) { // can't resolve
				cerr << "unable to resolve role conflict between server and p2p(" << i << ")" << endl;
				ambiguous_sp2p_roles_flows++;
			} else { // conflict resolution
				bool was_successful;
				// try to resolve conflict with role rating information. if not possible, try to resolve it the other way round
				if (srv_rating < p2p_rating) {
					was_successful = p2p_role->removeFlow(i, active_flowlist, roleMembership) || srv_role->removeFlow(i, active_flowlist, roleMembership);
				} else {
					was_successful = srv_role->removeFlow(i, active_flowlist, roleMembership) || p2p_role->removeFlow(i, active_flowlist, roleMembership);
				}
				if (!was_successful) {
					cerr << "role conflict resolution not successful" << endl;
				} else {
					if (debug6) {
						cout << "role conflict resolved" << endl;
					}
				}
			}
		}
		// -----===== conflict resolution end =====-----

		if (filter.filter_flow(i)) {
			filtered_flows++;
		} else if ((prefs.summarize_clt_roles && (flow_client_role[i] != 0)) || (prefs.summarize_srv_roles && (flow_server_role[i] != 0))
		      || (prefs.summarize_p2p_roles && (flow_p2p_role[i] != 0))) {
			// Do not process flows that are summarized (part of a role)
			summarized_flows++;
		} else {
			// Add current flow to graphlet: this is an unsummarized flow
			graphlet->add_single_flow(active_flowlist[i], single_flow_rolenum[i], i);
		}

		// Switch to next flow
		i++;
	}

	// (IIIb) Summarize pending roles
	// ==============================
	//
	if (prefs.summarize_clt_roles) { // Add client summary nodes to graphlet
		// Add client roles
		int c = 0;
		CRole::role_t * role = clientRole.get_next_role();
		while (role != NULL) {
			if (role->role_num != 0) { // Role number 0 marks an invalidated role
				if (debug2) {
					cout << "Client role " << c++ << endl;
				}
				graphlet->add_generic_role(*(role->getUsedSubRole(desummarizedRolesSet, desummarizedMultiNodeRolesSet)), *role, lastIP, active_flowlist);
			}
			role = clientRole.get_next_role();
		}
	}

	if (prefs.summarize_multclt_roles) { // Add multi-client summary nodes to graphlet
		// Add multi-client roles
		int c = 0;
		CRole::role_t * role = clientRole.get_next_mrole();
		while (role != NULL) {
			if (role->role_num != 0) { // Role number 0 marks an invalidated role
				if (debug2) {
					cout << "Multi-client role " << c++ << endl;
				}
				graphlet->add_generic_role(*(role->getUsedSubRole(desummarizedRolesSet, desummarizedMultiNodeRolesSet)), *role, lastIP, active_flowlist);
			}
			role = clientRole.get_next_mrole();
		}
	}

	if (prefs.summarize_srv_roles) { // Add server summary nodes to graphlet
		// Add server roles
		int c = 0;
		CRole::role_t * role = serverRole.get_next_role();
		while (role != NULL) {
			if (role->role_num != 0) { // Role number 0 marks an invalidated role
				if (debug2) {
					cout << "Server role " << c++ << endl;
				}
				graphlet->add_generic_role(*(role->getUsedSubRole(desummarizedRolesSet, desummarizedMultiNodeRolesSet)), *role, lastIP, active_flowlist);
			}
			role = serverRole.get_next_role();
		}
	}

	if (prefs.summarize_p2p_roles) { // Add p2p summary nodes to graphlet
		// Add p2p roles
		int c = 0;
		CRole::role_t * role = p2pRole.get_next_role();
		while (role != NULL) {
			if (role->role_num != 0) { // Role number 0 marks an invalidated role
				if (debug2) {
					cout << "P2P role " << c++ << endl;
				}
				graphlet->add_generic_role(*(role->getUsedSubRole(desummarizedRolesSet, desummarizedMultiNodeRolesSet)), *role, lastIP, active_flowlist);
			}
			role = p2pRole.get_next_role();
		}
	}

	//
	// (IIId) Finalize current graphlet and prepare for a next one
	// ==========================================================
	// Next flow belongs to new localIP: thus, finalize current host graphlet.
	//
	graphlet->finalize_graphlet(0);
	// Remember new localIP for change testing

	if (ambiguous_cs_roles_flows > 0)
		cerr << "INFO: ambiguous roles (client+server) for " << ambiguous_cs_roles_flows << " flows.\n";
	if (ambiguous_cp2p_roles_flows > 0)
		cerr << "INFO: ambiguous roles (client+p2p) for " << ambiguous_cp2p_roles_flows << " flows.\n";
	if (ambiguous_sp2p_roles_flows > 0)
		cerr << "INFO: ambiguous roles (server+p2p) for " << ambiguous_sp2p_roles_flows << " flows.\n";
	if (summarized_flows)
		cout << "Summarized flows: " << summarized_flows << endl;
	if (filtered_flows)
		cout << "Filtered flows: " << filtered_flows << " out of " << getActiveFlowlistSize() << " flows." << endl;

	if (debug) {
		desummarizedRoles::const_iterator dri;
		cout << "desummarized roles:\t";
		for (dri = desummarizedRolesSet.begin(); dri != desummarizedRolesSet.end(); dri++) {
			cout << (*dri) << ",";
		}
		cout << endl;

		roleMembership.print_multi_members();
		roleMembership.print_multisummary_rolecount();
		if (hap4nfsen) {
			cout << nodeInfos->printNodeInfos() << endl;
		}
	}

	if (hap4nfsen) {
		nodeInfos = graphlet->nodeInfos;
	}
	delete graphlet;
}

/**
 *	Returns all desummarized roles
 *
 *	\return desummarizedRoles A set of desummarized roles
 */
const desummarizedRoles CImport::get_desummarized_roles() {
	return desummarizedRolesSet;
}

/**
 *	Set the desummarized roles
 *
 *	\param desummarizedRoles A set of desummarized roles
 */
void CImport::set_desummarized_roles(const desummarizedRoles & role_set) {
	desummarizedRolesSet.clear();
	add_desummarized_roles(role_set);
}

/**
 *	Adds roles to the desummarzied ones
 *
 *	\param desummarizedRoles Desummarized roles to add
 */
void CImport::add_desummarized_roles(const desummarizedRoles & role_set) {
	desummarizedRolesSet.insert(role_set.begin(), role_set.end());
}

/**
 * Delete all desummarizes roles
 */
void CImport::clear_desummarized_roles() {
	desummarizedRolesSet.clear();
	desummarizedMultiNodeRolesSet.clear();
}

/**
 *	Calculates which multi-summary nodes have to be desummarized
 *
 *	\param roleMembership Holds the membership of the cflows
 */
void CImport::calculate_multi_summary_node_desummarizations(CRoleMembership & roleMembership) {
	const uint32_t MULTI_SUM_NODE_MASK = 0x00f00000; // value is only 24 bit
	const uint32_t MULTI_SUM_NODE_SHIFT = 23; // 24 bit-1 bit

	set<int> multi_sum_node_ids;
	for (desummarizedRoles::const_iterator role_iter = desummarizedRolesSet.begin(); role_iter != desummarizedRolesSet.end(); ++role_iter) {
		roleNumber role = *role_iter;
		if (((role & MULTI_SUM_NODE_MASK) >> MULTI_SUM_NODE_SHIFT) == 1) { // role is a multi summary node id
			cout << "[1]" << role << endl;
			int multi_node_id = (((int) (ROLE_NR_BIT_MASK - role)) * -1) - 1; // must be a(signed) integer because multi sum ids use negative role numbers
			cout << "[2]" << multi_node_id << endl;
			multi_sum_node_ids.insert(multi_node_id);
		}
	}

	CRoleMembership::multiSummaryNodeHashMap* m_s_nodes = roleMembership.get_hm_multiSummaryNode();
	for (CRoleMembership::multiSummaryNodeHashMap::const_iterator m_sum_iter = m_s_nodes->begin(); m_sum_iter != m_s_nodes->end(); ++m_sum_iter) {
		int multi_node_id = m_sum_iter->second->role_num;
		//cout << "candidate: " << multi_node_id << endl;
		set<int>::const_iterator mn_id_iter = multi_sum_node_ids.find(multi_node_id);
		if (mn_id_iter != multi_sum_node_ids.end()) { // multi-node should be desummarized
			if (debug6) {
				m_sum_iter->first.printkey();
			}
			cout << "found!" << endl;
			const boost::array<uint16_t, 8> roles = m_sum_iter->first.getRoles();
			cout << util::bin2hexstring(&roles, 16) << endl;
			for (boost::array<uint16_t, 8>::const_iterator role_iter = roles.begin(); role_iter != roles.end(); ++role_iter) {
				cout << "contains role: " << (*role_iter) << endl;
				desummarizedMultiNodeRolesSet.insert(*role_iter); // store values so they can later be used in getUsedSubRole
			}
		}
	}
}

/**
 *	Get host metadata from "flowlist" and store it in "hostMetadata".
 */
void CImport::get_hostMetadata() {
	// Scan flow list and assemble for each localIP the metadata
	assert(getActiveFlowlistSize() > 0);
	IPv6_addr lastIP = active_flowlist[0].localIP; // Get 1. localIP
	int hostFlowIndex = 0;
	int host_flows = 0;
	set<uint8_t> proto_set;

	int maxnum_hosts = 1;
	for (unsigned int j = 0; j < getActiveFlowlistSize(); j++) {
		if (active_flowlist[j].localIP != lastIP) {
			maxnum_hosts++;
			lastIP = active_flowlist[j].localIP;
		}
	}
	cout << "Input file " << in_filename << " contains " << maxnum_hosts << " unique local hosts.\n";

	hostMetadata.resize(maxnum_hosts);

	Subflowlist::const_iterator it = active_flowlist.begin();
	int host_index = -1;
	while (it != active_flowlist.end()) {
		// Check if host data is complete
		if (it->localIP != hostMetadata[host_index].IP || it == active_flowlist.begin()) {
			host_index++;
			hostMetadata[host_index].IP = it->localIP;
			hostMetadata[host_index].graphlet_number = host_index;
			hostMetadata[host_index].uniflow_count = 0;
			hostMetadata[host_index].packet_count = 0;
			hostMetadata[host_index].bytesForAllFlows = 0;
			hostMetadata[host_index].prot_count = 0;
			hostMetadata[host_index].index = 0;
			host_flows = 0;
			proto_set.clear();
			// Prepare for next host
			hostFlowIndex = distance(active_flowlist.begin(), it);
			// Remember new srcIP for change testing
			assert((unsigned int)host_index <= hostMetadata.size());

			//			// Show progress on console
			//			if ((host_index % 10000) == 0) {
			//				cout << ".";
			//				cout.flush();
			//			}
		}
		if (it->flowtype & uniflow)
			hostMetadata[host_index].uniflow_count++;
		hostMetadata[host_index].packet_count += it->dPkts;
		hostMetadata[host_index].bytesForAllFlows += it->dOctets;
		proto_set.insert(it->prot);
		hostMetadata[host_index].prot_count = proto_set.size();
		hostMetadata[host_index].index = hostFlowIndex;
		hostMetadata[host_index].flow_count = ++host_flows;
		it++;
	}

	next_host = 0;
	cout << "\nMetadata for " << host_index + 1 << " local hosts prepared.\n";
}

/**
 *	Return first host metadata (graphlet property) object.
 *
 *	\return Reference to host property object
 *
 * \pre hostMetadata.size() > 0
 *
 *	\exception std::string Errormessage
 */
const ChostMetadata & CImport::get_first_host_metadata() {
	if (hostMetadata.size() > 0) {
		next_host = 1;
		return hostMetadata[0];
	}
	throw "invalid access to an empty hostMetadata";
}

/**
 *	Return next host metadata (graphlet property) object.
 *	Use get_first_host() to scan list from beginning.
 *
 *	\return Reference to host property object
 *
 *	\pre next_host < hostMetadata.size() - 1
 *
 *	\exception std::string Errormessage
 */
const ChostMetadata & CImport::get_next_host_metadata() {
	if (next_host < ((int) hostMetadata.size())) {
		return hostMetadata[next_host++];
	}
	throw "invalid access behind the last element of hostMetadata";
}

/**
 *	Get a list of flows
 *
 *	\param flIndex Index into flowlist
 *	\param flow_count Number of flows
 *
 *	\return Subflowlist Subflowlist which ranges from flIndex to flIndex + flow_count in full_flowlist
 *
 *	\pre full_flowlist.size() >= flIndex + flow_count
 */
Subflowlist CImport::get_flow(unsigned int flIndex, unsigned int flow_count) const {
	assert(full_flowlist.size() >= flIndex + flow_count);
	return Subflowlist(full_flowlist.begin() + flIndex, full_flowlist.begin() + flIndex + flow_count);
}

/**
 *	Get the flowlist belonging to a graphlet of a remote host (remoteIP).
 *	Go through flow list and pick any flow containing remoteIP. To do this we need
 *	a previously initialized array r_index that contains an index such that remoteIPs are
 *	sorted in ascending order. All found flows are stored in a new temporary flowlist
 *	allocated on the fly for the requested remoteIP.
 *
 *	\param remoteIP IP address of a remote host
 *	\return CFlowList flowlist
 */
const CFlowList CImport::get_outside_graphlet_flows(IPv6_addr remoteIP) {
	// Search for first flow belonging to graphlet
	unsigned int i = 0;
	for (; i < full_flowlist.size(); i++) {
		int ii = remoteIP_index[i];
		if (full_flowlist[ii].remoteIP == remoteIP)
			break;
	}

	int flow_cnt = 0;
	unsigned int j = 0;
	if (i < full_flowlist.size()) { // Check if any flows found: i points to first such flow
		// Count the number of flows belonging to graphlet
		j = i + 1;
		// A flow has been found: look for more
		for (; j < full_flowlist.size(); j++) {
			int jj = remoteIP_index[j];
			if (full_flowlist[jj].remoteIP != remoteIP)
				break; // Found all flows
		}
		flow_cnt = j - i; // j points to first flow not belonging to graphlet
	}

	CFlowList flows(flow_cnt);
	if (flows.size() > 0) {
		// Now we are going to allocate and fill the graphlet's temporary flowlist
		//	flows = new cflow_t[flow_cnt + 1];
		// flows[flow_cnt].remoteIP = util::getDummyIpV6();	// Use extra entry for finalization check

		for (unsigned int k = 0; k < flows.size(); k++) { // Copy flow records in sorted order
			cflow_t temp = full_flowlist[remoteIP_index[i + k]];
			flows[k] = temp; // Make a copy and modify then direction-dependent fields
			// Exchange local <-> remote
			flows[k].localIP = temp.remoteIP;
			flows[k].remoteIP = temp.localIP;
			flows[k].localPort = temp.remotePort;
			flows[k].remotePort = temp.localPort;
			// Adjust flow direction if needed
			if ((temp.flowtype & uniflow) == uniflow) {
				; // Do not modify transit flows
			} else if ((temp.flowtype & inflow) != 0) {
				temp.flowtype = (temp.flowtype & (~inflow)) | outflow;
			} else if ((temp.flowtype & outflow) != 0) {
				temp.flowtype = (temp.flowtype & (~outflow)) | inflow;
			}
			flows[k].flowtype = temp.flowtype;
		}
		if (debug2) {
			cout << "First 20 flows for this graphlet:\n";
			for (int i = 0; i < 20; i++) {
				cout << flows[i] << endl;
			}
		}
	}
	return flows;
}

/**
 *	Print current content of flowlist in human readable form to console.
 *
 *	\param	linecount	Maximal count of flow to display (0: for all)
 */
void CImport::print_flowlist(unsigned int linecount) {
	if (getActiveFlowlistSize() == 0) {
		cout << "Empty flow list: nothing to print.\n";
	} else {
		cout << "Flow list contains " << getActiveFlowlistSize() << " flows.\n";
		unsigned int maxcount = (linecount < getActiveFlowlistSize()) && (linecount != 0) ? linecount : getActiveFlowlistSize();
		copy(active_flowlist.begin(), active_flowlist.begin() + maxcount, ostream_iterator<cflow_t> (cout, "\n"));
	}
}

/**
 *	Return the hpg filename in use
 *
 *	\return	std::string Name of the hpg filename used
 */
std::string CImport::get_hpg_filename() const {
	return hpg_filename;
}

/**
 *	Return the input filename in use
 *
 *	\return	std::string Name of the file which will be read
 */
std::string CImport::get_in_filename() const {
	return in_filename;
}

/**
 *	Returns the number of cflows in the full_flowlist
 *
 *	\return	int Number of elements in full_flowlist
 */
int CImport::get_flow_count() const {
	return full_flowlist.size();
}

/**
 *	Return true if there is a gfilter which can read the supplied file
 *
 * \param in_filename Filename to check
 *
 *	\return	bool True if there is a gfilter available for this filetype, false if not
 */
bool CImport::acceptForImport(const string & in_filename) {
	std::vector<GFilter *>::iterator importfilterIterator;

	if (inputfilters.empty())
		initInputfilters();

	for (importfilterIterator = inputfilters.begin(); importfilterIterator != inputfilters.end(); importfilterIterator++) {
		if ((*importfilterIterator)->acceptFileForReading(in_filename))
			return true;
	}
	return false;
}

/**
 *	Return true if there is a gfilter which can write to the supplied file
 *
 * \param in_filename Filename to check
 *
 *	\return	bool True if there is a gfilter available for this filetype, false if not
 */
bool CImport::acceptForExport(const string & out_filename) {
	std::vector<GFilter *>::iterator importfilterIterator;

	if (inputfilters.empty())
		initInputfilters();

	for (importfilterIterator = inputfilters.begin(); importfilterIterator != inputfilters.end(); importfilterIterator++) {
		if ((*importfilterIterator)->acceptFileForWriting(out_filename))
			return true;
	}
	return false;
}



/**
 *	Writes a flowlist to the given file
 *
 * \param in_filename Filename to write to
 * \param subflowlist Subflowlist to write to
 *
 * \exception std::string Errormessage
 */
void CImport::write_file(std::string out_filename, const Subflowlist & subflowlist, bool appendIfExisting) {
	std::vector<GFilter *>::iterator filterIterator;

	if (inputfilters.empty())
		initInputfilters();

	for (filterIterator = inputfilters.begin(); filterIterator != inputfilters.end(); filterIterator++) {
		if ((*filterIterator)->acceptFileForWriting(out_filename)) {
			try {
				(*filterIterator)->write_file(out_filename, subflowlist, appendIfExisting);
			} catch (string & e) {
				throw e;
			}
			return;
		}
	}
	throw "no usable exportfilter found";
}

/**
 *	Writes a flowlist to the given file
 *
 * \param in_filename Filename to write to
 *
 * \exception std::string Errormessage
 */
void CImport::write_file(std::string out_filename, const CFlowList & flowlist, bool appendIfExisting) {
	Subflowlist sublist(flowlist.begin(), flowlist.end());
	write_file(out_filename, sublist, appendIfExisting);
}

/**
 *	Return the name of the filetype of the give filename
 *
 * \param in_filename Filename to check
 *
 *	\return	std::string Filetype of given filename or "none" if no gfilter accepts the supplied filename
 */
std::string CImport::getFormatName(std::string & in_filename) {
	std::vector<GFilter *>::iterator importfilterIterator;

	if (inputfilters.empty())
		initInputfilters();

	for (importfilterIterator = inputfilters.begin(); importfilterIterator != inputfilters.end(); importfilterIterator++) {
		if ((*importfilterIterator)->acceptFileForReading(in_filename))
			return (*importfilterIterator)->getFormatName();
	}
	return "none";
}

/**
 *	Return the name of the filetypes supported
 *
 *	\return	vector<std::string> Vector of supported filetypes
 */
vector<std::string> CImport::getAllFormatNames() {
	std::vector<GFilter *>::iterator importfilterIterator;
	vector<string> allTypeNames;

	if (inputfilters.empty())
		initInputfilters();

	for (importfilterIterator = inputfilters.begin(); importfilterIterator != inputfilters.end(); importfilterIterator++)
		allTypeNames.push_back((*importfilterIterator)->getFormatName());
	return allTypeNames;
}



/**
 *	Return the human readable patterns of the filetypes supported
 *
 *	\return	vector<std::string> Vector of patterns of supported filetypes
 */
vector<std::string> CImport::getAllHumanReadablePatterns() {
	std::vector<GFilter *>::iterator importfilterIterator;
	vector<string> allTypeNames;

	if (inputfilters.empty())
		initInputfilters();

	for (importfilterIterator = inputfilters.begin(); importfilterIterator != inputfilters.end(); importfilterIterator++)
		allTypeNames.push_back((*importfilterIterator)->getHumanReadablePattern());
	return allTypeNames;
}

/**
 *	Print all supported filetypes to an ostream
 *
 *	\return	std::ostream Reference to used ostream
 */
std::ostream & CImport::printAllTypeNames(std::ostream & os) {
	vector<string> allTypeNames = getAllFormatNames();
	vector<string>::iterator it = allTypeNames.begin();
	os << (it != allTypeNames.end() ? *it : "");
	for (; it != allTypeNames.end(); ++it)
		os << *it << endl;
	return os;
}

/**
 *	Return all supported filetypes as a string, separated with ", "
 *
 *	\return	std::ostream Reference to used ostream
 */
std::string CImport::getFormatNamesAsString() {
	vector<string> allTypeNames = getAllFormatNames();
	string ret;
	vector<string>::iterator it = allTypeNames.begin();
	ret += (it != allTypeNames.end() ? *it : "");
	for (; it != allTypeNames.end(); ++it) {
		ret += ", ";
		ret += *it;
	}
	return ret;
}

/**
 *	Reads the (previously) set filename into memory
 *
 *	\param local_net Local network address
 *	\param netmask Network mask for local network address
 *
 * \pre one of the installed GFilter supports the given file
 *
 * \exception string Errortext
 */
void CImport::read_file(const IPv6_addr & local_net, const IPv6_addr & netmask) {
	if (inputfilters.empty())
		initInputfilters();

	std::vector<GFilter *>::iterator importfilterIterator;

	for (importfilterIterator = inputfilters.begin(); importfilterIterator != inputfilters.end(); importfilterIterator++) {
		if ((*importfilterIterator)->acceptFileForReading(in_filename)) {
			try {
				(*importfilterIterator)->read_file(in_filename, full_flowlist, local_net, netmask, false);
			} catch (string & e) {
				throw e;
			}
			catch (...) {
				throw string("Unkown error while importing");
			}
			prepare_flowlist();
			return;
		}
	}

	throw "no usable importfilter found";
}

/**
 *	Disables the remote-IP lookup
 */
void CImport::set_no_reverse_index() {
	use_reverse_index = false;
}

/**
 *	Return the active Subflowlist in use
 */
Subflowlist CImport::getActiveFlowlist() {
	return active_flowlist;
}

/**
 *	Invalidate the active_flowlist
 */
void CImport::invalidate() {
	active_flowlist.invalidate();
}

/**
 *	Set the begin of the active_flowlist at a specific index of the full flowlist
 *
 *	\param start Index of the full flowlist to become the start of the active_flowlist
 *
 *	\pre full_flowlist.size() >= start
 */
void CImport::setBegin(unsigned int start) {
	assert(full_flowlist.size() >= start);
	active_flowlist.invalidateBegin();
	active_flowlist.setBegin(full_flowlist.begin() + start);
}

/**
 *	Set the end of the active_flowlist
 *
 *	\param start Index of the full flowlist to become the end of the active_flowlist
 *
 *	\pre full_flowlist.size() >= last
 */
void CImport::setEnd(unsigned int last) {
	assert(full_flowlist.size() >= last);
	active_flowlist.invalidateEnd();
	active_flowlist.setEnd(full_flowlist.begin() + last);
}
