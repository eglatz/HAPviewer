/**
 *	\file grole.cpp
 *	\brief Classes for host role summarization.
 *	Extracted roles are: client/server/p2p
 *	Results:
 *	- A list of roles
 *	- All summarized flows are marked with their role
 */

#include <iostream>
#include <string>
#include <netinet/in.h>
#include <assert.h>
#include <boost/shared_ptr.hpp>
#include <algorithm>
#include <cmath>
#include <sstream>

#include "gutil.h"
#include "grole.h"

using namespace std;

#ifdef NDEBUG
static bool debug =false;
static bool debug2=false; // Show multiclient details
static bool debug3=false;// Show client/server/p2p role details
//static bool debug4=true;	// Report on particular role number
#else
static bool debug = true;
static bool debug2 = true; // Show multiclient details
static bool debug3 = false; // Show client/server/p2p role details
//static bool debug4=true;	// Report on particular role number
#endif

// This var. is only used when debug3=true
static const string ip("xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx"); // Define here the remote IP address to track

//********************************************************************************

/**
 * Constructor for CRole
 *
 * \param flow_list Sub-Flowlist required to access flows of the current graphlet
 * \param prefs User defined settings
 */
CRole::CRole(Subflowlist flow_list, const prefs_t & prefs) :
	flowlist(flow_list), prefs(prefs) {
	flow_role.resize(flowlist.size(), 0);
	role_count = 0;
	first2 = true;
	first = true;
}

/**
 * Create ratings for a specific role. Ratings are used to resolve role conflicts. Only implemented in sub-classes.
 *
 * \param role Role to be rated
 * \param full_flowlist Flowlist containing all available data
 * \param sub_flowlist Flowlist containing all flows used in the current graphlets
 */
void CRole::rate_role(role_t& role, const CFlowList& full_flowlist, const Subflowlist& sub_flowlist) {
	assert(false);
	// only used for sub-classes
}

/**
 * Create ratings for all roles of this type. Uses rate_role to rate roles. Only implemented in sub-classes.
 *
 * \param full_flowlist Flowlist containing all available data
 */
void CRole::rate_roles(const CFlowList& full_flowlist) {
	assert(false);
	// only used for sub-classes
}

/**
 * Get the role rating for the specified role. Only implemented in sub-classes.
 *
 * \param role_id Role id
 *
 * \return float Flow rating
 */
float CRole::getRating(const int role_id) {
	assert(false);
	return 0.0;
	// only used for sub-classes
}

/**
 * Create ratings for a specific role. Ratings are used to resolve role conflicts.
 *
 * \param role Role to be rated
 * \param full_flowlist Flowlist containing all available data
 * \param sub_flowlist Flowlist containing all flows used in the current graphlets
 */
void CP2pRole::rate_role(role_t& role, const CFlowList& full_flowlist, const Subflowlist& sub_flowlist) {
	uint32_t flowlist_size = role.flow_set->size();
	// check if flows can be removed from role without violating the rules for the minimum number of members
	if (flowlist_size==p2p_threshold) { // cannot remove any flows
		role.rating = 1;
		return;
	}

	// calculate flow rating
	uint32_t flow_counter = flowlist_size;
	// step 1: prepare "filters" used to identify candidates
	bool local_ip_set = false; // helps to avoid unnecessary copying of the local ip address
	set<IPv6_addr> remote_ips;
	IPv6_addr local_ip;
	uint32_t protocol = role.prot;
	for (set<int>::const_iterator it = role.flow_set->begin(); it != role.flow_set->end(); it++) {
		if (!local_ip_set) {
			local_ip = sub_flowlist[*it].localIP;
			local_ip_set = true;
		}
		remote_ips.insert(sub_flowlist[*it].remoteIP);
	}
		// step 1.1 calculate client candidates with high role number
		// generate candidates
		p2pClientCandidateHashMap client_candidates;
		for (Subflowlist::const_iterator it = full_flowlist.begin(); it != full_flowlist.end(); it++) {
			// flow is not a candidate because it..
			if (it->localIP == local_ip || // ..is part of the graphlet
					it->prot != protocol || // ..uses another protocol
					remote_ips.find(it->remoteIP) == remote_ips.end()) { // ..communicates with other remote IPs(== is not in the role's remote ip set)
				continue;
			}
			HashKeyIPv6_5T_2 client_key(it->localIP, it->remoteIP, it->prot, it->localPort, it->flowtype);
			p2pClientCandidateHashMap::iterator candidate_set = client_candidates.find(client_key);
			if (candidate_set == client_candidates.end()) { // entry does not exist => create
				set<const cflow_t*> candidates;
				candidates.insert(&(*it));
				client_candidates[client_key] = candidates;
			} else { // entry exists => update
				candidate_set->second.insert(&(*it));
			}
		}
		// accept candidates with remote_port
		set<const cflow_t*> accepted_client_candidates;
		for (p2pClientCandidateHashMap::iterator it = client_candidates.begin(); it != client_candidates.end(); it++) {
			if (it->second.size() < client_threshold) { // ignore roles with less than client_threshold flows
				continue;
			}
			for (set<const cflow_t*>::iterator flow_set_it = it->second.begin(); flow_set_it != it->second.end(); flow_set_it++) {
				if ((*flow_set_it)->remotePort >= p2p_port_threshold) { // port is greater than p2p_port_threshold => accept candidate
					accepted_client_candidates.insert(*flow_set_it);
				}
			}
		}

	// step 2: find flows outside of the current graphlet, that would share the role
	for (vector<cflow_t>::const_iterator it = full_flowlist.begin(); it != full_flowlist.end(); it++) {
		// flow is not counted because it..
		if (it->localIP == local_ip || // ..already is
				(it->remotePort < p2p_port_threshold && it->localPort < p2p_port_threshold) || // ..has both port numbers < p2p_port_threshold
					it->prot != protocol || // ..uses another protocol
					remote_ips.find(it->remoteIP) == remote_ips.end()) { // ..communicates with other remote IPs(== is not in the role's remote ip set)
			continue;
		}
		// check if the candidate flows match the p2p criteria
		bool high_ports = (it->remotePort >= p2p_port_threshold && it->localPort >= p2p_port_threshold);
		bool client_high_service = accepted_client_candidates.find(&(*it)) != accepted_client_candidates.end();
		// hosts using both protocols are automatically included by the normal candidate generation&prining process
		if (high_ports ||
				client_high_service) {
			// role candidate outside current graphlet found => increment counter
			flow_counter++;
		}
	}

	// step 3: calculate rating
	role.rating = flow_counter/((float)flow_rate_threshold);
	role.rating = min(role.rating, 1.0f); // ensures that rating is <= 1
}

/**
 * Create ratings for all roles of this type. Uses rate_role to rate roles.
 *
 * \param full_flowlist Flowlist containing all available data
 */
void CP2pRole::rate_roles(const CFlowList& full_flowlist) {
	for (p2pRoleHashMap::iterator it = hm_p2p_role->begin(); it != hm_p2p_role->end(); it++) {
		if ((it->second)->role_num == 0) { // skip invalid roles
			continue;
		}
		rate_role(*(it->second), full_flowlist, flowlist);
	}
}

/**
 * Get the role rating for the specified role.
 *
 * \param role_id Role id
 *
 * \return float Flow rating
 */
float CP2pRole::getRating(const int role_id) {
	for (p2pRoleHashMap::iterator it = hm_p2p_role->begin(); it != hm_p2p_role->end(); it++) {
		if ((it->second)->role_num == role_id) { // skip invalid roles
			return (*(it->second)).rating;
		}
	}
	cout << "unable to find p2p role with role id " << role_id << endl;
	return 0;
}

/**
 * Create ratings for a specific role. Ratings are used to resolve role conflicts.
 *
 * \param role Role to be rated
 * \param full_flowlist Flowlist containing all available data
 * \param sub_flowlist Flowlist containing all flows used in the current graphlets
 */
void CServerRole::rate_role(role_t& role, const CFlowList& full_flowlist, const Subflowlist& sub_flowlist) {
	role.rating = role.flows/((float)flow_rate_threshold); // all instances of the server role are already included in this graphlet => no need to check the rest of the flowlist
	if (role.flow_set->size()==server_threshold) { // cannot remove any flows
		role.rating = 1;
	}
	role.rating = min(role.rating, 1.0f); // ensures that rating is <= 1
}

/**
 * Create ratings for all roles of this type. Uses rate_role to rate roles.
 *
 * \param full_flowlist Flowlist containing all available data
 */
void CServerRole::rate_roles(const CFlowList& full_flowlist) {
	for (srvRoleHashMap::iterator it = hm_server_role->begin(); it != hm_server_role->end(); it++) {
		if ((it->second)->role_num == 0) { // skip invalid roles
			continue;
		}
		rate_role(*(it->second), full_flowlist, flowlist);
	}
}

/**
 * Get the role rating for the specified role.
 *
 * \param role_id Role id
 *
 * \return float Flow rating
 */
float CServerRole::getRating(const int role_id) {
	for (srvRoleHashMap::iterator it = hm_server_role->begin(); it != hm_server_role->end(); it++) {
		if ((it->second)->role_num == role_id) { // skip invalid roles
			return (*(it->second)).rating;
		}
	}
	cout << "unable to find server role with role id " << role_id << endl;
	return 0;
}

/**
 * Create ratings for a specific role. Ratings are used to resolve role conflicts.
 *
 * \param role Role to be rated
 * \param full_flowlist Flowlist containing all available data
 * \param sub_flowlist Flowlist containing all flows used in the current graphlets
 */
void CClientRole::rate_role(role_t& role, const CFlowList& full_flowlist, const Subflowlist& sub_flowlist) {
	char role_type = role.role_type;
	uint32_t flowlist_size = role.flow_set->size();
	// check if flows can be removed from role without violating the rules for the minimum number of members
	if ((role_type == 'c' && flowlist_size == client_threshold) || // check minimum number of flows for client..
			(role_type == 'm' && flowlist_size == multi_client_threshold)) { // ..and multiclient roles
		role.rating = 1; // cannot remove any flows
		return;
	}

	// calculate flow rating
	uint32_t flow_counter = 0;
	// step 1: prepare "filters" used to identify candidates
	bool local_ip_set = false; // helps to avoid unnecessary copying of the local ip address
	set<IPv6_addr> remote_ips;
	IPv6_addr local_ip;
	uint32_t protocol = role.prot;
	uint16_t remote_port = role.remotePort;
	set<int> flow_set;
	flow_set.insert(role.flow_set->begin(), role.flow_set->end());
	// if role is a multi-client role: => get all flows from consumed sub-roles
	if (role.role_type == 'm') {
		for (set<role_t *>::iterator sr_iter = role.role_set_->begin(); sr_iter != role.role_set_->end(); sr_iter++) {
			flow_set.insert((*sr_iter)->flow_set->begin(), (*sr_iter)->flow_set->end());
		}
	}
	flow_counter = flow_set.size();
	for (set<int>::const_iterator it = flow_set.begin(); it != flow_set.end(); it++) {
		if (!local_ip_set) {
			local_ip = sub_flowlist[*it].localIP;
			local_ip_set = true;
		}
		remote_ips.insert(sub_flowlist[*it].remoteIP);
	}

	// step 2: find flows outside of the current graphlet, that would share the role
	for (vector<cflow_t>::const_iterator it = full_flowlist.begin(); it != full_flowlist.end(); it++) {
		// flow is not counted because it..
		if (it->localIP == local_ip || // ..already is
				it->remotePort != remote_port || // ..uses the wrong remote port
				it->prot != protocol || // ..uses another protocol
				remote_ips.find(it->remoteIP) == remote_ips.end()) { // ..communicates with other remote IPs(== is not in the role's remote ip set)
			continue;
		}
		// role candidate outside current graphlet found => increment counter
		flow_counter++;
	}
	// step 3: calculate rating
	role.rating = flow_counter/((float)flow_rate_threshold);
	role.rating = min(role.rating, 1.0f); // ensures that rating is <= 1
}

/**
 * Create ratings for all roles of this type. Uses rate_role to rate roles.
 *
 * \param full_flowlist Flowlist containing all available data
 */
void CClientRole::rate_roles(const CFlowList& full_flowlist) {
	for (cltRoleHashMap::iterator it = hm_client_role->begin(); it != hm_client_role->end(); it++) {
		if ((it->second)->role_num == 0) { // skip invalid roles
			continue;
		}
		rate_role(*(it->second), full_flowlist, flowlist);
	}
	for (cltRoleHashMap::iterator it = hm_multiclient_role->begin(); it != hm_multiclient_role->end(); it++) {
		if ((it->second)->role_num == 0) { // skip invalid roles
			continue;
		}
		rate_role(*(it->second), full_flowlist, flowlist);
	}
}

/**
 * Get the role rating for the specified role.
 *
 * \param role_id Role id
 *
 * \return float Flow rating
 */
float CClientRole::getRating(const int role_id) {
	// need to check both client and multi client hash-map
	for (cltRoleHashMap::iterator it = hm_multiclient_role->begin(); it != hm_multiclient_role->end(); it++) {
		if ((it->second)->role_num == role_id) { // skip invalid roles
			return (*(it->second)).rating;
		}
	}
	for (cltRoleHashMap::iterator it = hm_client_role->begin(); it != hm_client_role->end(); it++) {
		if ((it->second)->role_num == role_id) { // skip invalid roles
			return (*(it->second)).rating;
		}
	}
	cout << "unable to find client role with role id " << role_id << endl;
	return 0;
}

/**
 * Destructor
 */
CRole::~CRole() {
//	delete[] flow_role;	// Used by get_next_role()
}

/**
 * Default constructor for rhost_t. Used in candidate generation.
 */
CRole::rhost_t::rhost_t() {
	remoteIP = IPv6_addr(); // was: remoteIP = 0;
	uses_tcp = false;
	uses_udp = true;
	flows = 0;
	packets = 0;
}

/**
 * Constructor for rhost_t. Used in candidate generation.
 *
 * \param remoteIP Remote IP address
 * \param flows Number of flows
 * \param packets Number of packets
 */
CRole::rhost_t::rhost_t(IPv6_addr remoteIP, int flows, int packets) {
	this->remoteIP = remoteIP;
	uses_tcp = false;
	uses_udp = true;
	this->flows = flows;
	this->packets = packets;
}

/**
 * Add a flow to the roles' flow set
 *
 * \param flow_id Flowlist index
 *
 * \return bool True, if the flow was successfully added
 */
bool CRole::role_t::addFlow(const int flow_id) {
	if (flow_set->find(flow_id) != flow_set->end()) {
		return false; // flow is already in list
	}
	flow_set->insert(flow_id);
	return true;
}

/**
 * Removes a flow to the roles' flow set. Used to assign flows after role conflict resolution.
 *
 * \param flow_id Flowlist index
 * \param flow_list Active sub flow list
 * \param role_membership role membership, used to update summary nodes
 *
 * \return bool True, if the flow was removed successfully
 */
bool CRole::role_t::removeFlow(const int flow_id, const Subflowlist& flow_list, CRoleMembership& role_membership) {
	if (flow_set->find(flow_id) == flow_set->end()) {
		return false; // flow is not in set and can't be removed
	}
	uint32_t flow_count = flow_set->size();
	bool not_enough_flows_left = true;
	switch (role_type) {
		case 'c': // client
			not_enough_flows_left = (flow_count <= flow_threshold_client);
			break;
		case 'm': // multi-client
			not_enough_flows_left = (flow_count <= flow_threshold_multi_client);
			break;
		case 's': // server
			not_enough_flows_left = (flow_count <= flow_threshold_server);
			break;
		case 'p': // peer to peer
			not_enough_flows_left = (flow_count <= flow_threshold_p2p);
			break;
		default: // unknown
			cerr << "unknown role type:\t" <<role_type << endl;
			break;
	}
	if (not_enough_flows_left) {
		if (debug) {
			cout << "could not remove flow " << flow_id << " from role " << role_num << ": not flow threshold reached" << endl;
		}
		return false;
	}
	flow_set->erase(flow_id);
	recalculateSummaries(flow_list, flow_id, role_membership);
	return true;
}

/**
 * Recalculate the summarized flow data after a flow has been removed
 *
 * \param flow_list active sub flow list
 * \param flow_id Index of the removed flow
 * \param role_membership role membership, used to update summary nodes
 */
void CRole::role_t::recalculateSummaries(const Subflowlist& flow_list, const int flow_id, CRoleMembership& role_membership) {
	if (debug) {
		cout << "-------------------------" << endl;
		cout << "updating role stats for role " << this->role_num << "(" << this->role_type <<")" << endl;
	}
	uint32_t flows = 0;
	uint32_t packets = 0;
	uint32_t bytes = 0;

	// iterate through associated flows and recalculate flows, packets and bytes
	for (set<int>::iterator fl_iter = flow_set->begin(); fl_iter != flow_set->end(); fl_iter++) {
		flows++;
		packets += flow_list[*fl_iter].dPkts;
		bytes +=flow_list[*fl_iter].dOctets;
	}
	if (role_type == 'm' || role_type == 'p') { // check all sub_roles(multi-client and p2p roles only)
		for (set<role_t *>::iterator rs_iter = role_set_->begin();rs_iter != role_set_->end();rs_iter++) {
			role_t* sub_role = *rs_iter;
			if (sub_role->role_num == 0) {continue;}
			for (set<int>::iterator fl_iter = sub_role->flow_set->begin(); fl_iter != sub_role->flow_set->end(); fl_iter++) {
				flows++;
				packets += flow_list[*fl_iter].dPkts;
				bytes +=flow_list[*fl_iter].dOctets;
			}
		}
	}

	// update summary node data
	CRoleMembership::sumnode_t * sn = role_membership.get_summaryNode(flow_list[flow_id].remoteIP);
	if (sn != NULL) {
		map<int, uint64_t>::iterator sn_iter = sn->role_map.find(this->role_num);
		if (sn_iter != sn->role_map.end()) { // found the entry
			uint32_t sn_p = (sn_iter->second) & 0xffff;
			uint32_t sn_f = (sn_iter->second) >> 32;
			if (sn_f == 1) { // only one flow left => remove role from summary node
				role_membership.remove_role(flow_list[flow_id].remoteIP, this);
				if (debug) {
					cout << "removed link to summary node containing ip " << flow_list[flow_id].remoteIP << endl;
					this->rIP_set->erase(flow_list[flow_id].remoteIP);
				}
			} else { // other flows exists => decrement values
				if (debug) {
					cout << "updated link to summary node containing ip " << flow_list[flow_id].remoteIP << endl;
				}
				sn_iter->second = (((uint64_t)sn_f-1)<<32) + (sn_p-flow_list[flow_id].dPkts);
			}
		}
	}

	if (debug) {
		cout << "flows:\t\t" << this->flows << "\t=>\t" << flows << endl;
		cout << "packets:\t" << this->packets << "\t=>\t" << packets << endl;
		cout << "bytes:\t\t" << this->bytes << "\t=>\t" << bytes << endl;
		cout << "-------------------------" << endl;
	}
	// update values
	this->flows = flows;
	this->packets = packets;
	this->bytes = bytes;
}

/**
 * Find the role that corresponds to a role number. Only implemented in sub-classes.
 *
 * \param role_id Role number
 *
 * \return CRole::role_t* Pointer to the role(if found), NULL otherwise
 */
CRole::role_t* CRole::getRole(const int role_id) {
	assert(false);
	// only implemented by sub-classes
	return NULL;
}

/**
 *  Generate sub-roles used by desummarization. Only implemented in sub-classes.
 */
void CRole::create_sub_roles() {
	cerr << "ERROR: CRole::create_pseudo_roles() was called. This functionality only exists in CRole's subclasses." << endl;
	assert(false);
}

void CRole::create_pseudo_roles(role_t& role, CRoleMembership& membership) {
	if (role.role_num != 0) {
		set<role_pattern> sub_patterns = role.getSubPatterns();
		for (set<role_pattern>::const_iterator sub_pattern = sub_patterns.begin(); sub_pattern != sub_patterns.end(); ++sub_pattern) {
			// copy data from original role
			boost::shared_ptr<role_t> p_r(
			      new role_t(membership.get_next_role_num(role.role_type), role.prot, role.localPort, role.remotePort, role.remoteIP, role.flows, role.flowtype,
			            role.bytes, role.packets, role.role_type));
			(*p_r.get()).rIP_set->insert(role.rIP_set->begin(), role.rIP_set->end());
			(*p_r.get()).flow_set->insert(role.flow_set->begin(), role.flow_set->end());
			if (role.role_set) {
				(*p_r.get()).role_set->insert(role.role_set->begin(), role.role_set->end());
			}
			// do sub-role modifications
			(*p_r.get()).pattern = *sub_pattern;
			role.sub_role_set->insert(p_r);
		}
	}
}

/**
 * Print a remote host to cout. Used for debugging.
 */
void CRole::rhost_t::print_rhost() {
	cout << "rhost details:";
	cout << "\n\t remoteIP = " << remoteIP << " tcp = " << (uses_tcp ? "TRUE" : "FALSE") << " udp = " << (uses_udp ? "TRUE" : "FALSE");
	cout << ", flows = " << flows << ", packets = " << packets;
	cout << "\n\trole_map = ";
	for (map<int, uint64_t>::iterator it = role_map.begin(); it != role_map.end(); it++) {
		cout << " {" << it->first << ", " << it->second << "}";
	}
	cout << endl;
}

/**
 * Constructor for role_t
 *
 * \param role_num Role number, used for identification
 * \param prot Protocol number
 * \param localPort Local port
 * \param remotePort Remote port
 * \param remoteIP Remote IP address
 * \param flows number of flows in the role
 * \param flowtype Flowtype(contains information like flow direction)
 * \param bytes Total number of bytes
 */
CRole::role_t::role_t(int role_num, uint32_t prot, uint16_t localPort, uint16_t remotePort, IPv6_addr remoteIP, int flows, uint8_t flowtype, uint64_t bytes,
      uint32_t packets, char role_type) {
	this->role_num = role_num, this->prot = prot;
	this->localPort = localPort;
	this->remotePort = remotePort;
	this->remoteIP = remoteIP;
	this->flows = flows;
	this->flowtype = flowtype;
	this->bytes = bytes;
	this->packets = packets;
	this->role_type = role_type;
	this->rating = 0;

	rIP_set = new set<IPv6_addr>;
	flow_set = new set<int>;
	role_set = new set<int>;
	role_set_ = new set<role_t*>;
	sub_role_set = new set<boost::shared_ptr<CRole::role_t> >;
	switch (role_type) {
	case 's':
		pattern = server;
		break;
	case 'p':
		pattern = p2p;
		break;
	case 'm':
		pattern = multi_client;
		break;
	case 'c':
		pattern = client;
		break;
	case 'f':
		pattern = single_flow;
		break;
	default:
		cerr << "ERROR: unknown role type: " << (int)role_type << endl;
		break;
	}
}

/**
 * Generate all sub-patterns for a flow.
 *
 * \return set<role_pattern> Set containing all available sub-patterns
 */
set<role_pattern> CRole::role_t::getSubPatterns() {
	set<role_pattern> sub_patterns;
	for (role_pattern combination = min_pattern; combination < max_pattern; ++combination) {
		if ((!((~pattern) & combination))/*is pattern or sub pattern*/&& (pattern != combination)) {
			sub_patterns.insert(combination);
		}
	}
	return sub_patterns;
}

/**
 * Checks, if the specified partition is desummarized.
 *
 * \return bool True in case of a desummarized partition, false in all other cases
 */
bool CRole::role_t::partition_summarized(const graphlet_partition p) {
	return ((pattern & p) > 0);
}

/**
 * Find the used sub-role.
 *
 * \param part_desum_list
 * \param mnode_desum_list
 *
 * \return CRole::role_t* Used sub-role
 */
CRole::role_t* CRole::role_t::getUsedSubRole(const desummarizedRoles& part_desum_list, const desummarizedRoles& mnode_desum_list) {
	role_t* result = this;
	uint8_t current_level = getSummarizationLevel();
	for (set<boost::shared_ptr<CRole::role_t> >::const_iterator role_ptr = sub_role_set->begin(); role_ptr != sub_role_set->end(); role_ptr++) {
		CRole::role_t* role = ((*role_ptr).get());
		desummarizedRoles::const_iterator desumm_id;
		desumm_id = part_desum_list.find(role->role_num);
		if (desumm_id != part_desum_list.end()) { // found a matching role
			const uint8_t sum_lvl = role->getSummarizationLevel();
			if (sum_lvl < current_level) { // multiple desummarizations could be active. only the one with the most desummarized nodes is used.
				result = role;
				current_level = sum_lvl;
			}
		}
	}
	desummarizedRoles::const_iterator mnode_iter = mnode_desum_list.find(role_num);
	bool uses_multi_node = (mnode_iter != mnode_desum_list.end());

	if (uses_multi_node) {
		result = getUsedSubRole((result->pattern) & (~(remote_ip * summarized)), result);
	}
	return result;
}

/**
 * Find the active sub-role
 *
 * \param pattern Role pattern of the (parent-) role
 * \param current_sub_role Currently active sub_role
 *
 * \return CRole::role_t* Pointer to the active role
 */
CRole::role_t* CRole::role_t::getUsedSubRole(const role_pattern pattern, CRole::role_t* current_sub_role) {
	//cout << "desummarizing multi_node: " << util::graphletSummarizationToString(pattern) << endl;
	role_t* result = current_sub_role;
	for (set<boost::shared_ptr<CRole::role_t> >::const_iterator role_ptr = sub_role_set->begin(); role_ptr != sub_role_set->end(); role_ptr++) {
		CRole::role_t* role = ((*role_ptr).get());
		if (role->pattern == pattern) { // found a matching role
			result = role;
			break;
		}
	}
	return result;
}

uint32_t CRole::role_t::getSubRoleId(const graphlet_partition& partition_to_be_desummarized, const CRole::role_t& parent_role) {
	uint32_t expected_pattern = pattern & (~partition_to_be_desummarized);
	for (set<boost::shared_ptr<CRole::role_t> >::const_iterator role_ptr = parent_role.sub_role_set->begin(); role_ptr != parent_role.sub_role_set->end();
	      role_ptr++) {
		CRole::role_t* role = ((*role_ptr).get());
		if (role->pattern == expected_pattern) {
			//parent_role.print_role();
			return role->role_num;
		}
	}
	assert(false);
	return 0;
}

/**
 * Count the number of summarized partitions.
 *
 * \return uint8_t The number of summarized partitions(between 0 and 3)
 */
uint8_t CRole::role_t::getSummarizationLevel() const {
	uint8_t level = 0;
	uint8_t tmp_pattern = pattern;
	for (unsigned int pos = 0; pos < 6; ++pos) {
		level += (tmp_pattern & summarized); // only 5 bits(==5 partitions) are used. the others are always 0.
		tmp_pattern = tmp_pattern >> 1;
	}assert(level <= 3);
	return level;
}

/**
 * Find the association between two partitions of a role.
 *
 * \param p1 First partition
 * \param p1 Second partition
 *
 * \return graphlet_partition_association The partition association
 */
graphlet_partition_association CRole::role_t::get_partition_association(const graphlet_partition p1, const graphlet_partition p2) {
	if ((pattern & p1) == 0) {
		if ((pattern & p2) == 0) {
			return gpa_1_1;
		}
		return gpa_1_n;
	}
	if ((pattern & p2) == 0) {
		return gpa_n_1;
	}
	return gpa_n_n;
}

/**
 * Destructor
 */
CRole::role_t::~role_t() {
	delete rIP_set;
	delete flow_set;
	delete role_set;
	delete sub_role_set;
	delete role_set_;
}

/**
 * Print a role to cout. Used for debugging.
 */
void CRole::role_t::print_role() const {
	cout << "************************\n";
	cout << "role details:\n\ttype = " << role_type << ", num = " << role_num << ", prot = " << util::ipV6ProtocolToString(prot) << ", localPort = "
	      << localPort;
	string buf;
	cout << ", remotePort = " << remotePort << ", remoteIP = " << remoteIP << ", flows = " << flows;
	cout << ", flowtype = " << util::print_flowtype(flowtype) << ", bytes = " << bytes << ", packets = " << packets;
	cout << ", pattern: " << util::graphletSummarizationToString(pattern);
	cout << "\n\trIP_set =";
	int cnt = 0;
	for (set<IPv6_addr>::iterator it = rIP_set->begin(); it != rIP_set->end(); it++) {
		cout << " " << *it;
		cnt++;
	}
	if (cnt == 0)
		cout << " <empty>";
	cout << "  (found " << cnt << " remote IPs)";
	cout << "\n\trole_set = ";
	cnt = 0;
	for (set<int>::iterator it = role_set->begin(); it != role_set->end(); it++) {
		cout << " " << (*it);
		cnt++;
	}
	if (cnt == 0)
		cout << " <empty>";
	cout << "  (found " << cnt << " roles)";
	cout << endl;
	cout << "************************\n";
}

//********************************************************************************

/**
 * Constructor for CRoleMembership
 */
CRoleMembership::CRoleMembership() {
	hm_remote_IP = new CRole::remoteIpHashMap();
	role_num = 2;
	role_type.push_back('n');
	role_type.push_back('n');
	hm_multiSummaryNode = new multiSummaryNodeHashMap();
	hm_remote_IP2 = new remoteIpHashMap2();
	multisummary_role_num = -1;
}

/**
 * Destructor
 */
CRoleMembership::~CRoleMembership() {
	for (CRole::remoteIpHashMap::iterator it = hm_remote_IP->begin(); it != hm_remote_IP->end(); it++) {
		delete it->second;
	}
	delete hm_remote_IP;
	delete hm_remote_IP2; // Contains references to elements stored by hm_multiSummaryNode
	for (CRoleMembership::multiSummaryNodeHashMap::iterator it = hm_multiSummaryNode->begin(); it != hm_multiSummaryNode->end(); it++) {
		delete it->second;
	}
	delete hm_multiSummaryNode;
}

/**
 *	Get next free role number.
 *
 *	If a singleton of this class is used then this function delivers
 *	unique role numbers.
 *
 *	\param	role_type_code Single character code for role (c: client, s:server,
 *									m: multiclient, p:p2p, f:single flow)
 *	\return Next free role number (gets reserved upon call of this function)
 */
int CRoleMembership::get_next_role_num(char role_type_code) {
	int next_role_num = role_num;
	role_type.push_back(role_type_code);
	role_num++;
	return next_role_num;
}

/**
 *	Add a remote host to list and register a role for it.
 *
 *	Role number 0 designates that there is a single flow having
 *	this remoteIP. We store this special role number to handle
 *	the situation in which this remoteIP is also involved in one
 *	or more roles.
 *
 *	\param	remoteIP	IP address of remote host
 *	\param	role_num		Number of role to be registered (o for none)
 * \param 	flows			Number of flows exchanged with this host
 * \param 	packets		Number of packets exchanged with this host
 *
 *	return	Count of role memberships (including new one)
 */
int CRoleMembership::add_remote_host(IPv6_addr remoteIP, int role_num, int flows, int packets) {
	CRole::remoteIpHashKey rmkey(remoteIP);
	CRole::remoteIpHashMap::iterator it = hm_remote_IP->find(rmkey);
	struct CRole::rhost_t * el;
	if (it == hm_remote_IP->end()) {
		el = new CRole::rhost_t(remoteIP, flows, packets);
		/*
		 el = new CRole::rhost_t();
		 el->remoteIP = remoteIP;
		 el->flows = flows;
		 el->packets = packets;
		 */
		(*hm_remote_IP)[rmkey] = el;
	} else {
		el = it->second;
		el->flows += flows;
		el->packets += packets;
	}

	if (role_num != 0) {
		map<int, uint64_t>::iterator it2 = el->role_map.find(role_num);
		uint64_t entry = ((uint64_t) flows << 32) + packets;
		if (it2 == el->role_map.end()) {
			// Make initial entry for this role
			el->role_map.insert(pair<int, uint64_t>(role_num, entry));
		} else {
			// Update existing entry
			it2->second += entry;
		}
	}
	return el->role_map.size();
}

/**
 *	Add single flow to a remote host.
 *	By doing this any singular flows involving this remote host are registered.
 *	Note: use this function when all role summarization is completed and only single
 *	flows remain without any role membership.
 *	These flows get assigned a virtual role number out of the pool of unassigned
 *	role numbers.
 *
 *	\param	remoteIP	IP address of remote host
 * \param 	packets		Number of packets exchanged with this host
 *
 *	\return	Assigned role number
 */
int CRoleMembership::add_single_flow(IPv6_addr remoteIP, int packets) {
	CRole::remoteIpHashKey rmkey(remoteIP);
	CRole::remoteIpHashMap::iterator it = hm_remote_IP->find(rmkey);
	if (it == hm_remote_IP->end()) {
		cerr << "\nERROR in CRoleMembership::add_single_flow(): remoteIP not found.\n\n";
		return 0;
	} else {
		struct CRole::rhost_t * el = it->second;
		int role_num = get_next_role_num('f');
		uint64_t entry = ((uint64_t) 1 << 32) + packets;
		el->role_map.insert(pair<int, uint64_t>(role_num, entry)); // Use next unassigned role number
		return role_num;
	}
}

/**
 *	Remove a stale role number from role set of a particular remote host.
 *
 *	\param	remoteIP	IP address of remote host
 *	\param	role		Role to be removed from remoteIP
 */
void CRoleMembership::remove_role(IPv6_addr remoteIP, CRole::role_t * role) {
	CRole::remoteIpHashKey rmkey(remoteIP);
	CRole::remoteIpHashMap::iterator it = hm_remote_IP->find(rmkey);
	if (it == hm_remote_IP->end()) {
		cerr << "\nERROR in CRoleMembership::remove_role(): remoteIP not found.\n\n";
		return;
	} else {
		struct CRole::rhost_t * el = it->second;
		el->role_map.erase(role->role_num);
		role_type.at(role->role_num) = 'n';
	}
}

/**
 *	Build a list of summary nodes connected to more than one role
 *	(single role summary nodes are already defined as part of their role)
 */
void CRoleMembership::fill_summaryNodeList() {
	if (multisummary_role_num != -1) {
		cerr << "ERROR: multiple call to fill_summaryNodeList()\n\n";
		return;
	}
	// Identify all role combinations associated with remoteIPs and
	// fill a list with a summary node for each role combination found
	bool role_info_flag = false;
	IPv6_addr old_remoteIP = IPv6_addr();
	CRole::remoteIpHashMap::iterator it;
	for (it = hm_remote_IP->begin(); it != hm_remote_IP->end(); it++) {
		CRole::rhost_t * el = it->second;

		// Build key from role set (max set size = 8)
		int k = 0;
		boost::array<uint16_t, 8> setarr = { { 0 } }; // Missing initialization values use zero
		map<int, uint64_t>::iterator it2;
		for (it2 = el->role_map.begin(); it2 != el->role_map.end(); it2++) {
			if (k < 8) {
				setarr[k] = (int16_t) it2->first; // Up to max. 8 role numbers
			} else {
				if (el->remoteIP != old_remoteIP) {
					old_remoteIP = el->remoteIP;
					if (!role_info_flag) {
						role_info_flag = true;
						cerr << "INFO: more than 8 roles in role_set for remote IP = ";
					}
					cerr << "  " << el->remoteIP;
				}
			}
			k++;
		}
		if (k == 0) {
			cerr << "\nERROR in fill_summaryNodeList(): encountered remote IP without role membership.\n\n";
			el->print_rhost();
			exit(1);
		}

		// Change: create summary node for all remote IPs: during graph creation we decide
		// if a summary node has to be draw or if it is a pseudo-summary containing 1 host only

		// if (k <= 1) continue; // Do not add remote hosts involved in just 1 role

		CHashKey8 myKey(setarr);
		multiSummaryNodeHashMap::iterator it3;
		sumnode_t * sn = NULL;
		it3 = hm_multiSummaryNode->find(myKey);
		if (it3 == hm_multiSummaryNode->end()) {
			// Multisummary node does not yet exist: add it
			sn = new sumnode_t();
			sn->role_num = multisummary_role_num;
			//cerr<<"---"<<multisummary_role_num<<endl;
			sn->clients = 1;
			sn->firstRemoteIP = el->remoteIP;

			// Go through role list of this r->IP and update/insert role with its total flows
			for (map<int, uint64_t>::iterator it4 = el->role_map.begin(); it4 != el->role_map.end(); it4++) {
				map<int, uint64_t>::iterator it5 = sn->role_map.find(it4->first);
				if (it5 == sn->role_map.end()) {
					// Add role to map
					sn->role_map.insert(pair<int, uint64_t>(it4->first, it4->second));
				} else {
					// Update role (i.e. # flows)
					it5->second += it4->second;
				}
			}

			multisummary_role_num--;
			(*hm_multiSummaryNode)[myKey] = sn;
		} else {
			// Multisummary node exists: update it
			sn = it3->second;
			sn->clients++;
			// Go through role list of this r->IP and update/insert role with its total flows
			for (map<int, uint64_t>::iterator it4 = el->role_map.begin(); it4 != el->role_map.end(); it4++) {
				map<int, uint64_t>::iterator it5 = sn->role_map.find(it4->first);
				if (it5 == sn->role_map.end()) {
					// Add role to map
					sn->role_map.insert(pair<int, uint64_t>(it4->first, it4->second));
				} else {
					// Update role (i.e. # flows)
					it5->second += it4->second;
				}
			}
		}
		// Add this remoteIP to IP-to-summayrNode list
		remoteIpHashKey2 myKey2((el->remoteIP));
		(*hm_remote_IP2)[myKey2] = sn;
	}
	if (role_info_flag)
		cerr << "\n\n";
}

/**
 *	Get multi-summary node containing this IP
 *
 *	\param	remoteIP	IP address of remote IP searched for
 *	\return	Summary node object or NULL (if no such node exists)
 */
struct CRoleMembership::sumnode_t * CRoleMembership::get_summaryNode(IPv6_addr remoteIP) {
	/*
	 cout<<"summary_nodes: #"<<hm_remote_IP2->size()<<endl;
	 for (remoteIpHashMap2::iterator it = hm_remote_IP2->begin(); it != hm_remote_IP2->end(); ++it) {
	 cout<<"hm_remote_IP2[key]: "<<(it->first).printkey()<<endl;
	 cout<<"hm_remote_IP2[value]: "<<(it->second)<<endl;
	 }
	 */
	remoteIpHashKey2 myKey2(remoteIP);
	remoteIpHashMap2::iterator it;
	it = hm_remote_IP2->find(myKey2);
	if (it == hm_remote_IP2->end()) {
		return NULL;
	} else {
		return it->second;
	}
}

/**
 *	Get all flows a remote host is involved
 *
 *	\param	remoteIP	IP address of remote IP searched for
 *	\return	Total flow count of this remote IP (0 if not found)
 */
int CRoleMembership::get_flowcount(IPv6_addr remoteIP) {
	CRole::remoteIpHashKey rmkey(remoteIP);
	CRole::remoteIpHashMap::iterator it = hm_remote_IP->find(rmkey);
	if (it == hm_remote_IP->end()) {
		cerr << "\nERROR in CRoleMembership::get_flows(): remoteIP not found.\n\n";
		return 0;
	} else {
		struct CRole::rhost_t * el = it->second;
		return el->flows;
	}
}

/**
 *	Get all flows & packets for a particular role and remote IP address.
 *
 *	\param	remoteIP 	IP address of remote host for which to look up flows/packet counts on role_num
 *	\param	role_num		Number of role for which flows are asked for
 *	\param	packets		Count of packets
 *	\return	count of flows
 */
int CRoleMembership::get_role_flowpacket_count(IPv6_addr remoteIP, int role_num, int & packets) {
	CRole::remoteIpHashKey rmkey(remoteIP);
	CRole::remoteIpHashMap::iterator it = hm_remote_IP->find(rmkey);
	if (it == hm_remote_IP->end()) {
		cerr << "\nERROR in CRoleMembership::get_flows(): remoteIP not found.\n\n";
		cerr << "\tremote IP = " << remoteIP << "\n\trole num = " << role_num << "\n\n";
		packets = 0;
		return 0;
	} else {
		struct CRole::rhost_t * el = it->second;

		std::map<int, uint64_t>::iterator it2 = el->role_map.find(role_num);
		if (it2 == el->role_map.end()) {
			cerr << "ERROR: get_role_flowpacket_count() cannot find role for IP\n";
			cerr << "\tremote IP = " << remoteIP << "\n\trole num = " << role_num << "\n";
			el->print_rhost();
			packets = 0;
			return 0;
		} else {
			packets = (int) (it2->second & 0xffffffff);
			return (int) (it2->second >> 32);
		}
	}
}

/**
 *	Get all flows & packets for a particular role a summary node is involved in.
 *
 *	\param	role_num		Number of role for which flows are asked for
 *	\param	packets		Count of packets
 *	\return	count of flows
 */
int CRoleMembership::sumnode_t::get_flowpacket_count(int role_num, int & packets) {
	map<int, uint64_t>::iterator it = role_map.find(role_num);
	if (it != role_map.end()) {
		packets = (int) (it->second & 0xffffffff);
		return (int) (it->second >> 32);
	} else {
		packets = 0;
		return 0;
	}
}

/**
 *	Print all remote IP addresses that are involved in more than one role.
 */
void CRoleMembership::print_multi_members() {
	CRole::remoteIpHashMap::iterator it;
	for (it = hm_remote_IP->begin(); it != hm_remote_IP->end(); it++) {
		struct CRole::rhost_t * el = it->second;
		if (el->role_map.size() > 1) {
			cout << el->remoteIP << " :";
			map<int, uint64_t>::iterator it2;
			for (it2 = el->role_map.begin(); it2 != el->role_map.end(); it2++) {
				int role_num = it2->first;
				int flows = it2->second;
				cout << " " << role_num << role_type.at(role_num) << "(" << flows << ")";
			}
			cout << endl;
		}
	}
}

/**
 * Print the number of multi summary-nodes to cout.
 */
void CRoleMembership::print_multisummary_rolecount() {
	cout << "CRoleMembership::multisummary role count = " << -1 - multisummary_role_num << endl;
}

//********************************************************************************

/**
 * Constructor for CClientRole
 *
 * \param flow_list Sub-Flowlist required to access flows of the current graphlet
 * \param prefs User defined settings
 */
CClientRole::CClientRole(Subflowlist flowlist, const prefs_t & prefs) :
		CRole(flowlist, prefs) {
	hm_client_role = new cltRoleHashMap();
	hm_multiclient_role = new cltRoleHashMap();
}

/**
 * Destructor
 */
CClientRole::~CClientRole() {
	for (CClientRole::cltRoleHashMap::iterator it = hm_client_role->begin(); it != hm_client_role->end(); it++) {
		role_t * role = it->second;
		delete role;
	}
	delete hm_client_role;

	for (CClientRole::cltRoleHashMap::iterator it = hm_multiclient_role->begin(); it != hm_multiclient_role->end(); it++) {
		role_t * role = it->second;
		delete role;
	}
	delete hm_multiclient_role;
}

/**
 * Find the role that corresponds to a role number.
 *
 * \param role_id Role number
 *
 * \return CRole::role_t* Pointer to the role(if found), NULL otherwise
 */
CRole::role_t* CClientRole::getRole(const int role_id) {
	// loop for normal client roles
	for (cltRoleHashMap::iterator it = hm_client_role->begin(); it != hm_client_role->end(); it++) {
		if ((it->second)->role_num == role_id) {
			return it->second;
		}
	}
	// loop for multi-client roles
	for (cltRoleHashMap::iterator it = hm_multiclient_role->begin(); it != hm_multiclient_role->end(); it++) {
		if ((it->second)->role_num == role_id) { // skip invalid roles
			return it->second;
		}
	}
	return NULL; // role not found
}

/**
 *  Generate sub-roles used by desummarization.
 */
void CClientRole::create_sub_roles() {
	for (cltRoleHashMap::iterator it = hm_client_role->begin(); it != hm_client_role->end(); it++) {
		CRole::role_t * role = it->second;
		CRole::create_pseudo_roles(*role, *proleMembership);
	}

	for (cltRoleHashMap::iterator it = hm_multiclient_role->begin(); it != hm_multiclient_role->end(); it++) {
		CRole::role_t * role = it->second;
		CRole::create_pseudo_roles(*role, *proleMembership);
	}
}

/**
 * Register a CRoleMembership object
 *
 * \param roleMembership Role membership to be registered
 */
void CClientRole::register_rM(CRoleMembership & roleMembership) {
	proleMembership = &roleMembership;
}

/**
 * Add a candidate for client roles.
 *
 * \param i Flow index
 *
 * \return False, if candidate was rejected, true otherwise
 */
bool CClientRole::add_candidate(int i) {
	// Here we implement client role summarization step 1
	// --------------------------------------------------

	IPv6_addr remoteIP = flowlist[i].remoteIP;
	uint16_t remotePort = flowlist[i].remotePort;
	uint8_t prot = flowlist[i].prot;
	uint64_t bytes = flowlist[i].dOctets;
	uint32_t packets = flowlist[i].dPkts;
	uint8_t flowtype = flowlist[i].flowtype;

	//
	// Store candidate role
	// --------------------
	cltRoleHashKey mykey(remoteIP, prot, remotePort, flowtype);
	cltRoleHashMap::iterator citer = hm_client_role->find(mykey);
	int cur_role_num = 0;
	int cur_flows = 1;
	if (citer == hm_client_role->end()) {
		// Not found: add as a new role
		cur_role_num = flow_role[i] = proleMembership->get_next_role_num('c');
		role_t * role = new role_t(cur_role_num, prot, 0, remotePort, remoteIP, 1, flowtype, bytes, packets, 'c');
		role->rIP_set->insert(remoteIP);
		role->flow_set->insert(i);
		(*hm_client_role)[mykey] = role;
		role_count++;

	} else {
		// Found: update with data from new flow
		role_t * role = citer->second;
		cur_role_num = flow_role[i] = role->role_num;
		role->flow_set->insert(i);
		role->flows++;
		cur_flows = role->flows;
		role->bytes += bytes;
		role->packets += packets;
	}assert(packets > 0);
	proleMembership->add_remote_host(remoteIP, cur_role_num, 1, packets);
	return true; //FIXME speculative to remove compiler warning!
}

/**
 * Check the generated candidates and remove unqualified ones.
 */
void CClientRole::prune_candidates() {
	// Here we implement client role summarization step 2
	// --------------------------------------------------
	// Decide which flows will be summarized, and mark them accordingly.
	// Rule: summarize all candidate roles involving at least two biflows.

	set<int> croleSet;
	for (CClientRole::cltRoleHashMap::iterator it = hm_client_role->begin(); it != hm_client_role->end(); it++) {
		role_t * role = it->second;
		int num = role->role_num;
		if (debug3) {
			cout << num << " : " << role->rIP_set->size() << endl;
			cout.flush();
		}
		if (role->flows < client_threshold) {
			// Dismiss this role number
			set<IPv6_addr>::iterator it2; // Remove from role set of each remote host involved
			for (it2 = role->rIP_set->begin(); it2 != role->rIP_set->end(); it2++) {
				IPv6_addr remoteIP = *it2;
				proleMembership->remove_role(remoteIP, role);
			}
			// Mark role as invalid
			role->role_num = 0;
			set<int>::iterator it3;
			for (it3 = role->flow_set->begin(); it3 != role->flow_set->end(); it3++) {
				flow_role[*it3] = 0;
			}
			role_count--;
		} else {
			if (debug) {
				croleSet.insert(role->role_num);
			}
		}
	}
	if (debug && prefs.summarize_clt_roles) {
		cout << " ** Retaining " << role_count << " client roles (";
		for (set<int>::iterator it = croleSet.begin(); it != croleSet.end(); it++) {
			cout << " " << *it;
		}
		cout << " )\n";
	}
}

/**
 *	This function handles situations in which a local host is a multiple client
 *	of the same service (indicated by same service port number). If the count
 *	of such multiple client roles is high then an additional summarization
 *	can be useful (we loose the identity of remote servers but can compress
 *	a large subgraph).
 */
void CClientRole::check_multiclient(const vector<uint32_t> & flow_server_role, const CFlowFilter & filter, bool summ_srv_roles) {
	// Search for frequent roles having same remote service port
	// =========================================================
	// 1) Candidate generation
	// a) Check client roles
	int mrole_count = 0;
	for (CClientRole::cltRoleHashMap::iterator it = hm_client_role->begin(); it != hm_client_role->end(); it++) {
		role_t * crole = it->second;
		if (crole->role_num == 0)
			continue; // Skip pruned client roles (marked with role number 0)
		if (debug2) {
			cout << "mc-role: added client role: " << crole->role_num << " with " << crole->flows << " flows\n";
		}
		uint8_t prot = (uint8_t) crole->prot;
		cltRoleHashKey mykey(IPv6_addr(), prot, (crole->remotePort), (crole->flowtype));
		cltRoleHashMap::iterator citer = hm_multiclient_role->find(mykey);
		int cur_role_num = 0;
		if (citer == hm_multiclient_role->end()) {
			// Not found: add role as a new multiclient role
			cur_role_num = proleMembership->get_next_role_num('m');
			role_t * mrole = new role_t(cur_role_num, crole->prot, 0, crole->remotePort, crole->remoteIP, crole->flows, crole->flowtype, crole->bytes,
			      crole->packets, 'm');
			mrole->rIP_set->insert(crole->remoteIP); // Remember IPs of all remote servers
			mrole->role_set->insert(crole->role_num);
			mrole->role_set_->insert(crole);
			(*hm_multiclient_role)[mykey] = mrole;
			mrole_count++;
		} else {
			// Found: update with data from new role
			role_t * mrole = citer->second;
			mrole->flows += crole->flows; // Yields #connections
			mrole->bytes += crole->bytes;
			mrole->packets += crole->packets;
			mrole->rIP_set->insert(crole->remoteIP);
			mrole->role_set->insert(crole->role_num);
			mrole->role_set_->insert(crole);
			cur_role_num = mrole->role_num;
		}assert(crole->packets > 0);
		proleMembership->add_remote_host(crole->remoteIP, cur_role_num, crole->flows, crole->packets);
	}
	// b) Check single flows with remote Port < 1024 which are not yet members of client or server roles
	for (unsigned int j = 0; j < flowlist.size(); j++) {
		if (filter.filter_flow(j))
			continue;
		if (flow_role[j] == 0 /* && flowlist[j].remotePort<1024*/) {
			if (summ_srv_roles && flow_server_role[j] != 0)
				continue;
			if (debug2) {
				cout << "mc-role: added single flow: " << j << endl;
			}
			cltRoleHashKey mykey(IPv6_addr(), (flowlist[j].prot), (flowlist[j].remotePort), (flowlist[j].flowtype));
			cltRoleHashMap::iterator citer = hm_multiclient_role->find(mykey);
			int cur_role_num = 0;
			int cur_packets = 0;
			if (citer == hm_multiclient_role->end()) {
				// Not found: add role as a new multiclient role
				cur_role_num = proleMembership->get_next_role_num('m');
				role_t * mrole = new role_t(cur_role_num, flowlist[j].prot, 0, flowlist[j].remotePort, flowlist[j].remoteIP, 1, flowlist[j].flowtype,
				      flowlist[j].dOctets, flowlist[j].dOctets, 'm');
				mrole->rIP_set->insert(flowlist[j].remoteIP); // Remember IPs of all remote servers
				mrole->flow_set->insert(j);
				mrole->role_set->insert(0);
				(*hm_multiclient_role)[mykey] = mrole;
				mrole_count++;
			} else {
				// Found: update with data from new role
				role_t * mrole = citer->second;
				mrole->flows++;
				mrole->bytes += flowlist[j].dOctets;
				cur_packets = mrole->packets += flowlist[j].dPkts;
				mrole->rIP_set->insert(flowlist[j].remoteIP);
				mrole->role_set->insert(0);
				mrole->flow_set->insert(j);
				cur_role_num = mrole->role_num;
			}assert(flowlist[j].dPkts > 0);
			proleMembership->add_remote_host(flowlist[j].remoteIP, cur_role_num, 1, flowlist[j].dPkts);
		}
	}
	// 2) Pruning of unsuitable candidates
	for (CClientRole::cltRoleHashMap::iterator it = hm_multiclient_role->begin(); it != hm_multiclient_role->end(); it++) {
		role_t * mrole = it->second;
		if (mrole->role_set->size() > multi_client_threshold || mrole->flow_set->size() > multi_client_threshold) {
			// Accept client role and single flows of this mc-role
			if (debug2) {
				cout << "mc-role: " << mrole->role_num << " contains " << mrole->flow_set->size() << " single flows and ";
				cout << mrole->flows << " flows in total.\n";
			}
			cltRoleHashMap::iterator it3;
			// All client roles merged to a multiclient role will be dismissed
			set<int> croleSet;
			for (CClientRole::cltRoleHashMap::iterator it3 = hm_client_role->begin(); it3 != hm_client_role->end(); it3++) {
				role_t * crole = it3->second;
				set<int>::iterator it4;
				it4 = mrole->role_set->find(crole->role_num);
				if (it4 != mrole->role_set->end()) {
					// This client role is part of new multiclient role
					if (crole->role_num == 0)
						continue; // Skip pruned client roles (marked with role number 0)
					croleSet.insert(crole->role_num);
					if (debug2) {
						cout << "mc-summarize:dismiss client role: " << crole->role_num << endl;
					}
					for (set<IPv6_addr>::iterator it5 = crole->rIP_set->begin(); it5 != crole->rIP_set->end(); it5++) {
						proleMembership->remove_role(*it5, crole);
					}
					// Dismiss this role number
					crole->role_num = 0;
				}
			}
			if (debug) {
				cout << " ** mc-role " << mrole->role_num << " consumes client roles:";
				for (set<int>::iterator it = croleSet.begin(); it != croleSet.end(); it++) {
					cout << " " << *it;
				}
				cout << "\n";
			}
			// Now mark each flow contained in flow_set of multi-client role as a summarized client flow
			set<int>::iterator it2;
			for (it2 = mrole->flow_set->begin(); it2 != mrole->flow_set->end(); it2++) {
				if (debug2) {
					cout << "mc-summarize: marked flow: " << *it2 << " with role num: " << mrole->role_num << endl;
				}
				flow_role[*it2] = mrole->role_num;
			}
			if (debug2) {
				cout << "mc-role: " << mrole->role_num << " has " << mrole->flows << " flows\n";
			}
		} else {
			// Prune this multiclient-role: mark it as invalid
			// Remove role from all it's remote host objects
			for (set<IPv6_addr>::iterator it2 = mrole->rIP_set->begin(); it2 != mrole->rIP_set->end(); it2++) {
				proleMembership->remove_role(*it2, mrole);
			}
			mrole->role_num = 0;
			mrole_count--;
		}
	}
	if (debug && prefs.summarize_multclt_roles)
		cout << " ** Identified " << mrole_count << " multi-client roles.\n";
}

/**
 * Clean up flow_role vector and update values with multi-client role numbers
 */
void CClientRole::cleanConsumedClientRoles() {
	// update flow_role with multi-client data
	for (cltRoleHashMap::const_iterator mc_role_iter = hm_multiclient_role->begin(); mc_role_iter != hm_multiclient_role->end(); mc_role_iter++) {
		role_t* mc_role = mc_role_iter->second;
		if (mc_role->role_num == 0) { // ignore this role
			continue;
		}
		set<int> consumed_roles;
		consumed_roles.insert(mc_role->role_set->begin(), mc_role->role_set->end());
		for (uint32_t idx = 0; idx < flow_role.size(); idx++) {
			if (consumed_roles.find(flow_role[idx]) != consumed_roles.end() && flow_role[idx] != 0) { // flow is part of consumed role
				flow_role[idx] = mc_role->role_num;
			}
		}
	}
}

/**
 *	Returns next role from client role hash map.
 *	Note: if a returned role has role number 0 then it is
 *	marked as invalidated and should be ignored by caller.
 *	This function is set to first element at class instantiaton and therefore,
 *	can be used for a single list scan only per object life.
 *
 *	\return role
 */
CRole::role_t * CClientRole::get_next_role() {
	static cltRoleHashMap::iterator role_it;

	if (first) {
		role_it = hm_client_role->begin();
		first = false;
		if (role_it == hm_client_role->end()) {
			return NULL;
		} else {
			return role_it->second;
		}
	} else if (role_it == hm_client_role->end()) {
		return NULL;
	} else {
		role_it++;
		if (role_it == hm_client_role->end()) {
			return NULL;
		} else {
			return role_it->second;
		}
	}
}

/**
 *	Returns next role from multiclient role hash map.
 *	Note: if a returned role has role number 0 then it is
 *	marked as invalidated and should be ignored by caller.
 *	This function is set to first element at class instantiaton and therefore,
 *	can be used for a single list scan only.
 *
 *	\return role
 */
CRole::role_t * CClientRole::get_next_mrole() {
	static cltRoleHashMap::iterator mrole_it;

	if (first2) {
		mrole_it = hm_multiclient_role->begin();
		first2 = false;
		if (mrole_it == hm_multiclient_role->end()) {
			return NULL;
		} else {
			return mrole_it->second;
		}
	} else if (mrole_it == hm_multiclient_role->end()) {
		return NULL;
	} else {
		mrole_it++;
		if (mrole_it == hm_multiclient_role->end()) {
			return NULL;
		} else {
			return mrole_it->second;
		}
	}
}

//********************************************************************************

/**
 * Constructor for CServerRole
 *
 * \param flow_list Sub-Flowlist required to access flows of the current graphlet
 * \param prefs User defined settings
 */
CServerRole::CServerRole(Subflowlist flowlist, const prefs_t & prefs) :
		CRole(flowlist, prefs) {
	hm_server_role = new srvRoleHashMap();
}

/**
 * Destructor
 */
CServerRole::~CServerRole() {
	if (hm_server_role != NULL) {
		for (srvRoleHashMap::iterator it = hm_server_role->begin(); it != hm_server_role->end(); it++) {
			role_t * role = it->second;
			delete role;
		}
		delete hm_server_role;
	}
}

/**
 *  Generate sub-roles used by desummarization.
 */
void CServerRole::create_sub_roles() {
	for (srvRoleHashMap::iterator it = hm_server_role->begin(); it != hm_server_role->end(); it++) {
		CRole::role_t * role = it->second;
		CRole::create_pseudo_roles(*role, *proleMembership);
	}
}

/**
 * Find the role that corresponds to a role.
 *
 * \param role_id Role id
 *
 * \return CRole::role_t* Pointer to the role(if found), NULL otherwise
 */
CRole::role_t* CServerRole::getRole(const int role_id) {
	for (srvRoleHashMap::iterator it = hm_server_role->begin(); it != hm_server_role->end(); it++) {
		if ((it->second)->role_num == role_id) { // skip invalid roles
			return it->second;
		}
	}
	return NULL; // role not found
}

/**
 * Register a CRoleMembership object
 *
 * \param roleMembership Role membership to be registered
 */
void CServerRole::register_rM(CRoleMembership & roleMembership) {
	proleMembership = &roleMembership;
}

/**
 * Add a candidate flow for server roles.
 *
 * \param i Flowlist index
 *
 * \return bool False, if candidate was rejected
 */
bool CServerRole::add_candidate(int i) {
	// Here we implement server role summarization step 1
	// --------------------------------------------------
	//uint32_t localIP	= flowlist[i].localIP;
	uint16_t localPort = flowlist[i].localPort;
	IPv6_addr remoteIP = flowlist[i].remoteIP;
	uint8_t prot = flowlist[i].prot;
	uint64_t bytes = flowlist[i].dOctets;
	uint32_t packets = flowlist[i].dPkts;
	uint8_t flowtype = flowlist[i].flowtype;

	uint32_t ftype = (uint32_t) flowtype;
	srvRoleHashKey mykey(IPv6_addr(ftype), prot, localPort);
	srvRoleHashMap::iterator citer = hm_server_role->find(mykey);
	int cur_role_num = 0;
	int cur_flows = 1;
	// int cur_packets = 0;
	if (citer == hm_server_role->end()) {
		// Not found: add as a new role
		if (debug3) {
			if (remoteIP == IPv6_addr(ip)) {
				cout << "new: i=" << i << endl;
			}
		}
		cur_role_num = flow_role[i] = proleMembership->get_next_role_num('s');
		role_t * role = new role_t(cur_role_num, prot, localPort, 0, remoteIP, 1, flowtype, bytes, packets, 's');
		role->rIP_set->insert(remoteIP);
		role->flow_set->insert(i);
		(*hm_server_role)[mykey] = role;
		role_count++;
	} else {
		// Found: update role with data from new flow
		role_t * role = citer->second;
		if (debug3) {
			if (remoteIP == IPv6_addr(ip)) {
				cout << "found: i=" << i << endl;
			}
		}
		role->flow_set->insert(i);
		role->flows++;
		cur_flows += role->flows;
		role->bytes += bytes;
		role->packets += packets;
		role->rIP_set->insert(remoteIP);
		cur_role_num = flow_role[i] = role->role_num;

		if (debug3) {
			if (remoteIP == IPv6_addr(ip)) {
				cout << "added to role" << role->role_num << endl;
			}
		}
	}assert(packets > 0);
	proleMembership->add_remote_host(remoteIP, cur_role_num, 1, packets);
	return true; //FIXME speculative to remove compiler warning!
}

void CServerRole::prune_candidates() {
	// Here we implement server role summarization step 2
	// --------------------------------------------------

	// (B) Reject server roles with less than 2 flows
	set<int> sroleSet;
	for (srvRoleHashMap::iterator it = hm_server_role->begin(); it != hm_server_role->end(); it++) {
		role_t * role = it->second;
		// int num = role->role_num;
		if (role->flows < server_threshold) {
			// Dismiss this role number
			set<IPv6_addr>::iterator it2; // Remove from role set of each remote host involved
			for (it2 = role->rIP_set->begin(); it2 != role->rIP_set->end(); it2++) {
				IPv6_addr remoteIP = *it2;
				proleMembership->remove_role(remoteIP, role);
			}

			set<int>::iterator it3;
			for (it3 = role->flow_set->begin(); it3 != role->flow_set->end(); it3++) {
				flow_role[*it3] = 0;
			}
			role_count--;
			// Mark role as invalid
			role->role_num = 0;
		} else {
			if (debug)
				sroleSet.insert(role->role_num);
		}
	}
	if (debug && prefs.summarize_srv_roles) {
		cout << " ** Retaining " << role_count << " server roles (";
		for (set<int>::iterator it = sroleSet.begin(); it != sroleSet.end(); it++)
			cout << " " << *it;
		cout << " )\n";
	}
}

/**
 *	Returns next role from server role hash map.
 *	Note: if a returned role has role number 0 then it is
 *	marked as invalidated and should be ignored by caller.
 *	This function is set to first element at class instantiaton and therefore,
 *	can be used for a single list scan only per object life.
 *
 *	\return role
 */
CRole::role_t * CServerRole::get_next_role() {
	static srvRoleHashMap::iterator role_it;

	if (first) {
		role_it = hm_server_role->begin();
		first = false;
		if (role_it == hm_server_role->end()) {
			return NULL;
		} else {
			return role_it->second;
		}
	} else if (role_it == hm_server_role->end()) {
		return NULL;
	} else {
		role_it++;
		if (role_it == hm_server_role->end()) {
			return NULL;
		} else {
			return role_it->second;
		}
	}

	/*
	 if (first) {
	 it = hm_server_role->begin();
	 first = false;
	 } else {
	 it++;
	 }
	 if (it != hm_server_role->end()) {
	 return it->second;
	 } else {
	 return NULL;
	 }
	 */
}

//********************************************************************************

CP2pRole::CP2pRole(Subflowlist flowlist, const prefs_t & prefs) :
		CRole(flowlist, prefs) {
	hm_p2p_role = new CP2pRole::p2pRoleHashMap();
	hm_remote_IP_p2p = new CRole::remoteIpHashMap();
	cand_flow_num = 1;
}

CP2pRole::~CP2pRole() {
	if (hm_p2p_role != NULL) {
		for (CP2pRole::p2pRoleHashMap::iterator it = hm_p2p_role->begin(); it != hm_p2p_role->end(); it++) {
			role_t * role = it->second;
			delete role;
		}
		delete hm_p2p_role;
	}

	if (hm_remote_IP_p2p != NULL) {
		for (CRole::remoteIpHashMap::iterator it = hm_remote_IP_p2p->begin(); it != hm_remote_IP_p2p->end(); it++) {
			delete it->second;
		}
		delete hm_remote_IP_p2p;
	}
}

/**
 *  Generate sub-roles used by desummarization.
 */
void CP2pRole::create_sub_roles() {
	for (p2pRoleHashMap::iterator it = hm_p2p_role->begin(); it != hm_p2p_role->end(); it++) {
		CRole::role_t * role = it->second;
		CRole::create_pseudo_roles(*role, *proleMembership);
	}
}

/**
 * Find the role that corresponds to an id.
 *
 * \param role_id Role id
 *
 * \return CRole::role_t* Pointer to the role(if found), NULL otherwise
 */
CRole::role_t* CP2pRole::getRole(const int role_id) {
	for (p2pRoleHashMap::iterator it = hm_p2p_role->begin(); it != hm_p2p_role->end(); it++) {
		if ((it->second)->role_num == role_id) { // skip invalid roles
			return it->second;
		}
	}
	return NULL; // role not found
}

/**
 * Register a CRoleMembership object
 *
 * \param roleMembership Role membership to be registered
 */
void CP2pRole::register_rM(CRoleMembership & roleMembership) {
	proleMembership = &roleMembership;
}

/**
 *	Any not yet summarized tcp/udp flow is a candidate.
 *	Note: we asssume that client and server roles have been summarized before
 *	this function is called.
 *	Track protocol usage per involved remote host for later pruning.
 *
 *	\param	i	Flow index into flowlist (must be a not yet summarized flow)
 */

bool CP2pRole::add_candidate(int i) {
	// Check if protocol is tcp or udp and skip flow if not
	uint8_t prot = flowlist[i].prot;
	if (prot != IPPROTO_TCP && prot != IPPROTO_UDP
		) return false;
	// Add as a candidate flow
	p2p_candidate_flows.insert(i);

	// Remember per remote IP protocol usage
	IPv6_addr remoteIP = flowlist[i].remoteIP;
	CRole::remoteIpHashKey rmkey(remoteIP);
	CRole::remoteIpHashMap::iterator it = hm_remote_IP_p2p->find(rmkey);
	if (it == hm_remote_IP_p2p->end()) {
		// Not found: add to list
		struct rhost_t * el = new rhost_t();
		el->flows = 1;
		if (prot == IPPROTO_TCP) {
			el->uses_tcp = true;
			el->uses_udp = false;
		} else { // Must be udp as we have excluded any other protocol before
			el->uses_udp = true;
			el->uses_tcp = false;
		}
		el->remoteIP = remoteIP;
		(*hm_remote_IP_p2p)[rmkey] = el;
		if (debug3) {
			if (remoteIP == ip) {
				cout << "i=" << i << endl;
			}
		}
		cand_flow_num++;
	} else {
		// Found: this role will be dropped so there is no need to update anything else than flow count
		struct rhost_t * el = it->second;
		el->flows++;
		if (prot == IPPROTO_TCP) {
			el->uses_tcp = true;
		} else { // Must be udp as we have excluded any other protocol before
			el->uses_udp = true;
		}
	}
	return true;
}

/**
 * Prune peer to peer role candidates and invalidate roles that do not meet the criteria.
 *
 * \param clientRole Client roles
 * \param serverRole Server roles
 * \param filter Flow filter settings
 */
void CP2pRole::prune_candidates(CClientRole & clientRole, CServerRole & serverRole, CFlowFilter & filter) {
	// Use candidate flow list filled by add_candidate() calls.
	// (A) Check first which of these flows will be part of candidate roles.
	// (B) Then check which candidate roles to retain.

	// (A) We accept a flow if:
	//
	// (both ports are high (>1024)) OR (involved remote host uses udp and tcp simultaneously)
	//
	// Accepted flows are used to construct candidate p2p roles.
	//
	// Additional candidates are generated from client roles with a high service port (>1024)

	// prune flows
	set<int> flows_to_delete;
	bool erased = false; // wasted 5h for this
	for (set<int>::iterator it = p2p_candidate_flows.begin(); it != p2p_candidate_flows.end();) {
		erased = false;
		int k = *it;
		if (flowlist[k].localPort < p2p_port_threshold || flowlist[k].remotePort < p2p_port_threshold) {
			// Prune flow if one or both ports <1024 and rIP does not use tcp+udp
			// Check if remote host uses both tcp and udp
			CRole::remoteIpHashKey rmkey((flowlist[k].remoteIP));
			CRole::remoteIpHashMap::iterator it2 = hm_remote_IP_p2p->find(rmkey);
			if (it2 == hm_remote_IP_p2p->end()) {
				// Not found: error
				cerr << "ERROR in CP2pRole::prune_candidates(): remote host missing in hm_remote_IP_p2p\n\n";
			} else {
				struct rhost_t * el = it2->second;
				if (el->uses_tcp == false || el->uses_udp == false) {
					// Prune flow
					it++;
					p2p_candidate_flows.erase(k);
					erased = true;
				}
			}
		}
		if(!erased)
			it++;
	}

	// Create candidate p2p roles from candidate flows
	for (set<int>::iterator it = p2p_candidate_flows.begin(); it != p2p_candidate_flows.end(); it++) {
		int k = *it;
		// We derive separate p2p candidate roles per protocol and flowtype
//		uint32_t kval = ((uint32_t)(flowlist[k].prot)<<16) + (uint32_t)(flowlist[k].flowtype);
		CP2pRole::p2pRoleHashKey mykey(flowlist[k].prot, flowlist[k].flowtype);
		CP2pRole::p2pRoleHashMap::iterator citer = hm_p2p_role->find(mykey);
		int cur_role_num = 0;
		int cur_flows = 1;
		if (citer == hm_p2p_role->end()) {
			// Not found: add to list
			cur_role_num = flow_role[k] = proleMembership->get_next_role_num('p');
			role_t * role = new role_t(cur_role_num, flowlist[k].prot, 0, 0, flowlist[k].remoteIP, 1, flowlist[k].flowtype, flowlist[k].dOctets, flowlist[k].dPkts,
			      'p');
			role->rIP_set->insert(flowlist[k].remoteIP);
			role->flow_set->insert(k);
			(*hm_p2p_role)[mykey] = role;
			role_count++;
//			if (debug4 && cur_role_num==63546) { cout << __FILE__ << ":#" << __LINE__ <<":" << __FUNCTION__ << ": "; role->print_role(); }

		} else {
			// Found: aggregate counts
			role_t * role = citer->second;
			cur_role_num = flow_role[k] = role->role_num;
			role->flows++;
			cur_flows = role->flows;
			role->bytes += flowlist[k].dOctets;
			role->packets += flowlist[k].dPkts;
			role->rIP_set->insert(flowlist[k].remoteIP);
			role->flow_set->insert(k);
//			if (debug4 && cur_role_num==63546) { cout << __FILE__ << ":#" << __LINE__ <<":" << __FUNCTION__ << ": "; role->print_role(); }
		}assert(flowlist[k].dPkts > 0);
		proleMembership->add_remote_host(flowlist[k].remoteIP, cur_role_num, 1, flowlist[k].dPkts);
	}

	// Next, add client roles with high remote port number (>1024) as candidates
	for (CClientRole::cltRoleHashMap::iterator it = clientRole.get_hm_client_role()->begin(); it != clientRole.get_hm_client_role()->end(); it++) {
		CRole::role_t * crole = it->second;
		if (crole->remotePort > 1024 && crole->role_num != 0) { // Skip roles marked invalid
			CP2pRole::p2pRoleHashKey mykey(crole->prot, crole->flowtype);
			CP2pRole::p2pRoleHashMap::iterator citer = hm_p2p_role->find(mykey);
			int cur_role_num = 0;
			int cur_flows = 0;
			if (citer == hm_p2p_role->end()) {
				// Not found: add to list
				cur_role_num = proleMembership->get_next_role_num('p');
				role_t * role = new role_t(cur_role_num, crole->prot, 0, 0, crole->remoteIP, crole->flows, crole->flowtype, crole->bytes, crole->packets, 'p');
				role->rIP_set->insert(crole->remoteIP);
				role->role_set->insert(crole->role_num);
				(*hm_p2p_role)[mykey] = role;
				role_count++;
//				if (debug4 && cur_role_num==63546) { cout << __FILE__ << ":#" << __LINE__ <<":" << __FUNCTION__ << ": "; role->print_role(); }
			} else {
				// Found: aggregate counts
				role_t * role = citer->second;
				cur_role_num = role->role_num;
				role->flows += crole->flows;
				cur_flows = role->flows;
				role->bytes += crole->bytes;
				role->packets += crole->packets;
				role->rIP_set->insert(crole->remoteIP);
				role->role_set->insert(crole->role_num);
//				role->flow_set->insert(k);
//				if (debug4 && cur_role_num==63546) { cout << __FILE__ << ":#" << __LINE__ <<":" << __FUNCTION__ << ": "; role->print_role(); }
			}
			if (debug3) {
				cout << " ** P2P: added client candidate role: " << crole->role_num << endl;
			}assert(crole->packets > 0);
			proleMembership->add_remote_host(crole->remoteIP, cur_role_num, crole->flows, crole->packets);
		}
	}

	// Check which candidate roles to retain.
	// *************************************
	set<int> proleSet;
	// We prune all roles with a flow/role count below threshold
	for (CP2pRole::p2pRoleHashMap::iterator it = hm_p2p_role->begin(); it != hm_p2p_role->end(); it++) {
		role_t * p2prole = it->second;

		// Check if enough client roles are part of the p2p candidate role
		if (p2prole->role_set->size() < p2p_threshold) {
//			if (debug4 && p2prole->role_num==63546) { cout << __FILE__ << ":#" << __LINE__ << ": removing client roles from " << p2prole->role_num << "\n";  }
			// Remove client roles from p2p role
			for (CClientRole::cltRoleHashMap::iterator it3 = clientRole.get_hm_client_role()->begin(); it3 != clientRole.get_hm_client_role()->end(); it3++) {
				role_t * crole = it3->second;
				if (crole->role_num == 0)
					continue; // Skip deprecated entries
				set<int>::iterator it4;
				it4 = p2prole->role_set->find(crole->role_num);
				if (it4 != p2prole->role_set->end()) {
					// Remove
//					if (debug4 && p2prole->role_num==63546) { cout << "\tclient role = " << crole->role_num << endl;  }
					proleMembership->remove_role(crole->remoteIP, p2prole);
					p2prole->rIP_set->erase(crole->remoteIP); // For a client role there is only one remoteIP, namely the server side IP
					p2prole->role_set->erase(crole->role_num);
					// Subtract flow/byte/packet counts
					p2prole->flows -= crole->flows;
					p2prole->bytes -= crole->bytes;
					p2prole->packets -= crole->packets;
				}
			}
		} else { // Accept role
//			if (debug4 && p2prole->role_num==63546) { cout << __FILE__ << ":#" << __LINE__ << ": accepting client role " << p2prole->role_num << "\n";  }
		// Go through client role list to remove roles now being part of a p2p role
			if (debug)
				proleSet.insert(p2prole->role_num);
//			const unsigned int mc_threshold = 3;	// For now; make it configurable (later)
			continue; // Skip next check as we have already accepted candidate role
		}

		// Check if enough flows are part of the p2p candidate role
		if ((unsigned int) p2prole->flows < p2p_threshold) {
			// Drop this role
//			if (debug4 && p2prole->role_num==63546) { cout << __FILE__ << ":#" << __LINE__ << ": dropping role " << p2prole->role_num << "\n";  }
			for (unsigned int j = 0; j < flowlist.size(); j++) {
				if ((int)flow_role[j] == p2prole->role_num)
					flow_role[j] = 0;
			}
			set<IPv6_addr>::iterator it2; // Remove from role set each remote host involved
			for (it2 = p2prole->rIP_set->begin(); it2 != p2prole->rIP_set->end(); it2++) {
				IPv6_addr remoteIP = *it2;
				proleMembership->remove_role(remoteIP, p2prole);
			}
			// Mark role as invalid
			p2prole->role_num = 0;
			role_count--;
		} else {
			if (debug)
				proleSet.insert(p2prole->role_num);
		}
	}

	if (debug) {
		cout << " ** Retaining " << role_count << " p2p roles (";
		for (set<int>::iterator it = proleSet.begin(); it != proleSet.end(); it++) {
			cout << " " << *it;
		}
		cout << " )\n";
	}
}

/**
 * Clean up flow_role vector and update values with p2p role numbers
 *
 * \param clientRole Client roles
 */
void CP2pRole::cleanConsumedClientRoles(CClientRole& clientRole) {
	// Go through all client roles and invalidate each one contained in role_set of multiclient role
	for (CP2pRole::p2pRoleHashMap::iterator it = hm_p2p_role->begin(); it != hm_p2p_role->end(); it++) {
		role_t* p2prole = (*it).second;
		if (p2prole->role_num == 0) {
			continue;
		}
		for (CClientRole::cltRoleHashMap::iterator it3 = clientRole.get_hm_client_role()->begin(); it3 != clientRole.get_hm_client_role()->end(); it3++) {
			role_t * crole = it3->second;
			set<int>::iterator it4 = p2prole->role_set->find(crole->role_num);
			if (it4 != p2prole->role_set->end()) {
				// Mark this client role as invalid
				proleMembership->remove_role(crole->remoteIP, crole);
				crole->role_num = 0;
				p2prole->flow_set->insert(crole->flow_set->begin(), crole->flow_set->end());
				for (set<int>::iterator flow_iter = crole->flow_set->begin(); flow_iter != crole->flow_set->end(); flow_iter++) {
					clientRole.set_flow_role_value(*flow_iter, 0);
					flow_role[*flow_iter] = p2prole->role_num;
				}
			}
		}
	}
}

/**
 *	Returns next role from P2P role hash map.
 *	Note: if a returned role has role number 0 then it is
 *	marked as invalidated and should be ignored by caller.
 *	This function is set to first element at class instantiaton and therefore,
 *	can be used for a single list scan only per object life.
 *
 *	\return role
 */
CRole::role_t * CP2pRole::get_next_role() {
	static p2pRoleHashMap::iterator role_it;

	if (first) {
		role_it = hm_p2p_role->begin();
		first = false;
		if (role_it == hm_p2p_role->end()) {
			return NULL;
		} else {
			return role_it->second;
		}
	} else if (role_it == hm_p2p_role->end()) {
		return NULL;
	} else {
		role_it++;
		if (role_it == hm_p2p_role->end()) {
			return NULL;
		} else {
			return role_it->second;
		}
	}

	/*
	 if (first) {
	 it = hm_p2p_role->begin();
	 first = false;
	 } else {
	 it++;
	 }
	 if (it != hm_p2p_role->end()) {
	 return it->second;
	 } else {
	 return NULL;
	 }
	 */
}

