#ifndef GROLE_H_
#define GROLE_H_
/**
 *	\file grole.h
 *	\brief Classes for host role summarization.
 *
 *	A base class CRole is used to define specialized classes for the different role types.
 *	Supported roles:
 *	- client
 *	- server
 *	- p2p (1)
 */

#include <stdint.h>
#include <set>
#include <map>
#include <boost/shared_ptr.hpp>

#include "HashMapE.h"
#include "cflow.h"
#include "global.h"

/**
 *	\enum summarization_type
 *	\brief  Enumeration of summarization statuses.
 */
enum summarization_type {
	summarized = 0x1, desummarized = 0x0
};

/**
 *	\enum graphlet_partition
 *	\brief  Enumeration of available graphlet partitions.
 */
enum graphlet_partition {
	local_ip = 0x1, // 2⁰
	proto = 0x2, // 2¹
	local_port = 0x4, // 2²
	remote_port = 0x8, // 2³
	remote_ip = 0x10
// 2⁴
};

/**
 *	\enum graphlet_partition_association
 *	\brief  Enumeration of partition associacions.
 */
enum graphlet_partition_association {
	gpa_1_1, // ..o-o..
	gpa_1_n, // ..o-[]..
	gpa_n_1, // ..[]-o..
	gpa_n_n, // ..[]-[]..
	gpa_unknown
// no connection between partitions
};

/**
 *	\enum summarization_limits
 *	\brief  Enumeration of summarization limits.
 */
enum summarization_limits {
	max_pattern = 0 + (summarized * local_ip + summarized * proto + summarized * local_port + summarized * remote_port + summarized * remote_ip), // (2⁵)-1
	min_pattern = 0 + (desummarized * local_ip + desummarized * proto + desummarized * local_port + desummarized * remote_port + desummarized * remote_ip)// 0
};

/**
 *	\enum role_type
 *	\brief  Enumeration of supported in role types.
 */
enum role_type {
	server = 0 + (summarized * remote_port + summarized * remote_ip), // o-o-o-[]-[]
	client = 0 + (summarized * local_port), // o-o-[]-o-o
	multi_client = 0 + (summarized * local_port + summarized * remote_ip), // o-o-[]-o-[]
	p2p = 0 + (summarized * local_port + summarized * remote_port + summarized * remote_ip), // o-o-[]-[]-[]
	single_flow = min_pattern
// o-o-o-o-o
};

/**
 *	\enum role_flow_threshold
 *	\brief  Minimum number of flows a role type must contain
 */
enum role_flow_threshold {
	flow_threshold_client = 2,
	flow_threshold_multi_client = 3,
	flow_threshold_server = 2,
	flow_threshold_p2p = 4
};

/**
 *	\typedef role_pattern
 *	\brief Number used to store role patterns
 */
typedef uint8_t role_pattern;

/**
 *	\typedef roleNumber
 *	\brief Number of a generated role. Used to identify the clicked node during drill-downs.
 */
typedef uint32_t roleNumber;

/**
 *	\typedef desummarizedRoles
 *	\brief Container for role numbers, used to store the ids of all desummarized roles.
 */
typedef std::set<roleNumber> desummarizedRoles;

/**
 *	\class	CRole
 *	\brief	Base class for role identification.
 *
 *	Defines common tasks (applicable to all role types):
 *	- create/delete hash map
 *	- role counter
 *	- create/delete flow_role array (contains role_num for each flow, 0 for no-role membership, 1 for ...)
 *
 *	In contrast: specialized tasks and thus implemented separately for each role:
 *	- hash map type
 *	- hash key type
 */

class CRoleMembership;
class CRole {
	protected:
		// Imports
		Subflowlist flowlist;
		const prefs_t & prefs;

		// List describing (potential) role memberships:
		// - Each role carries a per role-type number
		// - Role number 0 designates a flow with no role membership
		std::vector<uint32_t> flow_role; // Array containing assigned role numbers for each flow (0 for none)
		// (positions are aligned with flowlist)
		int role_count;
		// Initialization flags: must be kept here as initialization is required per class instantiation
		// (a static local variable cannot do the job as it is initialized at program start only)
		bool first; // Used by get_next_role()
		bool first2; // Used by get_next_mrole()

		static const uint32_t flow_rate_threshold = 1024 * 1024;

	public:
		// For tracking of remote host activities
		struct rhost_t {
				IPv6_addr remoteIP;
				std::map<int, uint64_t> role_map; // key: role# rIP is a member of; entry: (#flow<<32) + #packets for this rIP
				bool uses_tcp;
				bool uses_udp;
				int flows;
				int packets;

				rhost_t();
				rhost_t(IPv6_addr remoteIP, int flows, int packets);
				void print_rhost();
		};

		// For tracking of roles
		// (depending on role not all fields are used)
		struct role_t {
				int role_num;
				uint32_t prot;
				uint16_t localPort;
				uint16_t remotePort;
				IPv6_addr remoteIP;
				uint32_t flows;
				uint8_t flowtype;
				uint64_t bytes;
				uint32_t packets;
				char role_type; // Type of role: n = none, c = client, s = server, p = p2p, m = multiclient, f = single flow
				role_pattern pattern;
				float rating; // value between 0 and 1, containing a flow rating used for flow conflict resolution

				std::set<IPv6_addr> * rIP_set; // For remoteIPs summarized in summary node
				std::set<int> * flow_set; // All flows associated with this role
				std::set<int> * role_set; // All client roles associated with this multiclient role // TODO: remove? role_set_ provides access to the same information
				std::set<role_t *> * role_set_;
				std::set<boost::shared_ptr<CRole::role_t> > * sub_role_set;

				role_t(int role_num, uint32_t prot, uint16_t localPort, uint16_t remotePort, IPv6_addr remoteIP, int flows, uint8_t flowtype, uint64_t bytes,
				      uint32_t packets, char role_type);
				virtual ~role_t();

				void print_role() const;
				std::set<role_pattern> getSubPatterns();
				bool partition_summarized(const graphlet_partition p);
				graphlet_partition_association get_partition_association(const graphlet_partition p1, const graphlet_partition p2);
				role_t * getUsedSubRole(const desummarizedRoles & part_desum_list, const desummarizedRoles & mnode_desum_list);
				role_t * getUsedSubRole(const role_pattern pattern, CRole::role_t* current_sub_role);
				uint32_t getSubRoleId(const graphlet_partition& partition_to_be_desummarized, const role_t& parent_role);
				uint8_t getSummarizationLevel() const;
				bool addFlow(const int flow_id);
				bool removeFlow(const int flow_id, const Subflowlist& flow_list, CRoleMembership& role_membership);
				void recalculateSummaries(const Subflowlist& flow_list, const int flow_id, CRoleMembership& role_membership);
		};

		typedef HashKeyIPv6 remoteIpHashKey;

		// key = remoteIP
		// data = remote host object reference
		typedef hash_map<HashKeyIPv6, rhost_t *, HashFunction<HashKeyIPv6> , HashFunction<HashKeyIPv6> > remoteIpHashMap;

	public:
		CRole(Subflowlist flowlist, const prefs_t & prefs);
		virtual ~CRole();
		virtual bool add_candidate(int flow_num) {
			return false;
		}
		virtual void prune_candidates() {
		}
		virtual CRole::role_t * get_next_role() {
			return NULL;
		}
		const vector<uint32_t> & get_flow_role() {
			return flow_role;
		}
		void set_flow_role_value(const uint32_t index, const uint32_t value) {
			flow_role[index] = value;
		}
		int get_role_count() {
			return role_count;
		}
		virtual void create_sub_roles();
		virtual void rate_roles(const CFlowList& full_flowlist);
		virtual float getRating(const int role_id);
		virtual role_t* getRole(const int role_id);

	protected:
		virtual void create_pseudo_roles(role_t & role, CRoleMembership & membership);

	private:
		virtual void rate_role(role_t& role, const CFlowList& full_flowlist, const Subflowlist& sub_flowlist);
};

//********************************************************************************

/**
 *	\class CRoleMembership
 *	\brief Manage role memberships of remote hosts.
 *
 *	The majority of remote hosts (identified by their IP address) are a member
 *	of just a single role. However, there may be a considerable number of remote
 *	hosts which are involved in more than one role (eg. p2p applications,
 *	servers offering multiple services). Such remote hosts are assigned and counted
 *	by special summary nodes that are linked to more than one role.
 *	As there may be many differing sets of role memberships we have to maintain
 *	an appropriate number of such summary nodes whereas each represents a
 *   particular set of role memberships {role1, role2, .. } that are shared
 *	among all remote hosts associated with this summary node.
 *
 *	Required operations are:
 *	- add a remote host to list
 *	- get count of roles a remote host (remoteIP) is involved
 *	- update list of summary nodes in case a new membership set {role1, role2, .. }
 *	  occurs
 *	- add a remote host to a summary node
 */
class CRoleMembership {
	public:
		struct sumnode_t {
				int role_num;
				int clients;
				IPv6_addr firstRemoteIP; // IP of first host added
				std::map<int, uint64_t> role_map; // key: role# rIP is a member of; entry: (#flow<<32) + #packets for this rIP
				int get_flowpacket_count(int role_num, int & packets);
		};
		typedef CHashKey8 multiSummaryNodeKey; // Hash map: key=set of role numbers (up to 8)
		// key = set of role numbers (up to 8)
		// data = ref to summary node object
		typedef hash_map<CHashKey8, sumnode_t *, HashFunction<CHashKey8> , HashFunction<CHashKey8> > multiSummaryNodeHashMap;
	private:
		CRole::remoteIpHashMap * hm_remote_IP; // Hash map: key=remoteIP, entry=role set
		int role_num;
		std::vector<char> role_type; // For each role number store its role type
		// (n: none, c: client, s: server, p:p2p, m:multiclient, f: single flow)

		multiSummaryNodeHashMap * hm_multiSummaryNode;
		int multisummary_role_num;

		typedef HashKeyIPv6 remoteIpHashKey2;

		// key = remoteIP
		// data = remote host object reference
		typedef hash_map<HashKeyIPv6, sumnode_t *, HashFunction<HashKeyIPv6> , HashFunction<HashKeyIPv6> > remoteIpHashMap2;

		remoteIpHashMap2 * hm_remote_IP2;

	public:
		CRoleMembership();
		~CRoleMembership();

		int get_next_role_num(char role_type_code);
		int get_role_num() {
			return role_num;
		}
		int add_remote_host(IPv6_addr remoteIP, int role_num, int flows, int packets);
		int add_single_flow(IPv6_addr remoteIP, int packets);
		void remove_role(IPv6_addr remoteIP, CRole::role_t * role);
		void fill_summaryNodeList();
		struct sumnode_t * get_summaryNode(IPv6_addr remoteIP);
		int get_flowcount(IPv6_addr remoteIP);
		int get_role_flowpacket_count(IPv6_addr remoteIP, int role_num, int & packets);
		void print_multi_members();
		void print_multisummary_rolecount();
		multiSummaryNodeHashMap* get_hm_multiSummaryNode() {
			return hm_multiSummaryNode;
		}
		;
};

//********************************************************************************

/**
 *	\class	CClientRole
 *	\brief	Derived class for client role identification.
 */
class CClientRole: public CRole {
	public:
		typedef HashKeyIPv6_4T cltRoleHashKey; // key = 4-tuple {IP, prot, port, flowtype}

		// key = { remoteIP, prot, remotePort, flowtype }
		// data = role object reference
		typedef hash_map<HashKeyIPv6_4T, role_t *, HashFunction<HashKeyIPv6_4T> , HashFunction<HashKeyIPv6_4T> > cltRoleHashMap;

	private:
		cltRoleHashMap * hm_client_role;
		CRoleMembership * proleMembership;
		cltRoleHashMap * hm_multiclient_role;
		virtual void rate_role(role_t& role, const CFlowList& full_flowlist, const Subflowlist& sub_flowlist);
		static const uint32_t client_threshold = flow_threshold_client;
		static const uint32_t multi_client_threshold = flow_threshold_multi_client;
	public:
		CClientRole(Subflowlist flowlist, const prefs_t & prefs);
		virtual ~CClientRole();

		void register_rM(CRoleMembership & roleMembership);

		bool add_candidate(int flow_num);
		void prune_candidates();
		void check_multiclient(const vector<uint32_t> & flow_server_role, const CFlowFilter & filter, bool summ_srv_roles);
		CRole::role_t * get_next_mrole();
		CRole::role_t * get_next_role();
		cltRoleHashMap * get_hm_client_role() {
			return hm_client_role;
		}
		cltRoleHashMap * get_hm_multi_client_role() {
			return hm_multiclient_role;
		}
		virtual void create_sub_roles();
		virtual void rate_roles(const CFlowList& full_flowlist);
		virtual float getRating(const int role_id);
		virtual role_t* getRole(const int role_id);
		void cleanConsumedClientRoles();
};

//********************************************************************************

/**
 *	\class	CServerRole
 *	\brief	Derived class for server role identification.
 */
class CServerRole: public CRole {
	public:
		typedef HashKeyIPv6_3T srvRoleHashKey; // key = 3-tuple {IP, prot, port}

		// key = { flowtype, prot, localPort }
		// data = role object reference
		typedef hash_map<HashKeyIPv6_3T, role_t *, HashFunction<HashKeyIPv6_3T> , HashFunction<HashKeyIPv6_3T> > srvRoleHashMap;

	private:
		srvRoleHashMap * hm_server_role;
		CRoleMembership * proleMembership;
		virtual void rate_role(role_t& role, const CFlowList& full_flowlist, const Subflowlist& sub_flowlist);
		static const uint32_t server_threshold = flow_threshold_server;
	public:
		CServerRole(Subflowlist flowlist, const prefs_t & prefs);
		virtual ~CServerRole();
		void register_rM(CRoleMembership & roleMembership);

		bool add_candidate(int flow_num);
		void prune_candidates();

		role_t * get_next_role();
		srvRoleHashMap * get_hm_server_role() {
			return hm_server_role;
		}
		virtual void create_sub_roles();
		virtual void rate_roles(const CFlowList& full_flowlist);
		virtual float getRating(const int role_id);
		virtual role_t* getRole(const int role_id);
};

//********************************************************************************

/**
 *	\class	CP2pRole
 *	\brief	Derived class for p2p role identification.
 */
class CP2pRole: public CRole {
	public:
		typedef HashKeyProtoFlowtype p2pRoleHashKey; // key = (prot<<16) + flowtype

		// key = { prot, flowtype }	(see key coding rule above)
		// data = role object object reference
		typedef hash_map<HashKeyProtoFlowtype, role_t *, HashFunction<HashKeyProtoFlowtype> , HashFunction<HashKeyProtoFlowtype> > p2pRoleHashMap;
		typedef hash_map<HashKeyIPv6_5T_2, std::set<const cflow_t*>, HashFunction<HashKeyIPv6_5T_2> , HashFunction<HashKeyIPv6_5T_2> > p2pClientCandidateHashMap;

	private:
		CP2pRole::p2pRoleHashMap * hm_p2p_role;
		CRole::remoteIpHashMap * hm_remote_IP_p2p;
		int cand_flow_num;
		CRoleMembership * proleMembership;
		std::set<int> p2p_candidate_flows;
		virtual void rate_role(role_t& role, const CFlowList& full_flowlist, const Subflowlist& sub_flowlist);
		static const uint32_t p2p_threshold = flow_threshold_p2p;
		static const uint16_t p2p_port_threshold = 1024;
		static const uint32_t client_threshold = flow_threshold_client;

	public:
		CP2pRole(Subflowlist flowlist, const prefs_t & prefs);
		virtual ~CP2pRole();
		void register_rM(CRoleMembership & roleMembership);
		bool add_candidate(int flow_num);
		void prune_candidates(CClientRole & clientRole, CServerRole & serverRole, CFlowFilter & filter);
		role_t * get_next_role();
		int get_cand_flow_num() {
			return cand_flow_num;
		}
		virtual void create_sub_roles();
		virtual void rate_roles(const CFlowList& full_flowlist);
		virtual float getRating(const int role_id);
		virtual role_t* getRole(const int role_id);
		void cleanConsumedClientRoles(CClientRole & clientRole);
};
#endif

