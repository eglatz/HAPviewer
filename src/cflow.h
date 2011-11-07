#ifndef CFLOW_H_
#define CFLOW_H_
/**
 *	\file cflow.h
 *	\brief Compact format for NetFlow records.
 */

#include <stdint.h>
#include <iosfwd>
#include <vector>

#include "global.h"
#include "IPv6_addr.h"

#define CFLOW_4_MAGIC_NUMBER 1
#define CFLOW_6_MAGIC_NUMBER 2

// CFLOW_CURRENT_MAGIC_NUMBER should always point to the internally used magic version
#define CFLOW_CURRENT_MAGIC_NUMBER CFLOW_6_MAGIC_NUMBER

struct role_associations;
/**
 * \class	role_associations
 * \brief	Contains information about a flows' role membership.
 * 			This information is used to resolve role conflicts.
 */
struct role_associations {
	float client;				///< value between 0 and 1 that represents the flow's association with role type "client" or "multi client"
	float server;				///< value between 0 and 1 that represents the flow's association with role type "server""
	float p2p;					///< value between 0 and 1 that represents the flow's association with role type "peer to peer"
	void init() { // default values for all role types: 0
		client = 0;
		server = 0;
		p2p = 0;
	}
	static std::string toString(const role_associations& ra);
};


/**
 *	\class	cflow6
 *	\brief	Cflow format, used to store the relevant parts of NetFlow records (suitable for IPv4/6; size is 72 bytes)
 *				The members of this struct should not be aligned (#pragma pack(1)) as we serialize cflow6 directly to files.
 *
 *				Cflow format (suitable for IPv4/6; size is 72 bytes)
 *
 *				Additional requirements for files using this format:
 *				 - must use GZIP compression
 *				 - flows must be merged (re-assembled flow fragments)
 *				 - flow list must be sorted in
 *					   i) ascending order of srcIP
 *					  ii) ascending order of dstIP
 *					 iii) ascending order of flow start time
 */
#pragma pack(1)
struct cflow6 {
		uint8_t magic; ///< Magic number (format version)
		uint8_t prot; ///< protocol type
		union {
				uint8_t dir; ///< direction: for values see enum flow_type_t
				uint8_t flowtype; ///< Flow type
		};
		uint8_t tos_flags; ///< ToS flags
		uint32_t durationMs; ///< Flow duration in milliseconds since the epoch
		uint64_t startMs; ///< Flow start time in milliseconds
		IPv6_addr localIP; ///< Numeric ip address of source/server/client vertex (network byte order)
		IPv6_addr remoteIP; ///< Numeric ip address of destination vertex (network byte order)
		uint64_t dOctets; ///< flow size in byte
		uint32_t dPkts; ///< number of packets contained in flow
		uint16_t localPort; ///< Source port of vertex
		uint16_t remotePort; ///< Destination port of vertex
		uint32_t localAS; ///< source AS
		uint32_t remoteAS; ///< destination AS
		//uint32_t padding;		///< Fill up to next multiple of 8.

		cflow6();
		cflow6(const IPv6_addr & localIP, uint16_t localPort, const IPv6_addr & remoteIP,
					uint16_t remotePort, uint8_t prot, uint8_t flowtype, uint64_t startMs = 0,
					uint32_t durationMs = 0, uint64_t dOctets = 0, uint32_t dPkts = 0, uint8_t
					magic = CFLOW_6_MAGIC_NUMBER);
		bool operator<(const cflow6 & flow) const;
		void print(std::ostream & out) const;
};
#pragma pack()

std::ostream & operator<<(std::ostream& os, const cflow6 & flow);

/**
 *	\typedef cflow_t
 *	\brief cflow_t is a typedef for the currently used version of cflow.
 *			 Currently its is an alias for cflow6.
 *			 Use wherever possible cflow_t so it is possible to update this line
 *			 typedef to use a new version of the cflow6 struct.  This should be possible
 *			 relatively painless, as long as the new version just extend the cflow6 and not
 *			 modifies anything
 */
typedef cflow6 cflow_t;

/**
 *	\typedef CFlowList
 *	\brief CFlowList is a short version of std::vector<cflow_t>
 */
typedef std::vector<cflow_t> CFlowList;

/**
 *	\class	Subflowlist
 *	\brief	Subflowlist allows to access parts of a CFlowList without copying the CFlowList.
 */
class Subflowlist {
	public:
		/**
		 *	\typedef const_iterator
		 *	\brief Const iterator type
		 */
		typedef CFlowList::const_iterator const_iterator;
		/**
		 *	\typedef difference_type
		 *	\brief difference type
		 */
		typedef CFlowList::difference_type difference_type;
		/**
		 *	\typedef size_type
		 *	\brief Size type
		 */
		typedef CFlowList::size_type size_type;

		Subflowlist();
		Subflowlist(const_iterator begin, const_iterator end);
		Subflowlist(const Subflowlist & subflowlist);
		Subflowlist(const CFlowList & subflowlist);

		void setBegin(const_iterator begin);
		void setEnd(const_iterator end);
		void invalidate();
		void invalidateBegin();
		void invalidateEnd();
		const_iterator end() const;
		const_iterator begin() const;
		size_type size() const;
		const cflow_t & operator[](difference_type n) const;

	private:
		const_iterator _begin; ///< first element
		const_iterator _end; ///< one element behind the latest one
		bool initializedBegin; ///< true if _begin was set
		bool initializedEnd; ///< true if _end was set
};

// Compacted flow4 format (suitable for ipv4 only; size is 48 bytes)
// ================================================================

// We employ anonymous unions with components of equal memory footprint.
// This allows as to access the same members by different names. This is useful when using cflow_t
// for single flows and flow summaries (this is needed during the server role summarization to use
// the same hash map type for single records and summaries)
struct cflow4 {
		union {
				uint32_t localIP; ///< Numeric ip address of source vertex (host byte order)
				uint32_t serverIP; ///< Numeric ip address of server (host byte order)
				uint32_t clientIP; ///< Numeric ip address of client (host byte order)
		};
		union {
				uint32_t remoteIP; ///< Numeric ip address of destination vertex (host byte order)
				uint32_t connections; ///< Number of connections to a service port
		};
		uint64_t startMs; ///< Flow start time in milliseconds since the epoch
		union {
				uint32_t durationMs; ///< Flow duration in milliseconds since the epoch
				uint32_t summaryIn; ///< Index into inside summary list (flow membership, summary self-id)
		};
		union {
				uint16_t localPort; ///< Source port of vertex
				uint16_t servicePort; ///< Source port of vertex
		};
		union {
				uint16_t remotePort; ///< Destination port of vertex
				uint16_t clients; ///< Number of clients accessing this endpoint
		};
		uint64_t dOctets; ///< flow size in byte
		uint32_t dPkts; ///< number of packets contained in flow
		union {
				uint32_t summaryOut; ///< Index into outside summary list (flow membership)
				struct {
						uint16_t local; ///< source AS
						uint16_t remote; ///< destination AS
				} AS;
		};
		uint8_t prot; ///< protocol type
		union {
				uint8_t dir; ///< direction: for values see enum flow_type_t
				uint8_t flowtype; ///< Flow type
		};
		uint8_t tos_flags; ///< ToS flags
		uint8_t magic; ///< Magic number (format version)
		uint32_t padding; ///< Fill up to next multiple of 8
};

/**
 *	\enum proto_t
 *	\brief  Enumeration of distinguished protocols.
 */
enum proto_t {
	UDP, TCP, ICMP, OTHER
};

/**
 *	Maps uint8_t to proto_t
 *
 *	\param protonum Integer with the protcol number
 *
 *	\return proto_t Protocol
 */
inline proto_t map_protonum(uint8_t protonum) {
	switch (protonum) {
		case 1: //prot = "ICMP"
			return ICMP;
		case 6: //prot = "TCP "
			return TCP;
		case 17: //prot = "UDP "
			return UDP;
		default:
			return OTHER;
	}
}


/**
 * \enum flow_type_t
 *
 * \brief Enum flow type definitions employed as bit masks
 *
 *  Flow types are assigned to bit positions as follows:
 *
 *  Bitpos. 	Flow Type	Mask Value 	Comment
 *
 *     0		outflow	 	000001 B (=1)
 *     1		inflow      000010 B (=2)
 *   0/1		uniflow		000011 B (=3)	Unidirectional flow / transit flow
 *     2		biflow      000100 B (=4)	Bidirectional flow
 *     3		unibiflow   001000 B (=8) * (see below)
 * 0/1/2		allflow     000111 B (=7)
 *   2/3    okflow      001100 B (=12) benign flows (**)
 *  0..3		simpleflow	001111 B (=15) mask to get flow type without early/late attributes
 *     5		late			010000 B (=16)	flow exists after current interval
 *     6		early		 	100000 B (=32) flow exists before current interval
 *   5/6		longstand	110000 B (=48) long-standing flow (mask)
 *
 *   *: uniflow in the presence of one or more biflows between
 *      involved hosts
 *  **: based on the assumption that for beginning traffic between
 *      two hosts there has to be at least one biflow beside any
 *      uniflows
 */
enum flow_type_t {
	outflow = 1, inflow = 2, uniflow = 3, biflow = 4, unibiflow = 8, allflow = 7, okflow = 12, simpleflow = 15, late = 16, early = 32, longstand = 48
};

/**
 *	\class CFlowFilter
 *
 *	\brief Supports flow filtering by:
 *	- flow direction type (biflow, inflow, outflow, prod. inflow, prod. outflow)
 *	- protocol (granularity: TCP/UDP/ICMP/OTHER)
 *
 *	A flow filter object defines for each flow contained in flowlist if it
 *	is filtered or not. For this purpose a boolean array is initialized at
 *	object construction time. Thus, the filter function is very fast by
 *	just looking up this array by flow number.
 */
class CFlowFilter {
	private:
		std::vector<bool> flow_filter; ///< Array that defines filter setting on a per flow basis
		uint8_t flowtype_filter; ///< Bitmask of the flowtypes to filter
		uint8_t not_flowtype_filter; ///< Bitmask of the flowtypes not to filter

	public:
		CFlowFilter(const Subflowlist & subflowlist, const prefs_t & prefs);
		bool filter_flow(unsigned int flow_num) const;
};
#endif /* CFLOW_H_ */
