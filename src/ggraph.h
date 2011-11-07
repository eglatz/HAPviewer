#ifndef GGRAPH_H_
#define GGRAPH_H_

/**
 *	\file ggraph.h
 *	\brief Class CGraphlet for graphlet inference.
 *
 *	Transforms flow and role data into graph descriptions.
 *
 *	So far, we only support the binary "hpg" format defined in hpg.h.
 *	This format is very space efficient as it was originally introduced
 *	to store a large number of graphlets in a file efficiently.
 */

#include <iostream>
#include <fstream>

#include <stdlib.h>
#include <string>

#include <boost/array.hpp>

#include "cflow.h"
#include "global.h"
#include "grole.h"
#include "HashMapE.h"
#include "gsummarynodeinfo.h"

/**
 *	\class CGraphlet
 *
 *	\brief Infers graphlet vertex and edge data from single flows or from roles.
 *	Data is stored to a file using the format as defined by hpg.h.
 */
class CGraphlet {
	protected:
		int * flow_client_role;
		int * flow_server_role;
		int * flow_p2p_role;
		//		prefs_t & prefs; FIXME: needed?

		std::ofstream outfs;
		uint64_t totalbytes; // Counts bytes over all flows belonging to a particular graphlet
		uint32_t hostnum;

		CRoleMembership * proleMembership;

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

		// For a list of hosts
		//	key = IP address
		// data = (?)
		typedef hash_map<HashKeyIPv6, int, HashFunction<HashKeyIPv6> , HashFunction<HashKeyIPv6> > FlowHashMapHost;

		// Hash keys & maps for graphlet inference
		// ***************************************
		// Class CHashKey4_4 fits all graphlet hash maps needed:
		// - key consist of a pair of 32 bit values
		// - entry consists of a 64 bit value
		//
		// The type "localEport" keeps track of protocol type. It is used
		// for edges that always are associated with localIP.
		//
		// The type "remoteEport" occupies 32 bits and keeps track of remote host identity and protocol type as follows:
		// protocol_code (2 bit), remote_hostnumber (14 bit), port_number (16 bit).
		//
		// Host identities are formed as host numbers starting and ascending from 0 by allocating a new host number
		// to each new encountered remoteIp value. Thus, the host numbering has no special meaning except that it
		// is unique for each remoteIP.

		// Limitations & restrictions:
		//
		// Host numbers are used to distinguish cleanly between separate sockets as defined by { portnumber, protocol, hostnumber }.
		// Host numbers are in this context preferable to IP addresses as they can be allocated densly and, thus, make better use
		// of value ranges in the presence of limited data sizes.
		//
		// Unique host numbering used through hpg data creation:
		// - host numbers assigned to remoteIPs are limited to 32 bits
		// - host numbers as used as a part of the "remotePort" identification are limited to 14 bits
		//
		// Sequence numbers for graphlets
		// These numbers are used for:
		// 1) separation between subsequent graphlet edges when reading hpg data from a file. A change in graphlet_no indicates that data
		//    from a new graphlet starts.
		// 2) List view presentation in tool "gviewer": graphlet_no distinguish lines in the list view and can be used to jump directly to
		//    a particular line number (go to menu).
		// Graphlet numbers, as contained in hpg data, are restricted to 14 bits. Therefore, graphlet numbers wrap around at 16384.
		// But, as graphlets are sorted by ascending graphlet number in hpg files, the 14 bit limitation can be overcome when reading
		// the hpg data. Basically, a new graphlet number could be created for graphlets read as the graphlet number has no special
		// meaning except that it makes individual graphlets distinguishable.

		// Keys are needed to identify edges connecting graph partitions made of vertices.

		// key1 = { IP, proto }
		// key2 = { proto, Eport }
		// key3 = { - , Ip }
		// key4 = { Eport, Eport }
		// key5 = { Eport, Ip }
		typedef CHashKey6_6 graphletHashKey;
		//typedef boost::array<char, 32> HashMapEdge;

		// Entries describe edges in a unique way.

		// entry1 = (localIP<<32) + proto
		// entry2 = (prot<<32 + Eport)
		// entry3 = (Hnum<<32 + remoteIp)
		// entry4 = (Eport1<<32 + Eport2)
		// entry5 = (Eport2<<32 + Ip)
		struct flowsPacketsType;
		struct HashMapEdge {
				IPv6_addr ip;
				union {
						uint32_t proto;
						uint16_t hnum;
						uint32_t bytes;
						uint64_t rolnum_clients;
				} valueA;

				union {
						uint64_t port1;
						uint32_t packets;
				} valueB;

				union {
						uint32_t flows;
						uint64_t port2;
				} valueC;

				HashMapEdge();

				void addflowsPackets(const HashMapEdge fp2);
				void addBytesPackets(const HashMapEdge fp2);
		};

		typedef hash_map<graphletHashKey, HashMapEdge, HashFunction<graphletHashKey> , HashFunction<graphletHashKey> > graphletHashMap;

		// *** Use individual hash maps for each rank type

		// Derive a fully annotated graphlet in form of a k-partite graph (k=5)
		// Use k-1 hash tables to capture edges between the k partitions
		// Additionally, one more hash map is used to keep track of unique host numbers
		// Partitions are: localIP, prot, localPort, remotePort, remoteIP
		graphletHashMap * hm_localIp_prot; // localIP--prot

		// Local port number is not shared between protocols and hosts
		// (we have one hosts only, but might have several protocols)
		// -> store protocol enum code together with port number (use enum values as protocol code)
		graphletHashMap * hm_prot_localPort_11; // prot--localPort
		graphletHashMap * hm_prot_localPort_1n; // prot--localPort

		// Remote port numbers are not shared between remote hosts and protocols
		// (we might have several protocols and several remoteIPs)
		// -> store protocol enum code and remote host number together with port number
		graphletHashMap * hm_localPort_remotePort_11; // localPort--remotePort
		graphletHashMap * hm_localPort_remotePort_n1; // localPort--remotePort
		graphletHashMap * hm_localPort_remotePort_1n; // localPort--remotePort
		graphletHashMap * hm_localPort_remotePort_nn; // localPort--remotePort
		// Additional has map needed for edge annotations
		graphletHashMap * hm_localPort_remotePortE; // localPort--remotePort (extension)

		// Each remote port (enhanced with protocol enum code and host number) is associated
		// with exactly one remote host. To save space we do not identify remote host by its IP address,
		// but with a consecutively allocated host number (host code).
		// -> store unique remote Ips together with a host code (starting at 0; up to (2**14)-1)
		graphletHashMap * hm_hnum_remoteIp; // Auxiliary hash map for unique remote host numbers

		// Each remote port per protocol is associated with exactly one remoteIp.
		graphletHashMap * hm_remotePort_remoteIp_11; // remotePort--remoteIP
		graphletHashMap * hm_remotePort_remoteIp_n1; // remotePort--remoteIP
		graphletHashMap * hm_remotePort_remoteIp_1n; // remotePort--remoteIP
		graphletHashMap * hm_remotePort_remoteIp_nn; // remotePort--remoteIP
		// Additional has map needed for edge annotations
		graphletHashMap * hm_remotePort_remoteIpE; // remotePort--remoteIP (extension)
		graphletHashMap::iterator iterIpProt, iterProtEport, iterEport2, iterEport3, iterHnumIp, iterEportIp;

	public:
		CGraphlet(std::string hpg_filename, CRoleMembership & roleMembership);
		~CGraphlet();
		void add_single_flow(const cflow_t & pflow, int role_num, int flow_idx);
		void add_generic_role(CRole::role_t & role, const CRole::role_t & parent_role, IPv6_addr lastIP, Subflowlist flow_list);
		void finalize_graphlet(int graphlet_nr);
		CSummaryNodeInfos* nodeInfos;
	private:
		static uint8_t flowtype2colorcode(const uint8_t flowtype);
		static HashMapEdge ipProtoToEdge(const IPv6_addr & ip, const uint32_t proto);
		static HashMapEdge protoEportToEdge(const uint32_t proto, const uint64_t port);
		static HashMapEdge hNumRIpToEdge(const uint16_t hnum, const IPv6_addr & ip);
		static HashMapEdge ePort1EPort2ToEdge(const uint64_t port1, const uint64_t port2);
		static HashMapEdge ePortIpToEdge(const uint64_t port, const IPv6_addr & ip);
		static HashMapEdge rBytesRPacketsToEdge(const uint32_t bytes, const uint32_t packets);
		static HashMapEdge flowsPacketsToEdge(const uint32_t flows, const uint32_t packets);
		static HashMapEdge ePortRolnumClientsToEdge(const uint64_t port, const uint64_t rolnum_clients);
		static HashMapEdge bytesFlowsToEdge(const uint32_t bytes, const uint32_t flows);

		// functions that generate values used in graphlet generation. these functions mainly shift numbers and have been
		// extracted to avoid code duplication
		static uint64_t getLocalEport(const uint8_t flow_type, const uint32_t role_nr, const uint32_t flow_count);
		static uint64_t getLocalEport(const uint8_t flow_type, const uint64_t localEportKey);
		static uint64_t getLocalEportKey(const uint8_t protocol, const uint16_t local_port);
		static uint64_t getRemoteEport(const uint8_t flowtype, const uint32_t role_num, const uint32_t remote_port/*or flow count..same logic*/);
		static uint64_t getRemoteEport(const uint8_t flowtype, const uint8_t protocol, const uint32_t hostnum, const uint16_t remote_port, const uint16_t flow_id);
		static uint64_t getRolnumClients(const uint32_t role_nr, const uint32_t client_count);
		static std::string getSummaryNodeIdString(const CRoleMembership::sumnode_t* node);
};

#endif

