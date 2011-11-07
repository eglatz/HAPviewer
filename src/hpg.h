#ifndef HPG_H_
#define HPG_H_

/**
 *	\file hpg.h
 *	\brief Host profile graphlet definitions.
 */
#include <boost/array.hpp>
#include <stdlib.h>
#include <stdint.h>

#ifdef GUI
const bool hap4nfsen = false;
#else
const bool hap4nfsen = true;
#endif

//( tab width: 3)

/**********************************************************************
 *
 * 	Format definition of stored graphlet edge data (version 3)
 *	==========================================================
 *	File name extension:  *.hpg  (for "host profile graphlet")
 *
 *	This is a graph-description based on edge information. For
 *	each edge the following information is recorded:
 *	- identification of partition-pair connected (rank)
 *	- regular/summary node properties for both involved vertices
 *	- vertex labels
 *	- additional data to make each vertex label unique in its partition
 *	  (this concerns per protocol/per remoteIP uniqueness of port numbers
 *		and flow direction type))
 *	  --> use a dynamically assigned host number
 *	  --> code flow direction type
 *
 *	Note that vertex labels have to be chosen carefully such that edges
 *	are connected properly.
 *
 *	Per graphlet edge 3 values of 128 bit are stored:
 *
 *	value 0: bits 31..4 contain graphlet number (ascending value starting at 0)
 *          	bits 3..0: rank number (rank 0 comprises all edges connecting partition
 *	         0 and 1, rank 1 comprises all edges connecting partition 1 and 2, etc.)
 *
 *	value 1: annotation of node 1 (use 0 for un-annotated node)
 *
 *	value 2: annotation of node 2 (use 0 for un-annotated node)
 *
 *	Currenly there are 4 ranks describing the interconnections in a k-partite graph with k=5.
 *	The node annotations stored in value2/3 depend on the rank as follows:
 *
 *	rank (value0.3..0)   			value 1        value 2
 *	---------------------------------------------------------
 *	localIp_prot         			localIP        protocol
 *	prot_localPort       			protocol       localEport
 *	prot_localPortSum    			protocol       localEportSUM
 *	localPort_remotePort 			localEport     remoteEport
 *	localPortSum_remotePort 		localEportSUM  remoteEport
 *	localPort_remotePortSum			localEport     remoteEportSUM
 *	localPortSum_remotePortSum 	localEportSUM  remoteEportSUM
 *	remotePort_remoteIp  			remoteEport    remoteIP
 *	remotePortSum_remoteIP			remoteEportSUM remoteIP
 *	remotePort_remoteIPsum			remoteEport		remoteIPSUM
 *	remotePortSum_remoteIPsum		remoteEportSUM remoteIPSUM
 *	edge_label							val1				val2
 *	version								version_num		(build_unixsecs)
 *
 *	With:
 *	localEport:  	(protcode<<PROTCODE_SHIFT3)+(flowtype<<FLOWTYPE_SHIFT3)+port
 *	localEportSUM:	(protcode<<PROTCODE_SHIFT3)+(flowtype<<FLOWTYPE_SHIFT3)+((role_num & ROLE_NR_BIT_MASK)<<ROLE_SHIFT3)+(flows & FLOW_COUNT_BIT_MASK)
 *
 *	remoteEport:  	(color<<COLORTYPE_SHIFT)+(protcode<<PROTCODE_SHIFT3)+((hostnum & HOSTNUM_BIT_MASK)<<HOSTNUM_SHIFT)+port
 *	remoteEportSUM:(color<<COLORTYPE_SHIFT)+(flowtype<<FLOWTYPE_SHIFT3)+((rolenum & ROLE_NR_BIT_MASK)<<HOSTNUM_SHIFT)+(peers & FLOW_COUNT_BIT_MASK)
 *
 *	remoteIPSUM:	((rolenum & ROLE_NR_BIT_MASK)<<HOSTNUM_SHIFT)+(peers & FLOW_COUNT_BIT_MASK)
 *
 *	Property  Size   Bitpos.  Comments
 *   ------------------------------------
 *	protocol: 8 bits [7..0]
 *	port:    16 bits [15..0]
 *	color:    2 bits [62..60]       (0=black, 1=red, 2=green, 3=invalid)
 *	protcode: 2 bits [58..56]
 *	flowtype: 4 bits [27..24]
 *	hostnum: 24 bits [28..24]       (greedy per-graphlet host numbering)
 *	val1:	  128 bits (only 64 used) (eg. bytes)
 *	val2:   128 bits (only 64 used) (eg. packets)
 *	version_num: version number (128 bits)
 *	(build_unixsecs): build time as unix seconds (optional; default is 0)
 *
 *	Note: graphlet edges are partially ordered in regard to ranks
 *
 */

// Choose version(only v3 supported)
#define	hpg							v3

// Version 3
// *********

#define	COLORTYPE_SHIFT			60
#define	PROTCODE_SHIFT3			56
#define	FLOWTYPE_SHIFT3			48
#define	ROLE_SHIFT3					24
#define	HOSTNUM_SHIFT				24
#define	GRAPHLETNUM_SHIFT			4

#define	GET_COLORCODE(value)		((uint8_t)(((value) & 0xf000000000000000LL) >> COLORTYPE_SHIFT))
#define	GET_FLOWTYPE(value)		((uint8_t)(((value) & 0x00ff000000000000LL) >> FLOWTYPE_SHIFT3))

#define	LOCAL_EPORT0_MASK			0x0300000000ffffffLL	// ..ffffff: proto << 0; ..3..: protcode << PROTCODE_SHIFT3
#define	ROLE_NR_BIT_MASK			0xffffff					// 3 bytes
#define	HOSTNUM_BIT_MASK			0xffffff					// 3 bytes
#define	FLOW_COUNT_BIT_MASK		0xffffff					// 3 bytes
#define	CLIENT_COUNT_BIT_MASK	0xffffff					// 3 bytes
#define	GRAPHLET_NUM_BIT_MASK	0x1fff					// 13 bit
//	Edge rank defintions
//
// Edge ranks refer to the partitions connected by edges and, thus, carry the names of involved partitions.
//
// One exception is the rank "totalBytes" which is used as a pseudo-edge (i. e. not visualized) to provide additional
// information for the graphlet metadata list.

/**
 * \union Contains one third of a hpg edge
 */
union hpg_field {
		struct {
				uint64_t data;
		} eightbytevalue;
		boost::array<unsigned char, 16> data;
		void reset() {
			std::fill(data.begin(), data.end(), 0);
		}
};
// Definition for v3 graphlet
// --> added for HAPviewer V 1.0
// --> incompatible to v1 and v2 data
// code 15 (out of codes 0..15) is reserved for version info.
// V1 graphlet data files (*.hpg) contain a "srcIP_prot" edge as a first edge.
// V2 graphlet data files (*.hpg) contain a "localIP_prot" edge as a first edge.
// V3 graphlet data files (*.hpg) contain a "version" edge as a first edge.
enum rank_t {
	// Version 1
	// *********
	srcIP_prot = 0,
	prot_dstIP = 1,
	dstIP_srcPort = 2,
	srcPort_dstPort = 3,
	dstPort_dstIP = 4,

	// Version 2
	// *********
	localIP_prot = 5,
	prot_localPort = 6,
	localPort_remotePort = 7,
	remotePort_remoteIP = 8,
	totalBytes = 9, // Counts total bytes of graphlet

	// Version 3
	// *********
	// (re-use 4 ranks from v2)
	//	localIP_prot, 					// k1-k2

	//	prot_localPort, 				// k2-k3
	prot_localPortSum = 0,

	//	localPort_remotePort, 		// k3-k4
	localPortSum_remotePort = 1,
	localPort_remotePortSum = 2,
	localPortSum_remotePortSum = 3,

	//	remotePort_remoteIP, 		// k4-k5
	remotePortSum_remoteIP = 4,
	remotePort_remoteIPsum = 10,
	remotePortSum_remoteIPsum = 11,

	edge_label = 14, // Marks an edge that applies to the edge listed just prior to it (extends it)
	version = 15
};

#endif /* HPG_H_ */
