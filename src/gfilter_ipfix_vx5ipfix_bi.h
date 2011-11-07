#ifndef GFILTER_IPFIX_VX5IPFIX_H_
#define GFILTER_IPFIX_VX5IPFIX_H_
/**
 *\file gfilter_ipfix_vx5ipfix_bi.h
 *
 *	\brief Example IPFIX file reader and writer code based on a template
 *	supporting uniflows and biflows on IPv4.
 *
 *	Author: Brian Trammell
 *	Changes (delta counters removed, biflow support added): Eduard Glatz
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdarg.h>
#include <inttypes.h>
#include <ctype.h>
#include <errno.h>
#include <signal.h>

#include <fixbuf/public.h>

#include <netinet/in.h>

#define VX5_TID 0x2301
#define IP_VERS_NR_IPv6 6 // http://www.iana.org/assignments/version-numbers/version-numbers.xml
// details about the fields and datatypes: http://www.iana.org/assignments/ipfix/ipfix.xml
typedef struct vx5Flow_st {
	uint64_t flowStartMilliseconds;
	uint64_t flowEndMilliseconds;
	uint64_t packetTotalCount;
	uint64_t octetTotalCount;
	uint64_t reversePacketTotalCount;
	uint64_t reverseOctetTotalCount;
	uint32_t sourceIPv4Address;
	uint32_t destinationIPv4Address;
	in6_addr sourceIPv6Address;
	in6_addr destinationIPv6Address;
	uint16_t sourceTransportPort;
	uint16_t destinationTransportPort;
	uint32_t ipNextHopIPv4Address;
	in6_addr ipNextHopIPv6Address;
	uint32_t ingressInterface;
	uint32_t egressInterface;
	uint8_t ipVersion; // details about values: http://www.iana.org/assignments/version-numbers/version-numbers.xml
	uint8_t protocolIdentifier;
	uint8_t nextHeaderIPv6;
	uint8_t tcpControlBits;
	uint8_t pad0[4];
} vx5Flow_t;

fbSession_t *vx5InitSession(GError **err);

fBuf_t *vx5ReaderForFP(FILE *fp, GError **err);

fBuf_t *vx5WriterForFP(FILE *fp, GError **err);

#ifdef __cplusplus
}
#endif

#endif /* GFILTER_IPFIX_VX5IPFIX_H_ */
