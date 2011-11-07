#ifndef GFILTER_IPFIX_H_
#define GFILTER_IPFIX_H_

/**
 *	\file gfilter_ipfix.h
 *	\brief Filter to import ipfix files
 */

#include <string>

#include "fixbuf/public.h"	// fixbuf routines to read ipfix files
#include "gfilter_ipfix_vx5ipfix_bi.h"	// Auxiliary functions to create an IPFIX file reader
#include "gfilter.h"

/**
 *	\class	GFilter_ipfix
 *	\brief	GFilter_ipfix is an class which can import ipfix files
 */
class GFilter_ipfix: public GFilter {
public:
	GFilter_ipfix(std::string name = "ipfix", std::string simplePattern = "*.dat", std::string regexPattern = ".*\\.dat");
	virtual void read_file(std::string in_filename, CFlowList & flowlist, const IPv6_addr & local_net, const IPv6_addr & netmask, bool append) const;
	virtual bool acceptFileForReading(std::string in_filename) const;
	void print_ipfix_record(uint8_t * recbase) const;
};

#endif /* GFILTER_IPFIX_H_ */
