#ifndef GFILTER_PCAP_H_
#define GFILTER_PCAP_H_

/**
 *	\file gfilter_pcap.h
 *	\brief Filter to import pcap files
 */
#include <string>

#include "gfilter.h"
#include "IPv6_addr.h"
#include "cflow.h"

/**
 *	\class	GFilter_pcap
 *	\brief	GFilter_pcap is an class which can import pcap files
 */
class GFilter_pcap: public GFilter {
	public:
		GFilter_pcap(std::string name = "pcap", std::string simplePattern = "*.pcap", std::string regexPattern = "^.+\\.pcap$");
		virtual void read_file(std::string in_filename, CFlowList & flowlist, const IPv6_addr & local_net, const IPv6_addr & netmask, bool append) const;
		virtual bool acceptFileForReading(std::string in_filename) const;
};

#endif /* GFILTER_PCAP_H_ */
