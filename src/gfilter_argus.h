/**
 *	\file gfilter_argus.h
 *	\brief Filter to import argus files
 */
#ifndef GFILTER_ARGUS_H_
#define GFILTER_ARGUS_H_

#include "gfilter.h"

/**
 *	\class	GFilter_argus
 *	\brief	GFilter_argus is an class which can import argus files
 */
class GFilter_argus: public GFilter {
	public:
		GFilter_argus(std::string formatName = "argus", std::string humanReadablePattern = "*.log", std::string regexPattern = ".*\\.log");
		virtual void read_file(std::string in_filename, CFlowList & flowlist, const IPv6_addr & local_net, const IPv6_addr & netmask, bool append) const;
		virtual bool acceptFileForReading(std::string in_filename) const;

	private:
		static uint8_t proto_string_to_proto_num(const std::string& p_str);
		static uint8_t flow_dir_string_to_flow_dir(const std::string& fd_str);
		static void invert_flow_if_needed(cflow_t& flow, const IPv6_addr& local_net, const IPv6_addr& netmask);

		enum ARGUS_FIELDS {
			START_TS = 0,
			DURATION = 1,
			PROTOCOL = 2,
			SRC_IP = 3,
			DST_IP = 4,
			DIRECTION = 5,
			SRC_PORT = 6,
			DST_PORT = 7,
			SRC_PACKETS = 8,
			DST_PACKETS = 9,
			SRC_BYTES = 10,
			DST_BYTES = 11,
			SRC_TOS = 12,
			DST_TOS = 13
		};
};

#endif /* GFILTER_ARGUS_H_ */
