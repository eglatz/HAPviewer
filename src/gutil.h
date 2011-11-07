#ifndef UTIL_H_
#define UTIL_H_

/**
 *	\file gutil.h
 *	\brief Include file for utility functions.
 */

#include <fstream>
#include <string>
#include <iostream>
#include <set>
#include <stdint.h>
#include <netinet/in.h>
#include <stdio.h>

#include "IPv6_addr.h"
#include "grole.h"
#include "cflow.h"

namespace util {
	void open_outfile(std::ofstream & outfs, std::string ofname);
	void open_infile(std::ifstream & infs, std::string ifname);
	uint64_t getFileSize(std::string in_filename);
	bool fileExists(std::string in_filename);
	FILE * openFile(std::string in_filename, std::string openmode);
	void closeFile(FILE * file);
	IPv6_addr ipV6NfDumpToIpV6(const uint64_t * ipv6_parts);
	IPv6_addr ipV6IpfixToIpV6(const in6_addr & ipv6_ipfix);
	const std::string & ipV6ProtocolToString(uint8_t prot);
	const std::string & print_flowtype(uint8_t dir);
	void record2String(const cflow_t & record, char * out);
	void record2StringShort(const cflow_t & record, char * out);
	//	void record2StringB(const cflow_t & record, char * out);
	//	void summaryEntry2String(const cflow_t & record, char * out);
	//void  write_summary(std::string & basefilename, cflow_t * & summary, int & summary_count, bool csv);
	void seconds2date_ISO8601(uint32_t seconds, std::string & s);
	void seconds2date_short(uint32_t seconds, std::string & s);
	int utime3(const char * timestring);
	std::string pformat(int x, int min_fieldsize);
	std::string pformat(long x, int min_fieldsize);
	std::string bin2hexstring(const void * start, uint32_t length_in_byte);
	std::string graphletSummarizationToString(const role_pattern & config);
	void printFlow(const cflow_t & flow);
	std::string seconds2daytime(uint64_t mseconds);
	std::string getIPandPortWithStableSize(const IPv6_addr & ip, const uint16_t & port);
#ifdef GUI
	void renderDot(std::string & inputDOT, std::string & outputFile, std::string & format);
#endif // GUI
}
;

#endif
