/**
 *	\file gutil.cpp
 *	\brief Utility functions for concersion and console output.
 */

#include <stdint.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>		// IP protocol type definitions
#include <arpa/inet.h>
#include <sys/stat.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#ifdef GUI
#include <gvc.h>
#endif //GUI

#include <cstdlib>
#include <cstring>
#include <ctime>
#include <assert.h>
#include <stdexcept>
#include <cmath>
#include <sstream>
#include <algorithm>
#include <string>
#include <iomanip>
#include <math.h>

#include "gutil.h"

using namespace std;

namespace util {

	/**
	 *	Open file for output. Discard any contents if it already exists.
	 *
	 *	\param outfs output stream (out)
	 *	\param ofname name of output file (out)
	 *
	 *	\exception string Errormessage
	 */
	void open_outfile(ofstream & outfs, string ofname) {
		outfs.open(ofname.c_str(), ios::out | ios::trunc | ios_base::binary);
		if (outfs.fail()) {
			string error = "ERROR: Opening output file " + ofname + " failed.";
			throw error;
		}
	}

	/**
	 *	Open file for (binary) input.
	 *
	 *	\param infs input stream (in)
	 *	\param ifname name of input file (in)
	 *
	 *	\exception string Errormessage
	 */
	void open_infile(ifstream & infs, string ifname) {
		infs.open(ifname.c_str(), ios::in | ios_base::binary);

		if (infs.fail()) {
			string error = "ERROR: Opening input file " + ifname + " failed.";
			throw error;
		}
	}

	/**
	 *	Open file at in_filename and returns a pointer to the file descriptor.
	 *
	 *	\param in_filename Filename of the file to open
	 *	\param openmode Contains the openmode (C style)
	 *	\exception string Contains the error message
	 *	\return file descriptor
	 */
	FILE * openFile(std::string in_filename, std::string openmode) {
		FILE * pFile = fopen(in_filename.c_str(), openmode.c_str());
		if (pFile == NULL) {
			string errtext = in_filename + ": ";
			errtext += strerror(errno);
			throw errtext;
		}
		return pFile;
	}

	/**
	 *	Closes a file descriptor.
	 *
	 *	\param file File descriptor to close
	 *	\exception string Contains the error message
	 */
	void closeFile(FILE * file) {
		int ret = fclose(file);
		if (ret)
			throw strerror(errno);
	}

	/**
	 *	Test if a file exists.
	 *
	 *	\param in_filename File to check
	 *	\return true if input file exists
	 */
	bool fileExists(std::string in_filename) {
		struct stat statbuf;
		if (stat(in_filename.c_str(), &statbuf) == -1) {
			return false;
		}
		return true;
	}

	/**
	 *	Get filesize of a file.
	 *
	 *	\param in_filename File to look up the size
	 *
	 *	\return size of the file in bytes
	 *
	 *	\exception std::string Errormessage
	 */
	uint64_t getFileSize(string in_filename) {
		// Sanity check: does input file exist?
		if (fileExists(in_filename)) {
			struct stat statbuf;
			stat(in_filename.c_str(), &statbuf);
			return statbuf.st_size;
		}
		string error = "File " + in_filename + " does not exists, can not get filesize";
		throw error;
	}

	IPv6_addr ipV6NfDumpToIpV6(const uint64_t * ipv6_parts) {
		IPv6_addr addr;
		uint64_t p1 = ipv6_parts[0];
		uint64_t p2 = ipv6_parts[1];
		memcpy(addr.begin(), &p1, sizeof(uint64_t));
		memcpy(addr.begin() + sizeof(uint64_t), &p2, sizeof(uint64_t));
		cout << util::bin2hexstring(addr.begin(), sizeof(IPv6_addr)) << endl;
		return addr; // FIXME: is the byte order correct? ~reto
	}

	IPv6_addr ipV6IpfixToIpV6(const in6_addr & ipv6_ipfix) {
		IPv6_addr addr;
		memcpy(addr.begin(), &ipv6_ipfix, sizeof(ipv6_ipfix));
		cout << "[0]" << bin2hexstring(addr.begin(), sizeof(IPv6_addr)) << endl;
		cout << "[1]" << bin2hexstring(addr.begin(), sizeof(IPv6_addr)) << endl;
		return addr;
	}

	/**
	 * \brief Returns the IP protocol as string. E.g. UDP, TCP, ...
	 *
	 * \param prot IP V4 protocol number
	 * \return string IP protocol name
	 */
	const string & ipV6ProtocolToString(uint8_t prot) {
		switch (prot) {
			case IPPROTO_ICMP:
				static const string icmp = "ICMP";
				return icmp;
			case IPPROTO_IGMP:
				static const string igmp = "IGMP";
				return igmp;
			case IPPROTO_TCP:
				static const string tcp = "TCP";
				return tcp;
			case IPPROTO_UDP:
				static const string udp = "UDP";
				return udp;
			case IPPROTO_IPV6:
				static const string ipv6 = "IPv6";
				return ipv6;
			case IPPROTO_ICMPV6:
				static const string icmp_ipv6 = "ICMPv6";
				return icmp_ipv6;
			case IPPROTO_RSVP:
				static const string rsvp = "RSVP";
				return rsvp;
				//IPPROTO_GRE is not defined on OpenSolaris 09.06 - do not know about other versions
#ifdef __svr4
				case IPPROTO_GRE:
				static const string gre = "GRE";
				return gre;
#endif // defined(__svr4__)
			case 94: // Remark: not defined in in.h
				static const string ipip = "IPIP";
				return ipip;
			default:
				static char protoname[20];
				snprintf(protoname, 20, "prot%d", prot);
				static const string unknown(protoname);
				return unknown;
		}
	}

	/**
	 * \brief Returns the flow direction type as descriptive text
	 *
	 * \param dir	direction type
	 * \return string direction text
	 */
	const string & print_flowtype(uint8_t dir) {
		switch (dir) {
			case 1:
				static const string dir1 = "outflow(1)";
				return dir1;
			case 2:
				static const string dir2 = "inflow (2)";
				return dir2;
			case 3:
				static const string dir3 = "uniflow(3)";
				return dir3;
			case 4:
				static const string dir4 = "biflow (4)";
				return dir4;
			case 7:
				static const string dir7 = "allflow(7)";
				return dir7;
			case 8:
				static const string dir8 = "unibifl(8)";
				return dir8;
			case 9:
				static const string dir9 = "q_outfl(9)";
				return dir9;
			case 10:
				static const string dir10 = "q_infl(10)";
				return dir10;
			case 11:
				static const string dir11 = "q_trfl(11)";
				return dir11;
			case 12:
				static const string dir12 = "okflow(12)";
				return dir12;

			default:
				static string dirX = "?flow?(  )"; // Unexpected value
				char msd = 0x30 + dir / 10;
				char lsd = 0x30 + dir % 10;
				dirX[7] = msd;
				dirX[8] = lsd;
				return dirX;
		}
	}



	/**
	 *	Print record contents in human readable form to console.
	 *
	 *	** This version tries to be more compact.
	 *
	 *	\param record	A single flow record.
	 *	\param out Output stream to be used.
	 */
	void record2StringShort(const cflow_t & record, char * out) {
		// Start time
		time_t tt = (time_t) (record.startMs / 1000);
		struct tm ts;
		localtime_r(&tt, &ts);

		// IP addresses
		static string local;
		static string remote;
		local = record.localIP.toString();
		remote = record.remoteIP.toString();

		char dir1[] = "outflow(1)"; // Choice of flow types
		char dir2[] = "inflow (2)";
		char dir3[] = "uniflow(3)";
		char dir4[] = "biflow (4)";
		char dir9[] = "q_outfl(9)";
		char dir10[] = "q_infl(10)";
		char dir11[] = "q_trfl(11)";

		char dir8[] = "unibifl(8)"; // Masks to identify flow types
		char dir7[] = "allflow(7)";
		char dir12[] = "okflow(12)";

		char dirX[] = "?flow?(  )"; // Unexpected value
		char * dir;
		switch (record.dir) {
			case 1:
				dir = dir1;
				break;
			case 2:
				dir = dir2;
				break;
			case 3:
				dir = dir3;
				break;
			case 4:
				dir = dir4;
				break;
			case 7:
				dir = dir7;
				break;
			case 8:
				dir = dir8;
				break;
			case 9:
				dir = dir9;
				break;
			case 10:
				dir = dir10;
				break;
			case 11:
				dir = dir11;
				break;
			case 12:
				dir = dir12;
				break;
			default:
				char msd = 0x30 + record.dir / 10;
				char lsd = 0x30 + record.dir % 10;
				dirX[7] = msd;
				dirX[8] = lsd;
				dir = dirX;
				break;
		}

		char ip_padding1[] = "        ";
		ip_padding1[15 - local.size()] = '\0';
		char ip_padding2[] = "        ";
		ip_padding2[15 - remote.size()] = '\0';

		unsigned long bytes = (unsigned long) record.dOctets;
		unsigned int packets = (unsigned int) record.dPkts;

		cout << ipV6ProtocolToString(record.prot).c_str() << ":" << dir << ip_padding1 << local << ":" << record.localPort << " -> " << ip_padding2 << remote
		      << ":" << record.remotePort << bytes << " Byte, " << packets << " Pkts," << "beg=" << ts.tm_hour << ":" << ts.tm_min << ":" << ts.tm_sec << "."
		      << (record.startMs % 1000) << ", " << "dur=" << (record.durationMs / 1000) << "." << (record.durationMs % 1000) << endl;
	}

	/**
	 *	seconds2date_ISO8601 - converts time from UTC-1900-seconds to extended "YYYY.MM.DD-HR:MIN:SEC" UTC date format.
	 *	This format is useful to display date/time values in the console.
	 *
	 *	\param seconds	: time in seconds
	 *	\param s : result string for date/time
	 */
	void seconds2date_ISO8601(uint32_t seconds, string & s) {
		time_t tt = (time_t) seconds;
		struct tm ts;
		gmtime_r(&tt, &ts);
		char * tmp = NULL;

		// ISO8601 demands: YYYY-MM-DD hh:mm:ssZ (Z stands for "UTC" or "Zulu-time", respectively)
		int ret = asprintf(&tmp, "%04d-%02d-%02d %02d:%02d:%02dZ", 1900 + ts.tm_year, 1 + ts.tm_mon, ts.tm_mday, ts.tm_hour, ts.tm_min, ts.tm_sec);
		if (ret == -1)
			exit(-1);
		s = tmp;
		free(tmp);
	}

	/**
	 *	seconds2date_short - converts time from UTC-1900-seconds to compact "YYYYMMDD.hhmmss" date format.
	 *	This format is useful to construct file names including date/time information.
	 *
	 *	\param seconds		time in seconds
	 *	\param s          result string for date/time
	 */
	void seconds2date_short(uint32_t seconds, string & s) {
		time_t tt = (time_t) seconds;
		struct tm ts;
		gmtime_r(&tt, &ts);
		char * tmp = NULL;

		int ret = asprintf(&tmp, "%04d%02d%02d.%02d%02d%02d", 1900 + ts.tm_year, 1 + ts.tm_mon, ts.tm_mday, ts.tm_hour, ts.tm_min, ts.tm_sec);
		if (ret == -1)
			exit(-1);
		s = tmp;
		free(tmp);
	}

	/**
	 *	Convert short UTC date/time string to unix seconds.
	 *
	 *	\param timestring Short UTC date/time string using format YYYYMMDD.hhmm
	 *
	 *	\return Unix seconds
	 */
	int utime3(const char * timestring) {
		static struct tm tm;
		static time_t t;

		if (strptime(timestring, "%Y%m%d.%H%M", &tm) == NULL) {
			cerr << "\nERROR in strptime(): invalid date/time string = " << timestring << "\n\n";
			exit(1);
		}
		tm.tm_isdst = -1; /* Not set by strptime(); tells mktime()
		 to determine whether daylight saving time
		 is in effect */
		t = mktime(&tm);
		if (t == -1) {
			printf("\nERROR: mktime() failed.!\n\n");
			exit(1);
		}
		cout << (unsigned int) t << " unix seconds since the Epoch " << endl;

		string s;
		uint32_t time = t;
		seconds2date_ISO8601(time, s);
		cout << "Converted back date and time is " << s << ".\n";
		return time;
	}

	/**
	 *	Format a number for pretty output.
	 *
	 *	If required then leading spaces are added.
	 *	Number is formatted by groups of three digits separated by single quotes.
	 *	Note: this function is not reentrant (due to local static variable)
	 *
	 *	\param 	x to be formatted
	 *	\param 	fieldsize Minimum field size to use.
	 */
	string pformat(int x, int min_fieldsize) {
#define dbg false

		stringstream ss;
		ss << x;

		ss.seekg(0, ios::end);
		int numdigits = ss.tellg();
		ss.seekg(0, ios::beg);

		int numsigns = 0;
		if (x < 0)
			numsigns = 1; // Negative numbers have a leading minus sign

		// Calculate number of commas
		int numcommas = (numdigits - numsigns) / 3;

		if (((numdigits - numsigns) % 3) == 0)
			numcommas--; // Suppress comma if no digit on the left of it

		// Calculate number of leading spaces
		int numspaces = min_fieldsize - numdigits - numcommas;
		if (dbg) {
			if (numspaces < 0) {
				numspaces = 0;
				cerr << "INFO: field size exceeded.\n";
			}
		}

		static string s;
		s.clear();
		for (int i = 0; i < numspaces; i++)
			s += " ";
		if (numsigns > 0) {
			char buf[2];
			ss.read(buf, 1);
			buf[1] = 0;
			s += buf;
		}

		int leadingdigits = (numdigits - numsigns) % 3;

		if (dbg) {
			cout << "x=" << x << ", min_fieldsize=" << min_fieldsize << ", numdigits=" << numdigits << ", numsigns=" << numsigns;
			cout << ", numspaces=" << numspaces << ". leadingdigits=" << leadingdigits << ", numcommas=" << numcommas << endl;
		}
		// Output leading digits
		if (leadingdigits > 0) {
			char buf[80];
			ss.read(buf, leadingdigits);
			buf[leadingdigits] = 0;
			s += buf;
		}

		// Update remaining number of digits
		numdigits -= leadingdigits;

		// Output remaining digits as groups of three
		for (int j = numdigits / 3; j > 0; j--) {
			char buf[6];
			ss.read(buf, 3);
			buf[3] = 0;
			if (j < numdigits / 3 || leadingdigits > 0)
				s += "'";
			s += (char *) buf;
		}

		return s;
	}

	/**
	 *	Format a number for pretty output.
	 *
	 *	If required then leading spaces are added.
	 *	Number is formatted by groups of three digits separated by single quotes.
	 *	Note: this function is not reentrant (due to local static variable)
	 *
	 *	\param 	x to be formatted
	 *	\param 	fieldsize Minimum field size to use.
	 */
	string pformat(long x, int min_fieldsize) {
#define dbg false

		stringstream ss;
		ss << x;

		ss.seekg(0, ios::end);
		int numdigits = ss.tellg();
		ss.seekg(0, ios::beg);

		int numsigns = 0;
		if (x < 0)
			numsigns = 1; // Negative numbers have a leading minus sign

		// Calculate number of commas
		int numcommas = (numdigits - numsigns) / 3;

		if (((numdigits - numsigns) % 3) == 0)
			numcommas--; // Suppress comma if no digit on the left of it

		// Calculate number of leading spaces
		int numspaces = min_fieldsize - numdigits - numcommas;
		if (dbg) {
			if (numspaces < 0) {
				numspaces = 0;
				cerr << "INFO: field size exceeded.\n";
			}
		}

		static string s;
		s.clear();
		for (int i = 0; i < numspaces; i++)
			s += " ";
		if (numsigns > 0) {
			char buf[2];
			ss.read(buf, 1);
			buf[1] = 0;
			s += buf;
		}

		int leadingdigits = (numdigits - numsigns) % 3;

		if (dbg) {
			cout << "x=" << x << ", min_fieldsize=" << min_fieldsize << ", numdigits=" << numdigits << ", numsigns=" << numsigns;
			cout << ", numspaces=" << numspaces << ". leadingdigits=" << leadingdigits << ", numcommas=" << numcommas << endl;
		}
		// Output leading digits
		if (leadingdigits > 0) {
			char buf[80];
			ss.read(buf, leadingdigits);
			buf[leadingdigits] = 0;
			s += buf;
		}

		// Update remaining number of digits
		numdigits -= leadingdigits;

		// Output remaining digits as groups of three
		for (int j = numdigits / 3; j > 0; j--) {
			char buf[6];
			ss.read(buf, 3);
			buf[3] = 0;
			if (j < numdigits / 3 || leadingdigits > 0)
				s += "'";
			s += (char *) buf;
		}

		return s;
	}

	std::string bin2hexstring(const void * start, uint32_t length_in_byte) {
		std::stringstream ss;
		uint32_t bytes_written = 0;
		ss << "0x[" << length_in_byte << "byte]";
		while (bytes_written < length_in_byte) {
			char buf[16];
			uint32_t bytes_left = length_in_byte - bytes_written;
			string part_hex;
			if (bytes_left >= 4) {
				sprintf(buf, "%X", *((uint32_t *) ((uint32_t*) start + bytes_written)));
				part_hex = std::string(buf);
				part_hex.insert(part_hex.begin(), 8 - part_hex.size(), '0');
				bytes_written += 4;
			} else if (bytes_left >= 2) {
				sprintf(buf, "%X", *((uint16_t *) ((uint32_t*) start + bytes_written)));
				part_hex = std::string(buf);
				part_hex.insert(part_hex.begin(), 4 - part_hex.size(), '0');
				bytes_written += 2;
			} else if (bytes_left >= 1) {
				sprintf(buf, "%X", *((uint8_t *) ((uint32_t*) start + bytes_written)));
				part_hex = std::string(buf);
				part_hex.insert(part_hex.begin(), 2 - part_hex.size(), '0');
				bytes_written += 1;
			} else {
				cerr << "ERROR: unexpected case in bin2hexstring encountered" << endl;
				assert(false);
			}
			ss << part_hex;
		}
		return ss.str();
	}

	std::string graphletSummarizationToString(const role_pattern & config) {
		string res = "";
		const role_pattern max = (role_pattern)round(logf(max_pattern) / logf(2)); // round is needed because logf works with floating point numbers. log2f would calculate log2() directly but is not available on FreeBSD
		for (unsigned int pos = 0; pos < max; ++pos) {
			uint8_t filter = (uint8_t)pow(double(2), double(pos));
			uint8_t value = (config & filter) >> (pos);
			assert((value|0x1)==1);
			if (value == 0) {
				res.append("o"); // represents a not summarized node
			} else {
				res.append("[]"); // represents a summarized node
			}
			if (pos + 1 < max) {
				res.append("-"); // represents an edge
			}
		}
		return res;
	}

	void printFlow(const cflow_t& flow) {
		cout << "[cflow k1-k5]\t" << (flow.localIP) << "\t" << ((int) flow.prot) << "\t" << (flow.localPort) << "\t" << (flow.remotePort) << "\t"
		      << (flow.remoteIP) << endl;
	}

	string getIPandPortWithStableSize(const IPv6_addr & ip, const uint16_t & port) {
		stringstream ipandport;
		if (ip.isIPv6()) {
			int fill = INET6_ADDRSTRLEN - ip.toString().size() - 2 /* "]:" */ - 5 /* port */ ;
			ipandport << setfill(' ') << setw(fill) << "[" << left << ip << "]:" << setw(5) << port;
		} else {
			int fill = INET_ADDRSTRLEN - ip.toString().size() - 1 /* ":" */ - 5 /* port */ ;
			ipandport << setfill(' ') << setw(fill) << left << ip << ":" << setw(5) << port;
		}
		return ipandport.str();
	}

	/**
	 *	This format is useful to display time values in the console.
	 *
	 *	\param seconds	: time in mseconds
	 *
	 *	\return string for time
	 */
	string seconds2daytime(uint64_t mseconds) {
		stringstream output;
		time_t tt = (time_t) (mseconds / 1000);
		struct tm ts;
		localtime_r(&tt, &ts);
		output << setw(2) << setfill('0') << ts.tm_hour << ":" << setw(2) << setfill('0') << ts.tm_min << ":" << setw(2) << setfill('0') << ts.tm_sec << "."
		      << setw(3) << setfill('0') << (mseconds % 1000);
		return output.str();
	}

#ifdef GUI

	/**
	 * Render a DOT file to something that it supported by graphviz
	 *
	 * @param inputDOT Filename of inputfile
	 * @param outputFile Filename of outputfile
	 * @param format selected output format (png, jpg, svg, etc.)
	 *
	 * @exception std::string Errormessage
	 */
	void renderDot(std::string & inputDOT, std::string & outputFile, std::string & format) {
		GVC_t *gvc;
		graph_t *g;
		FILE *fpin;

		gvc = gvContext();

		try {
			fpin = util::openFile(inputDOT.c_str(), "r");
		}
		catch(string & e) {
			throw e;
		}

		g = agread(fpin);
		util::closeFile(fpin);

		if(g == NULL) {
			stringstream error;
			error << ".g.dot" << " is not a useable dot file";
			throw error.str();
		}

		gvLayout(gvc, g, (char *) "dot");
		if(gvc == NULL) {
			stringstream error;
			error << ".g.dot" << " is not a useable dot file";
			throw error.str();
		}
		int ret = gvRenderFilename(gvc, g, (char *) format.c_str(), (char *) outputFile.c_str());
		if(ret == -1)
			throw "Could not save file";

		gvFreeLayout(gvc, g);
		agclose(g);
	}
#endif // GUI
} // Namespace
