/**
 *	\file IPv6_addr.cpp
 *	\brief Internally used class to store IP addresses (v4 and v6)
 */

#include <algorithm>
#include <string.h>
#include <stdint.h>
#include <fstream>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <sys/socket.h>
#include <string.h>
#include <string>
#include <iostream>
#include <sstream>
#include <limits>
#include <boost/regex.hpp>

#include "IPv6_addr.h"

using namespace std;

const std::string IPv6_addr::ipRegex = "[:\\.A-Fa-f0-9]+";
const boost::hash<uint32_t> IPv6_addr::partial_ip_hasher = boost::hash<uint32_t>(); // initializes the hasher

/**
 *	Constructor: default, assigns 0 to all bits
 *	\pre sizeof(IPv6_addr) == 16
 */
IPv6_addr::IPv6_addr() {
	assert(sizeof(IPv6_addr) == 16); // make sure we do not add any overhead to this class
	assign(0);
}

/**
 *	Constructor: from in6_addr.
 *
 *	\param src in6_addr struct representing the IP address.
 *	\param hostorder flag which indicates if the submitted is already in networkorder-byte-order
 *
 *	\pre sizeof(IPv6_addr) == 16
 *	\pre sizeof(in6_addr) == 16
 */
IPv6_addr::IPv6_addr(const in6_addr & src) {
	assert(sizeof(IPv6_addr) == 16); // make sure we do not add any overhead to this class
	assert(sizeof(in6_addr) == 16);
	memcpy(this, &src, sizeof(src));
}

/**
 *	Constructor: from string.
 *
 *	\param src string representing the IP address.
 *
 *	\exception std::string Errormessage
 *	\pre sizeof(IPv6_addr) == 16
 */
IPv6_addr::IPv6_addr(string IP_str) {
	assert(sizeof(IPv6_addr) == 16); // make sure we do not add any overhead to this class
	IPv6_addr result_ip;

	boost::regex ip_regex(ipRegex);
	if (!boost::regex_match(IP_str, ip_regex)) {
		string::iterator it = IP_str.begin();
		while (it != IP_str.end()) {
			boost::smatch m;
			if (!boost::regex_match(string::const_iterator(it), string::const_iterator(it + 1), m, ip_regex)) {
				IP_str.erase(it);
				it--;
			}
			it++;
		}
	}

	bool ret = false;
	if (IP_str.find(":") != string::npos) { // looks like IPv6?
		in6_addr ipv6;
		ret = inet_pton(AF_INET6, IP_str.c_str(), &ipv6);
		*this = ipv6;
	} else {
		uint32_t ipv4;
		ret = inet_pton(AF_INET, IP_str.c_str(), &ipv4);
		*this = IPv6_addr(ntohl(ipv4));
	}
	if (ret != 1) { // src is neither a valid IPv4 nor a valid IPv6 string
		string errormsg = IP_str + " is not a valid IP address";
		throw errormsg;
	}
}

/**
 *	Constructor: from 32 bit int value.
 *
 *	\param src uint32_t value representing the IPv4 address.
 *
 * IPv4-mapped IPv6 addresses
 *
 * Hybrid dual-stack IPv6/IPv4 implementations support a special class of addresses, the IPv4-mapped IPv6 addresses.
 * This address type has its first 80 bits set to zero and the next 16 set to one, while its last 32 bits are filled with the IPv4 address.
 * These addresses are commonly represented in the standard IPv6 format, but having the last 32 bits written in the customary dot-decimal
 * notation of IPv4; for example, ::ffff:192.0.2.128 represents the IPv4 address 192.0.2.128.
 *
 * Because of the significant internal differences between IPv4 and IPv6, some of the lower level functionality available to programmers in
 * the IPv6 stack do not work identically with IPv4 mapped addresses. Some common IPv6 stacks do not support the IPv4-mapped address feature,
 * either because the IPv6 and IPv4 stacks are separate implementations (e.g., Microsoft Windows 2000, XP, and Server 2003), or because of
 * security concerns (OpenBSD) .[34] On these operating systems, it is necessary to open a separate socket for each IP protocol that is to
 * be supported. On some systems, e.g., the Linux kernel, NetBSD, and FreeBSD, this feature is controlled by the socket option IPV6_V6ONLY
 * as specified in RFC 3493
 *
 *	copied from: http://en.wikipedia.org/w/index.php?title=IPv6&section=20#IPv4-mapped_IPv6_addresses, 29.3.2011
 *
 *	\exception std::string Errormessage
 *	\pre sizeof(IPv6_addr) == 16
 */
IPv6_addr::IPv6_addr(uint32_t src) {
	assert(sizeof(IPv6_addr) == 16); // make sure we do not add any overhead to this class
	// filling ipv6 address with 0s
	fill_n(begin(), 10, 0); // 80 bits / 8 bits/Byte = 10 Byte
	// and 1s
	fill_n(begin() + 10, 2, 0xff); // 16 bits / 8 bits/Byte = 2 Byte
	// last 4 bytes contain the ipv4 address
	uint32_t src_networkorder = htonl(src);
	memcpy(begin() + 12, &src_networkorder, sizeof(src_networkorder));
}

/**
 *	Constructor: from boost::array.
 *
 *	\param src boost::array representing the IP address in network byte order.
 */
IPv6_addr::IPv6_addr(const boost::array<unsigned char, 16> & src) {
	assert(sizeof(IPv6_addr) == 16); // make sure we do not add any overhead to this class
	copy(src.begin(), src.end(), this->begin());
}

/**
 *	Implements the assign operator
 *
 *	\param other IP address to assign
 *
 *	\return IPv6_addr Reference to this object
 */
IPv6_addr & IPv6_addr::operator=(const IPv6_addr & other) {
	std::copy(other.begin(), other.end(), begin());
	return *this;
}

/**
 *	Returns a string representation of this IP address
 *
 *	\return string String representation of this IP address
 */
std::string IPv6_addr::toString() const {
	char buf[INET6_ADDRSTRLEN]; // Buffer for inet_ntop
	inet_ntop(AF_INET6, this, buf, sizeof(buf));
	string IP(buf); // Contains the final string representation of this IP

	if (!isIPv6()) {
		size_t pos = IP.rfind(":");
		IP.replace(0, pos + 1, ""); // Remove all the :
	}
	return IP;
}

/**
 *	Writes this IP address to an ostream
 *
 *	\param os Reference to the ostream we should write to
 */
void IPv6_addr::print(ostream& os) const {
	os << toString();
}

/**
 *	Implements insertion operator
 *
 *	\param os Reference to the ostream we should write to
 *	\param ip IP address to be written to the ostream
 *
 *	\return ostream Reference to the submitted ostream
 */
std::ostream & operator<<(std::ostream & os, const IPv6_addr & ip) {
	ip.print(os);
	return os;
}

/**
 *	Implements the bitwise AND operator
 *
 *	\param other Reference to the other IP address
 *
 *	\return IPv6_addr Resulting IP address
 */
IPv6_addr IPv6_addr::operator &(const IPv6_addr & other) {
	IPv6_addr result;
	for (uint32_t i = 0; i < size(); i++) {
		result[i] = (*this)[i] & other[i];
	}
	return result;
}


/**
 *	Implements the less operator
 *
 *	\param other Reference the the IP address which we should compare to
 *
 *	\return bool True if this is smaller than other
 */
bool IPv6_addr::operator<(const IPv6_addr & other) const {
	for(unsigned int i = 0; i < sizeof(IPv6_addr); i++ ) {
		if((*this)[i] < other[i])
			return true;
		if((*this)[i] > other[i])
			return false;
	}
	return false;
}


/**
 *	Implements the equals operator
 *
 *	\param other Reference the the IP address which we should compare to
 *
 *	\return bool True if both addresses are the same, false if not
 */
bool IPv6_addr::operator==(const IPv6_addr & other) const {
	return equal(this->begin(), this->end(), other.begin());
}

/**
 *	Implements the not-equals operator
 *
 *	\param other Reference the the IP address which we should compare to
 *
 *	\return bool false if both addresses are the same, true if not
 */
bool IPv6_addr::operator!=(const IPv6_addr & other) const {
	return !(*this == other);
}

/**
 *	Checks if this IP is an IPv6 address
 *
 *	\return bool True if the address is a IPv6 address, false if it is an IPv4 address
 */
bool IPv6_addr::isIPv6() const {
	if ((*this)[0] == 0x00 && (*this)[1] == 0x00 && (*this)[2] == 0x00 && (*this)[3] == 0x00 && (*this)[4] == 0x00 && (*this)[5] == 0x00 && (*this)[6] == 0x00
	      && (*this)[7] == 0x00 && (*this)[8] == 0x00 && (*this)[9] == 0x00 && (*this)[10] == 0xff && (*this)[11] == 0xff) {
		return false;
	}
	return true;
}

/**
 *
 * @return
 */
std::string IPv6_addr::toNumericString() const {
	std::stringstream ss;
	ss << (*((uint64_t*) begin())) << (*((uint64_t*) (begin() + sizeof(uint64_t))));
	return ss.str();
}

/**
 *	Checks if this IP is an IPv4 address
 *
 *	\return bool True if the address is a IPv4 address, false if it is an IPv6 address
 */
bool IPv6_addr::isIPv4() const {
	return !isIPv6();
}

/**
 * Generates a 24 bit hash from the ipv6 address
 *
 * \return uint32_t first 24 bits contain the hash code, the last 8 bits are set to 0
 *
 * \exception std::sring Errormessage
 */
uint32_t IPv6_addr::get24bitHash() const {
	long hash = partial_ip_hasher(*((uint32_t*) begin())); // hashes the first 32 bits
	hash += partial_ip_hasher(*((uint32_t*) (begin() + 1 * sizeof(uint32_t)))); // hashes the next 32 bits
	hash += partial_ip_hasher(*((uint32_t*) (begin() + 2 * sizeof(uint32_t)))); // hashes the next 32 bits
	hash += partial_ip_hasher(*((uint32_t*) (begin() + 3 *sizeof(uint32_t)))); // hashes the next 32 bits
	return hash & 0xffffff;
}

/**
 * Generate a bitmask for the given prefix
 *
 * \return IPv6_addr IP with the first prefix bits set to 1
 *
 * \exception std::string Errormessage
 */
IPv6_addr IPv6_addr::getNetmask(const uint8_t prefix) {
	if (prefix == 0 || prefix > 128) {
		stringstream errormsg;
		errormsg << "ERROR: invalid prefix value: (" << prefix << "). ";
		errormsg << "Valid prefix lengths are 1..128. For monitoring a single host use 128.";
		throw errormsg.str();
	}
	IPv6_addr netmask; // all bits are set to 0
	uint8_t complete_bytes = prefix / 8;
	uint8_t additional_bits = prefix % 8;
	fill_n(netmask.begin(), complete_bytes, numeric_limits<unsigned char>::max());
	if (additional_bits) {
		*(netmask.begin() + complete_bytes + 1) = (char) (1 << (additional_bits - 1));
	}
	return netmask;
}
