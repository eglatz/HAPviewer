/**
 *	\file IPv6_addr.h
 *	\brief Internally used class to store IP addresses (v4 and v6)
 */

#ifndef IPV6_ADDR_H_
#define IPV6_ADDR_H_

#include <boost/array.hpp>
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <stdint.h>
#include <fstream>
#include <string>
#include <boost/functional/hash.hpp>

class IPv6_addr: public boost::array<unsigned char, 16> {
	public:
		// Default constructor, initializes with zeros
		IPv6_addr();
		// For compatibility reasons: Takes a plain boost::array, remove later
		IPv6_addr(const boost::array<unsigned char, 16> & src);
		// Takes the systems representation of an IPv6 address to initialize our own
		IPv6_addr(const in6_addr & src);
		// Takes a string representation of a IP address, works for IPv6 as well as for IPv4
		IPv6_addr(std::string IP_str);
		// Takes a IPv4 (uint32_t value) and converts it into an IPv6 address
		explicit IPv6_addr(uint32_t ipv4);
		// Returns a string representation of our IP address
		std::string toString() const;
		bool isIPv6() const;
		bool isIPv4() const;
		void print(std::ostream& os) const;
		IPv6_addr & operator=(const IPv6_addr & other);
		bool operator==(const IPv6_addr & other) const;
		bool operator<(const IPv6_addr & other) const;
		bool operator!=(const IPv6_addr & other) const;
		IPv6_addr operator &(const IPv6_addr & other);

		std::string toNumericString() const;
		uint32_t get24bitHash() const;
		static IPv6_addr getNetmask(const uint8_t prefix);

		const static std::string ipRegex;
		const static boost::hash<uint32_t> partial_ip_hasher;
};

std::ostream & operator<<(std::ostream& os, const IPv6_addr & ip);

#endif /* IPV6_ADDR_H_ */
