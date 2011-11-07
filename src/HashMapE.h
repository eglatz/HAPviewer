/**
 *	\file HashMapE.h
 *
 *	Extends HashMap.h with specialized classes.
 */

#ifndef HASHMAPE_H_
#define HASHMAPE_H_

#include <arpa/inet.h>
#include <string>
#include <boost/array.hpp>
#include <ext/hash_map>

#include "lookup3.h"
#include "HashMap.h"
#include "cflow.h"

using namespace __gnu_cxx;

/* *************************************************************
 * Key type HashKeyIPv6Pair: IPv6Pair key                      *
 * *************************************************************/

/**
 *	\class HashKeyIPv6Pair
 *	\brief Hash Key for IPv6 address pairs. The length is fixed to 32 bytes.
 *
 */
class HashKeyIPv6Pair {
public:
	/**
	 * Constructor.
	 * \param ip1 the first IPv6 address
	 * \param ip2 the second IPv6 address
	 */
	typedef boost::array<char, 32> key_type;

	HashKeyIPv6Pair(const IPv6_addr & ip1, const IPv6_addr & ip2);
	~HashKeyIPv6Pair();
	size_t size() const;
	HashKeyIPv6Pair(const HashKeyIPv6Pair & b);
	const key_type & getkey() const;
	std::string printkey() const;

protected:
	key_type key;
};

/* *************************************************************
 * Key type HashKeyIPv6_3T: IPv6 Three-Tuple key               *
 * *************************************************************/

/**
 *	\class HashKeyIPv6_3T
 *	\brief Hash Key for 3-tuple [IP, potocol, port]. IP addresses are v6 (128 bits).
 *	The size of the key amounts to 19 bytes.
 */
class HashKeyIPv6_3T {
public:
	/**
	 * Constructor.
	 * \param IP IP address
	 * \param protocol protocol number (e.g. 6=tcp, 17=UDP)
	 * \param port port
	 */
	typedef boost::array<char, 19> key_type;

	HashKeyIPv6_3T(const IPv6_addr & IP, const uint8_t & protocol, const uint16_t & port);
	HashKeyIPv6_3T(const HashKeyIPv6_3T &b);
	~HashKeyIPv6_3T();
	size_t size() const;
	const key_type & getkey() const;
	std::string printkey() const;

protected:
	key_type key;
};

/* *************************************************************
 * Key type HashKeyIPv6_4T: IPv6 Four-Tuple key                *
 * *************************************************************/

/**
 *	\class HashKeyIPv6_4T
 *	\brief Hash Key for 4-tuple [IP, protocol, port, flowtype]. IP addresses are v6 (128 bits).
 *	The size of the key amounts to 20 bytes.
 */
class HashKeyIPv6_4T {
public:
	/**
	 * Constructor.
	 * \param IP IP address
	 * \param protocol protocol number (e.g. 6=tcp, 17=UDP)
	 * \param port port
	 * \param flowtype flow direction type
	 */
	typedef boost::array<char, 20> key_type;

	HashKeyIPv6_4T(const IPv6_addr & IP, const uint8_t & protocol, const uint16_t & port, const uint8_t & flowtype);
	HashKeyIPv6_4T(const HashKeyIPv6_4T &b);
	~HashKeyIPv6_4T();
	size_t size() const;
	const key_type & getkey() const;
	std::string printkey() const;

protected:
	key_type key;

};

/* *************************************************************
 * Key type HashKeyIPv6_5T: IPv6 Five-Tuple key                *
 * *************************************************************/

/**
 *	\class HashKeyIPv6_5T
 *	\brief Hash Key for t-tuples [srcIP, dstIP, srcPort, dstPort, protocol]. IP addresses are v6 (128 bits).
 *	The size of the key amounts to 37 bytes.
 */
class HashKeyIPv6_5T {
public:

	/**
	 * Constructor.
	 * \param srcIP source IP address
	 * \param dstIP destination IP address
	 * \param srcPort source port
	 * \param dstPort destination port
	 * \param protocol protocol number (e.g. 6=tcp, 17=UDP)
	 */
	typedef boost::array<char, 37> key_type;

	HashKeyIPv6_5T(const IPv6_addr & srcIP, const IPv6_addr & dstIP, const uint16_t & srcPort, const uint16_t & dstPort, const uint8_t & protocol);
	HashKeyIPv6_5T(const HashKeyIPv6_5T &b);
	~HashKeyIPv6_5T();
	size_t size() const;
	const key_type & getkey() const;
	std::string printkey() const;

protected:
	key_type key;
};

/* *************************************************************
 * Key type HashKeyIPv6_5T_2: IPv6 five-Tuple key                *
 * *************************************************************/

/**
 *	\class HashKeyIPv6_5T_2
 *	\brief Hash Key for 5-tuple [localIP, remoteIP, protocol, port, flowtype]. IP addresses are v6 (128 bits).
 *	The size of the key amounts to 36 bytes.
 */
class HashKeyIPv6_5T_2 {
public:
	/**
	 * Constructor.
	 * \param localIP local IP address
	 * \param remoteIP remote IP address
	 * \param protocol protocol number (e.g. 6=tcp, 17=UDP)
	 * \param port port
	 * \param flowtype flow direction type
	 */
	typedef boost::array<char, 37> key_type;

	HashKeyIPv6_5T_2(const IPv6_addr & localIP, const IPv6_addr & remoteIP, const uint8_t & protocol, const uint16_t & port, const uint8_t & flowtype);
	HashKeyIPv6_5T_2(const HashKeyIPv6_5T_2 &b);
	~HashKeyIPv6_5T_2();
	size_t size() const;
	const key_type & getkey() const;
	std::string printkey() const;

protected:
	key_type key;

};

/* *************************************************************
 * Key type HashKeyIPv6_5T: IPv6 Seven-Tuple key               *
 * *************************************************************/

/**
 *	\class HashKeyIPv6_7T
 *	\brief Hash Key for 7-tuples [srcIP, dstIP, srcPort, dstPort, protocol, TOS, direction]. IP addresses are v6 (128 bits).
 *	The size of the key amounts to 39 bytes.
 */
class HashKeyIPv6_7T {
public:
	/**
	 * Constructor.
	 * \param srcIP source IP address
	 * \param dstIP destination IP address
	 * \param srcPort source port
	 * \param dstPort destination port
	 * \param protocol protocol number (e.g. 6=tcp, 17=UDP)
	 * \param tos TOS field (Type Of Service)
	 * \param dir Direction field
	 */
	typedef boost::array<char, 39> key_type;

	HashKeyIPv6_7T(const IPv6_addr & srcIP, const IPv6_addr & dstIP, const uint16_t & srcPort, const uint16_t & dstPort, const uint8_t & protocol,
	      const uint8_t & tos, const uint8_t & dir);
	HashKeyIPv6_7T(const HashKeyIPv6_7T &b);
	~HashKeyIPv6_7T();
	size_t size() const;
	const key_type & getkey() const;
	std::string printkey() const;

protected:
	key_type key;
};

/* *************************************************************
 * Key type CHashKey4_4: 2-tuples of 32 bit values             *
 * *************************************************************/

/**
 *	\class CHashKey4_4
 *	\brief Hash key for pair uint32_t, uint32_t (val1, val2).
 *
 */
class CHashKey6_6 {
public:
	typedef boost::array<char, 32> key_type;

	CHashKey6_6(const IPv6_addr & val1, const IPv6_addr & val2);
	CHashKey6_6(const IPv6_addr & val1, const uint64_t val2);
	CHashKey6_6(const uint64_t val1, const IPv6_addr & val2);
	CHashKey6_6(const uint32_t val1, const uint32_t val2);
	CHashKey6_6(const uint64_t val1, const uint64_t val2);
	CHashKey6_6(const CHashKey6_6 &b);
	~CHashKey6_6();
	size_t size() const;
	const key_type & getkey() const;
	std::string printkey() const;

protected:
	key_type key;
};

/* *************************************************************
 * Key type CHashKey8: 8 tuple of 16 bit values                *
 * *************************************************************/

/**
 *	\class CHashKey8
 *	\brief Hash key for eight numbers of 16 bit size.
 *
 */
class CHashKey8 {
public:
	typedef boost::array<char, 16> key_type;

	CHashKey8(const CHashKey8 & b);
	CHashKey8(const boost::array<uint16_t, 8> & val);
	~CHashKey8();
	size_t size() const;
	const boost::array<uint16_t, 8> getRoles() const;
	const key_type & getkey() const;
	std::string printkey() const;

protected:
	key_type key;
};

#endif /* HASHMAPE_H_ */
