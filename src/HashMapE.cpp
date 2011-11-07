/**
 *	\file HashMapE.cpp
 *
 *	Extends HashMap.h with specialized classes.
 */
#include <string.h>
#include <stdio.h>
#include <sys/socket.h>
#include <assert.h>
#include <boost/array.hpp>
#include <algorithm>
#include <sstream>

#include "HashMapE.h"

#include "gutil.h"

/* *************************************************************
 * Key type HashKeyIPv6: IPv6Pair key                          *
 * *************************************************************/

HashKeyIPv6Pair::HashKeyIPv6Pair(const IPv6_addr & ip1, const IPv6_addr & ip2) {
	std::copy(ip1.begin(), ip1.end(), key.begin());
	std::copy(ip2.begin(), ip2.end(), key.begin() + sizeof(ip1));
}

CHashKey6_6::CHashKey6_6(const uint64_t val1, const IPv6_addr & val2) {
	std::fill(key.begin(), key.end(), 0);
	memcpy(key.begin(), &val1, sizeof(uint64_t));
	memcpy(key.begin() + 16, val2.begin(), sizeof(IPv6_addr));
}

CHashKey6_6::CHashKey6_6(const uint32_t val1, const uint32_t val2) {
	// |4 bytes: val1|12 bytes: 0|4 bytes: val2|12 bytes: 0|
	std::fill(key.begin(), key.end(), 0);
	memcpy(key.begin(), &val1, sizeof(uint32_t));
	memcpy(key.begin() + 16, &val2, sizeof(uint32_t));
}

CHashKey6_6::CHashKey6_6(const uint64_t val1, const uint64_t val2) {
	std::fill(key.begin(), key.end(), 0);
	memcpy(key.begin(), &val1, sizeof(uint64_t));
	memcpy(key.begin() + 16, &val2, sizeof(uint64_t));
}

HashKeyIPv6Pair::HashKeyIPv6Pair(const HashKeyIPv6Pair& b) {
	key = b.key;
}

HashKeyIPv6Pair::~HashKeyIPv6Pair() {
	// nothing to do in here
}

size_t HashKeyIPv6Pair::size() const {
	return key.size();
}

const HashKeyIPv6Pair::key_type & HashKeyIPv6Pair::getkey() const {
	return key;
}

std::string HashKeyIPv6Pair::printkey() const {
	char tmpip1[INET6_ADDRSTRLEN];
	char tmpip2[INET6_ADDRSTRLEN];
	std::stringstream ss;
	ss << tmpip1;
	ss << " ";
	ss << tmpip2;
	return ss.str();
}

/* *************************************************************
 * Key type HashKeyIPv6_3T: IPv6 Three-Tuple key               *
 * *************************************************************/

HashKeyIPv6_3T::HashKeyIPv6_3T(const IPv6_addr & IP, const uint8_t & protocol, const uint16_t & port) {
	std::copy(IP.begin(), IP.end(), key.begin());
	key[16] = protocol;
	memcpy(&(key[17]), &port, 2);
//	*((uint32_t *)(&(key[0]))) = *IP;
//	*((uint8_t *)(&(key[4]))) = *protocol;
//	*((uint16_t *)(&(key[5]))) = *port;
}

HashKeyIPv6_3T::~HashKeyIPv6_3T() {
	// nothing to do in here
}

size_t HashKeyIPv6_3T::size() const {
	return key.size();
}

HashKeyIPv6_3T::HashKeyIPv6_3T(const HashKeyIPv6_3T &b) {
	key = b.key;
}

const HashKeyIPv6_3T::key_type & HashKeyIPv6_3T::getkey() const {
	return key;
}

std::string HashKeyIPv6_3T::printkey() const {
	IPv6_addr addr(0);
	std::copy(key.begin(), key.begin()+sizeof(IPv6_addr), addr.begin());
	uint8_t protocol = key[16];
	uint16_t port;
	memcpy(&port, &(key[17]), sizeof(uint16_t));
	std::stringstream ss;
	ss << "ip: ";
	ss << addr;
	ss << " proto: ";
	ss << (int)protocol;
	ss << " port: ";
	ss << port;
	return ss.str();
}

/* *************************************************************
 * Key type HashKeyIPv6_4T: IPv6 Four-Tuple key                *
 * *************************************************************/

HashKeyIPv6_4T::HashKeyIPv6_4T(const IPv6_addr & IP, const uint8_t & protocol, const uint16_t & port, const uint8_t & flowtype) {
	std::copy(IP.begin(), IP.end(), key.begin());
	memcpy(key.begin() + 16, &protocol, 1);
	memcpy(key.begin() + 17, &port, 2);
	memcpy(key.begin() + 19, &flowtype, 1);
}

HashKeyIPv6_4T::~HashKeyIPv6_4T() {
	// nothing to do in here
}

size_t HashKeyIPv6_4T::size() const {
	return key.size();
}

HashKeyIPv6_4T::HashKeyIPv6_4T(const HashKeyIPv6_4T &b) {
//	memcpy(key, b.key, 8);
	key = b.key;
}

const HashKeyIPv6_4T::key_type & HashKeyIPv6_4T::getkey() const {
	return key;
}

std::string HashKeyIPv6_4T::printkey() const {
	IPv6_addr ip;
	uint8_t protocol;
	uint16_t port;
	uint8_t flowtype;
	std::copy(key.begin(), key.begin()+sizeof(IPv6_addr), ip.begin());
	memcpy(&protocol, key.begin() + 16, sizeof(uint8_t));
	memcpy(&port, key.begin() + 17, sizeof(uint16_t));
	memcpy(&flowtype, key.begin() + 19, sizeof(uint8_t));

	std::stringstream ss;
	ss << "ip: ";
	ss << ip;
	ss << "proto: ";
	ss << (int)protocol;
	ss << "port: ";
	ss << port;
	ss << "flowtype: ";
	ss << (int)flowtype;
	return ss.str();
}

/* *************************************************************
 * Key type HashKeyIPv6_5T_2: IPv6 Five-Tuple key                *
 * *************************************************************/

HashKeyIPv6_5T_2::HashKeyIPv6_5T_2(const IPv6_addr & localIP, const IPv6_addr & remoteIP, const uint8_t & protocol, const uint16_t & port, const uint8_t & flowtype) {
	std::copy(localIP.begin(), localIP.end(), key.begin());
	std::copy(remoteIP.begin(), remoteIP.end(), key.begin() + sizeof(IPv6_addr));
	memcpy(key.begin() + sizeof(IPv6_addr) + sizeof(IPv6_addr), &protocol, sizeof(uint8_t));
	memcpy(key.begin() + sizeof(uint8_t) + sizeof(IPv6_addr) + sizeof(IPv6_addr), &port, sizeof(uint16_t));
	memcpy(key.begin() + sizeof(uint16_t) + sizeof(uint8_t) + sizeof(IPv6_addr) + sizeof(IPv6_addr), &flowtype, sizeof(uint8_t));
}

HashKeyIPv6_5T_2::~HashKeyIPv6_5T_2() {
	// nothing to do in here
}

size_t HashKeyIPv6_5T_2::size() const {
	return key.size();
}

HashKeyIPv6_5T_2::HashKeyIPv6_5T_2(const HashKeyIPv6_5T_2 &b) {
	key = b.key;
}

const HashKeyIPv6_5T_2::key_type & HashKeyIPv6_5T_2::getkey() const {
	return key;
}

std::string HashKeyIPv6_5T_2::printkey() const {
	IPv6_addr localip;
	IPv6_addr remoteip;
	uint8_t protocol;
	uint16_t port;
	uint8_t flowtype;
	std::copy(key.begin(), key.begin() + sizeof(IPv6_addr), localip.begin());
	std::copy(key.begin() + sizeof(IPv6_addr), key.begin() + sizeof(IPv6_addr) + sizeof(IPv6_addr), remoteip.begin());
	memcpy(&protocol, key.begin() + sizeof(IPv6_addr) + sizeof(IPv6_addr), sizeof(uint8_t));
	memcpy(&port, key.begin() + sizeof(uint8_t) + sizeof(IPv6_addr) + sizeof(IPv6_addr), sizeof(uint16_t));
	memcpy(&flowtype, key.begin() + sizeof(uint16_t) + sizeof(uint8_t) + sizeof(IPv6_addr) + sizeof(IPv6_addr), sizeof(uint8_t));

	std::stringstream ss;
	ss << "local_ip: ";
	ss << localip;
	ss << " remote_ip: ";
	ss << remoteip;
	ss << "proto: ";
	ss << (int)protocol;
	ss << "port: ";
	ss << port;
	ss << "flowtype: ";
	ss << (int)flowtype;
	return ss.str();
}

/* *************************************************************
 * Key type HashKeyIPv6_5T: IPv6 Five-Tuple key                *
 * *************************************************************/

HashKeyIPv6_5T::HashKeyIPv6_5T(const IPv6_addr & srcIP, const IPv6_addr & dstIP, const uint16_t & srcPort, const uint16_t & dstPort, const uint8_t & protocol) {
	std::copy(srcIP.begin(), srcIP.end(), key.begin());
	std::copy(dstIP.begin(), dstIP.end(), key.begin() + 16);
	memcpy(key.begin() + 32, &srcPort, 2);
	memcpy(key.begin() + 34, &dstPort, 2);
	memcpy(key.begin() + 36, &protocol, 1);

//	*((uint32_t *)(&(key[0]))) = *srcIP;
//	*((uint32_t *)(&(key[4]))) = *dstIP;
//	*((uint16_t *)(&(key[8]))) = *srcPort;
//	*((uint16_t *)(&(key[10]))) = *dstPort;
//	*((uint8_t *)(&(key[12]))) = *protocol;

}

HashKeyIPv6_5T::~HashKeyIPv6_5T() {
	// nothing to do in here
}

size_t HashKeyIPv6_5T::size() const {
	return key.size();
}

HashKeyIPv6_5T::HashKeyIPv6_5T(const HashKeyIPv6_5T &b) {
	key = b.key;
}

const HashKeyIPv6_5T::key_type & HashKeyIPv6_5T::getkey() const {
	return key;
}

std::string HashKeyIPv6_5T::printkey() const {
	char buf[128];
	char tmpip_src[INET6_ADDRSTRLEN];
	char tmpip_dst[INET6_ADDRSTRLEN];
	inet_ntop(AF_INET6, &key, tmpip_src, sizeof(tmpip_src));
	inet_ntop(AF_INET6, &key + 16, tmpip_dst, sizeof(tmpip_dst));
	sprintf(buf, "%u - %s:%u %s:%u", *((uint8_t *) (&(key[12]))), tmpip_src, *((uint16_t *) (&(key[8]))), tmpip_dst, *((uint16_t *) (&(key[10]))));
	return std::string(buf);
}

/* *************************************************************
 * Key type HashKeyIPv6_7T: IPv6 Seven-Tuple key               *
 * *************************************************************/

HashKeyIPv6_7T::HashKeyIPv6_7T(const IPv6_addr & srcIP, const IPv6_addr & dstIP, const uint16_t & srcPort, const uint16_t & dstPort, const uint8_t & protocol,
      const uint8_t & tos, const uint8_t & dir) {
	std::copy(srcIP.begin(), srcIP.end(), key.begin());
	std::copy(dstIP.begin(), dstIP.end(), key.begin() + 16);
	memcpy(key.begin() + 32, &srcPort, 2);
	memcpy(key.begin() + 34, &dstPort, 2);
	memcpy(key.begin() + 36, &protocol, 1);
	memcpy(key.begin() + 37, &tos, 1);
	memcpy(key.begin() + 38, &dir, 1);

//	*((uint32_t *)(&(key[0]))) = *srcIP;
//	*((uint32_t *)(&(key[4]))) = *dstIP;
//	*((uint16_t *)(&(key[8]))) = *srcPort;
//	*((uint16_t *)(&(key[10]))) = *dstPort;
//	*((uint8_t *)(&(key[12]))) = *protocol;
//	*((uint8_t *)(&(key[13]))) = *tos;
//	*((uint8_t *)(&(key[14]))) = *dir;
}

HashKeyIPv6_7T::~HashKeyIPv6_7T() {
	// nothing to do in here
}

size_t HashKeyIPv6_7T::size() const {
	return key.size();
}

HashKeyIPv6_7T::HashKeyIPv6_7T(const HashKeyIPv6_7T &b) {
	key = b.key;
}

const HashKeyIPv6_7T::key_type & HashKeyIPv6_7T::getkey() const {
	return key;
}

std::string HashKeyIPv6_7T::printkey() const {
	char buf[128];
	char tmpip_src[INET6_ADDRSTRLEN];
	char tmpip_dst[INET6_ADDRSTRLEN];
	inet_ntop(AF_INET6, &key, tmpip_src, sizeof(tmpip_src));
	inet_ntop(AF_INET6, &(key[16]), tmpip_dst, sizeof(tmpip_dst));
	sprintf(buf, "%u - %s:%u %s:%u (%u) (%u)", *((uint8_t *) (&(key[12]))), tmpip_src, *((uint16_t *) (&(key[8]))), tmpip_dst, *((uint16_t *) (&(key[10]))),
	      *((uint8_t *) (&(key[13]))), *((uint8_t *) (&(key[14]))));
	return std::string(buf);
}

/* *************************************************************
 * Key type CHashKey4_4: 4 byte - 4 byte                       *
 * *************************************************************/

CHashKey6_6::CHashKey6_6(const IPv6_addr & val1, const IPv6_addr & val2) {
	std::copy(val1.begin(), val1.end(), key.begin());
	std::copy(val2.begin(), val2.end(), key.begin() + 16);
}

CHashKey6_6::CHashKey6_6(const IPv6_addr & val1, const uint64_t val2) {
	std::fill(key.begin(), key.end(), 0);
	std::copy(val1.begin(), val1.end(), key.begin());
	memcpy(key.begin() + 16, &val2, sizeof(uint64_t));
}

CHashKey6_6::~CHashKey6_6() {
	// nothing to do in here
}

size_t CHashKey6_6::size() const {
	return key.size();
}

const CHashKey6_6::key_type & CHashKey6_6::getkey() const {
	return key;
}

CHashKey6_6::CHashKey6_6(const CHashKey6_6 &b) {
	key = b.key;
}

std::string CHashKey6_6::printkey() const {
	return util::bin2hexstring(&(key[0]), sizeof(key));;
}

/* *************************************************************
 * Key type CHashKey8: 8 tuple of 16 bit values                *
 * *************************************************************/

CHashKey8::CHashKey8(const boost::array<uint16_t, 8> & val) {
	*((int16_t *) (&(key[0]))) = val[0];
	*((int16_t *) (&(key[2]))) = val[1];
	*((int16_t *) (&(key[4]))) = val[2];
	*((int16_t *) (&(key[6]))) = val[3];
	*((int16_t *) (&(key[8]))) = val[4];
	*((int16_t *) (&(key[10]))) = val[5];
	*((int16_t *) (&(key[12]))) = val[6];
	*((int16_t *) (&(key[14]))) = val[7];
}

CHashKey8::~CHashKey8() {
	// nothing to do in here
}

size_t CHashKey8::size() const {
	return key.size();
}

const CHashKey8::key_type & CHashKey8::getkey() const {
	return key;
}

CHashKey8::CHashKey8(const CHashKey8 &b) {
	//memcpy(key, b.key, 16);
	key = b.key;
}

std::string CHashKey8::printkey() const {
	char buf[128];
	sprintf(buf, "%u - %u - %u - %u - %u - %u - %u - %u ", *((int16_t *) (&(key[0]))), *((int16_t *) (&(key[2]))), *((int16_t *) (&(key[4]))),
	      *((int16_t *) (&(key[6]))), *((int16_t *) (&(key[8]))), *((int16_t *) (&(key[10]))), *((int16_t *) (&(key[12]))), *((int16_t *) (&(key[14]))));
	return std::string(buf);
}

const boost::array<uint16_t, 8> CHashKey8::getRoles() const {
	boost::array<uint16_t, 8> roles;
	memcpy(roles.begin(), key.begin(), sizeof(boost::array<uint16_t, 8>));
	/*
	 roles[0] = (key[0]<<16)+key[1];
	 roles[1] = (key[2]<<16)+key[3];
	 roles[2] = (key[4]<<16)+key[5];
	 roles[3] = (key[6]<<16)+key[7];
	 roles[4] = (key[8]<<16)+key[9];
	 roles[5] = (key[10]<<16)+key[11];
	 roles[6] = (key[12]<<16)+key[13];
	 roles[7] = (key[14]<<16)+key[15];
	 */
	return roles;
}
