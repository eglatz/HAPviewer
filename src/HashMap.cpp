/** \file HashMap.cpp
 * \brief HashMap implementation file
 * 
 * Copyright (c) 2008, Bernhard Tellenbach 
 *
 * Author: Bernhard Tellenbach  (bernhard.tellenbach@gmail.com) 
 * 
 * Distributed under the Gnu Public License version 2 or the modified
 * BSD license (see file COPYING
 *
 */
#include <stdio.h>
#include <cstring>
#include <sys/socket.h>

#include "HashMap.h"

using namespace std;
using namespace __gnu_cxx;

/* *************************************************************
 * Key type HashKeyGeneric: Arbitrary lengt key (slow)         *
 * *************************************************************/

HashKeyGeneric::HashKeyGeneric(char* buf, uint8_t len) {
	key = NULL;
	length = len;
	key = new char[length];
	memcpy(key, buf, length);
}

HashKeyGeneric::~HashKeyGeneric() {
	delete[] key;
}

size_t HashKeyGeneric::size() const {
	return length;
}

HashKeyGeneric::HashKeyGeneric(const HashKeyGeneric &b) {
	key = new char[b.length];
	memcpy(key, b.key, b.length);
	length = b.length;
}

std::string HashKeyGeneric::printkey() const {
	char buf[length * 4 + 1];for(unsigned int i = 0; i< length; i++) {
		sprintf(&(buf[i*4]),"0x%02ix", key[i]);
	}
	return std::string(buf);
}

/* *************************************************************
 * Key type HashKeyIPv4: IPv4 key                              *
 * *************************************************************/

HashKeyProtoFlowtype::HashKeyProtoFlowtype(const uint8_t proto, const uint8_t flowtype) {
	key[0] = proto;
	key[1] = flowtype;
}

HashKeyProtoFlowtype::~HashKeyProtoFlowtype() {
	// nothing to do in here
}

size_t HashKeyProtoFlowtype::size() const {
	return key.size();
}

HashKeyProtoFlowtype::HashKeyProtoFlowtype(const HashKeyProtoFlowtype & b) {
	copy(b.key.begin(), b.key.end(), key.begin());
}

const HashKeyProtoFlowtype::key_type & HashKeyProtoFlowtype::getkey() const {
	return key;
}

std::string HashKeyProtoFlowtype::printkey() const {
	char tmpip[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, key.begin(), tmpip, sizeof(tmpip));
	return std::string(tmpip);
}

/* *************************************************************
 * Key type HashKeyIPv6: IPv6 key                              *
 * *************************************************************/

HashKeyIPv6::HashKeyIPv6(const IPv6_addr & ip) {
	key = ip;
}

HashKeyIPv6::~HashKeyIPv6() {
	// nothing to do in here
}

size_t HashKeyIPv6::size() const {
	return key.size();
}

const IPv6_addr & HashKeyIPv6::getkey() const {
	return key;
}

HashKeyIPv6::HashKeyIPv6(const HashKeyIPv6 & b) {
	key = b.getkey();
}
