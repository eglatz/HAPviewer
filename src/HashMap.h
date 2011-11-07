#ifndef HASHMAP_H_
#define HASHMAP_H_

/** 
 * \file HashMap.h
 * \brief Header file that defines keys and hashfunction for use with the SGI hash_map
 * 
 * Copyright (c) 2008, Bernhard Tellenbach 
 *
 * Author: Bernhard Tellenbach  (bernhard.tellenbach@gmail.com) 
 * 
 * 
 *\section general_hmap General Remarks on the SGI hash_map
 * Pros of the SGI hash_map vs. the NetflowVxPlusPlus HashedTable:
 *  - Interface to hash_map objects is the same as the interface to STL map Objects
 *  - Deletion of elements while iterating over the elements requires no special treatment
 *  - Faster, if the size of the hash table is not known or if it grows/shrinks many times during operation
 *  - Template based. No typecasts required to read elements. Type specified during construction.
 *
 * <br>Cons of the SGI hash_map vs. the NetflowVxPlusPlus HashedTable:
 * - If there is a need for a generic key (of arbitrary length), the hash_map can be slower than the HashedTable.
 *
 * <b> WARNING: </b> Even though it is possible to define the element type to be of non-pointer type, this should not be
 * used unless your element type is a basic number type (int, long,...). The reason is, that an insert operation makes
 * <b> a copy </b> of the element (if it is a pointer type, it just makes a copy of the pointer!). Therefore, if your
 * element size is bigger than a pointer (more than 4 (32-bit system) or 8 (64-bit system) bytes), you would introduce
 * memory copy-overhead! However, using pointer types is less comfortable than using non-pointer types because the 
 * hash_map would take care of the deletion of the elements. If you use pointer types, you have to delete the elements YOURSELF!
 * (see example code).
 * 
 * \section hmap_hashkeys Custom Hash Key Types
 * If you need key types other than those already specified in this header file, and if you do not want to use the 
 * HashKeyGeneric because of its performance penalty, you can create your own key type. This is straight forward since
 * the only thing that your new Key Class has to do is to implement the following interface (see one of the key types already defined in this header file as example):
 *
 * \section specific_hmap Examples
 * - <b>Example 1: </b>  Creation, use and deletion of a hash_map with entries of type 'unsigned long long' (basic number type) and HashKeyIPv4Addr keys.
 * \code 
 #include "HashMap.h"
 #include <iostream>
 #include <sys/types.h>

 #define NUM_ELEMENTS  10000000

 using namespace std;

 typedef HashKeyIPv4_6T MyHashKey;
 typedef hash_map<HashKeyIPv4_6T, uint32_t , HashFunction<HashKeyIPv4_6T>,HashFunction<HashKeyIPv4_6T> > HashMap;

 int main() {
 uint32_t dstAddr = 0;
 uint16_t dstPort = 0;
 uint16_t srcPort = 0;
 uint8_t protocol = 0;
 uint8_t tos = 0;

 try{

 //insert NUM_ELEMENTS. Key is 'counting' source address and other key fields set to zero
 HashMap * myHashMap = new HashMap();
 for (uint32_t i = 0; i< NUM_ELEMENTS;i++){
 MyHashKey mykey(&i, &dstAddr, &srcPort, &dstPort, &protocol, &tos);
 (*myHashMap)[mykey]=i;
 }

 //searching for elements (here, we search for all inserted elements!)	
 HashMap::iterator iter;
 uint32_t found = 0;
 for (uint32_t i = 0; i < NUM_ELEMENTS; i++) {
 MyHashKey mykey(&i, &dstAddr, &srcPort, &dstPort, &protocol, &tos);
 iter = myHashMap->find(mykey);
 if(iter!=myHashMap->end()){
 //access and print the key:
 //  cout << (iter->first).printkey() << "\n";
 //access the element: 
 //   cout << "Stored uint32_t value is:"<< (iter->second) << "\n";
 found++;
 }
 }
 if(found != NUM_ELEMENTS){
 throw("ERROR: Not all inserted elements found! Aborting....\n");
 }

 //deleting elements while iterating over the hash table
 //NOTE 1: Elements are of basic non-pointer type. The memory used is 
 //        automatically freed when deleting the element.
 //NOTE 2: Deletion of an hash table entry must NOT be done using
 //        the iterator itself -> memory exception. You must advance the
 //        iterator before deleting the entry!
 
 HashMap::iterator  iter_end = myHashMap->end();
 HashMap::iterator  iter_tmp;
 iter = myHashMap->begin();
 uint32_t deleted = 0;
 while(iter!=iter_end) {
 iter_tmp = iter;
 ++iter;
 myHashMap->erase(iter_tmp);		
 deleted++;
 }
 if(deleted != NUM_ELEMENTS){
 cout << deleted << "\n";
 throw("ERROR: Not all inserted elements could be deleted! Aborting....\n");
 } else {
 cout << "Example SUCCESSFULLY completed!\n";
 } 
 delete myHashMap;
 }catch (char const * e){
 cout<< "Caught Exception: " << e << "\n";
 }

 }
 * \endcode
 * 
 * - <b>Example 2: </b> Creation, use and deletion of a hash_map with entries of type 'MyObject *' (pointer type) and HashKeyIPv4_6T keys
 * \code 
 #include "HashMap.h"
 #include <iostream>
 #include <sys/types.h>

 #define NUM_ELEMENTS  10000000

 using namespace std;

 class MyObject {
 private:
 uint32_t myIntfield;
 public:
 char info[16];
 //constructor of myObject
 MyObject(uint32_t myint){
 myIntfield = myint;
 for(int i=0; i<16; i++){
 info[i]=0;
 }
 }
 //destructor of myObject
 ~MyObject(){
 
 }	
 };

 typedef HashKeyIPv4_6T MyHashKey;
 typedef hash_map<HashKeyIPv4_6T, MyObject * , HashFunction<HashKeyIPv4_6T>,HashFunction<HashKeyIPv4_6T> > HashMap;

 int main() {
 uint32_t dstAddr = 0;
 uint16_t dstPort = 0;
 uint16_t srcPort = 0;
 uint8_t protocol = 0;
 uint8_t tos = 0;

 try{

 //insert NUM_ELEMENTS. Key is 'counting' source address and other key fields set to zero
 HashMap * myHashMap = new HashMap();
 for (uint32_t i = 0; i< NUM_ELEMENTS;i++){
 MyHashKey mykey(&i, &dstAddr, &srcPort, &dstPort, &protocol, &tos);
 (*myHashMap)[mykey]=new MyObject(i);
 }

 //searching for elements (here, we search for all inserted elements!)	
 HashMap::iterator iter;
 uint32_t found = 0;
 for (uint32_t i = 0; i < NUM_ELEMENTS; i++) {
 MyHashKey mykey(&i, &dstAddr, &srcPort, &dstPort, &protocol, &tos);
 iter = myHashMap->find(mykey);
 if(iter!=myHashMap->end()){
 //access and print the key:
 //   cout << (iter->first).printkey() << "\n";
 //access the element (e.g., print out field 'info'): 
 //   cout << (iter->second)->info << "\n";
 found++;
 }
 }
 if(found != NUM_ELEMENTS){
 throw("ERROR: Not all inserted elements found! Aborting....\n");
 }

 //deleting elements while iterating over the hash table
 //NOTE 1: Elements are of POINTER TYPE. The memory used is 
 //        NOT automatically freed when deleting the element.
 //NOTE 2: Deletion of an hash table entry must NOT be done using
 //        the iterator itself -> memory exception. You must advance the
 //        iterator before deleting the entry!
 
 HashMap::iterator  iter_end = myHashMap->end();
 HashMap::iterator  iter_tmp;
 iter = myHashMap->begin();
 uint32_t deleted = 0;
 while(iter!=iter_end) {
 iter_tmp = iter;
 ++iter;
 //we need to delete the element manualy (we allocated it with 'new'!
 delete iter_tmp->second;
 myHashMap->erase(iter_tmp);		
 deleted++;
 }
 if(deleted != NUM_ELEMENTS){
 cout << deleted << "\n";
 throw("ERROR: Not all inserted elements could be deleted! Aborting....\n");
 } else {
 cout << "Example SUCCESSFULLY completed!\n";
 } 
 delete myHashMap;
 }catch (char const * e){
 cout<< "Caught Exception: " << e << "\n";
 }
 }
 * \endcode
 * Distributed under the Gnu Public License version 2 or the modified
 * BSD license.
 *
 */

#include <arpa/inet.h>
#include <ext/hash_map>

#include "lookup3.h"
#include "cflow.h"
#include "IPv6_addr.h"

/**
 *	\class HashKeyGeneric
 * 	\brief Holds a generic hash key. You can pass a pointer to the key and the key length. Use this class if
 * 	none of the other hash key classes are suitable. 
 */
class HashKeyGeneric {
public:
	/**
	 * the key.
	 */
	char * key;
	/**
	 * length of the key.
	 */
	uint8_t length;
	/**
	 * Constructor.
	 * \param buf pointer to the key
	 * \param len length of the key. Note that if you pass a pointer to a string (char array) it will not be 
	 * treated as a null-terminated string. Only the passed length is relevant.
	 */
	HashKeyGeneric(char* buf, uint8_t len);
	~HashKeyGeneric();

	size_t size() const;
	HashKeyGeneric(const HashKeyGeneric & b);
	std::string printkey() const;
};

/**
 *	HashKeyGeneric	HashKeyIPv4
 * 	\brief Hash Key for IPv4 addresses. The length is fixed to 4 bytes.
 */
class HashKeyProtoFlowtype {
public:
	typedef boost::array<char, 2> key_type;
	/**
	 * Constructor.
	 * \param proto Protocol
	 * \param flowtype Flowtype
	 */
	HashKeyProtoFlowtype(const uint8_t proto, const uint8_t flowtype);
	HashKeyProtoFlowtype(const HashKeyProtoFlowtype & b);
	~HashKeyProtoFlowtype();
	size_t size() const;
	const key_type & getkey() const;
	std::string printkey() const;

protected:
	/**
	 * the protocol and flowtype
	 */
	key_type key;
};

/**
 *	\class	HashKeyIPv6
 * 	\brief	Hash Key for IPv6 addresses. The length is fixed to 16 bytes.
 */
class HashKeyIPv6 {
private:
	/**
	 * the IPv6 address.
	 */
public:
	IPv6_addr key;
	/**
	 * Constructor.
	 * \param ip the IPv6 address
	 */
	HashKeyIPv6(const IPv6_addr & ip);
	HashKeyIPv6(const HashKeyIPv6 &b);
	~HashKeyIPv6();
	size_t size() const;
	const IPv6_addr & getkey() const;
	std::string printkey() const;
};

/**
 *	\struct	HashFunction
 *	\brief Holds the implementation of the equals and hash operator for the different HashKeys.
 */
template<typename T> struct HashFunction {
	/**
	 * Hash function for HashKey class. The method hashlittle() is called on the key. See lookup3.h for details.
	 */
	size_t operator()(const T& key) const {
		return hashlittle(&key.getkey(), key.size(), 0);
	}

	/**
	 * Equals operator for HashKey class. Two keys are equal if they have the same size and all bytes
	 * are equal.
	 */
	bool operator()(const T& key1, const T& key2) const {
		if (key1.size() != key2.size())
			return false;
		for (unsigned int i = 0; i < key1.size(); i++) {
			if (key1.getkey()[i] != key2.getkey()[i])
				return false;
		}
		return true;
	}
};

#endif
