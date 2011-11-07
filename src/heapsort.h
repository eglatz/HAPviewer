#ifndef HEAPSORT_H_
#define HEAPSORT_H_

/** 
 *	\file heapsort.h
 *	\brief Include file for heapsort algorithm modified for use with array sets.
 *
 *	<b>Motgivation</b>
 *	The C++ STL implements sorting for the class list. This class represents a
 *	linear list, but is built as a double-linked list. Such an implementation is not
 *	very efficient for large data sets in respect to space and time complexity.
 *
 *	<b>Approach</b>
 *	This implementation of a sort function can be applied to sets of arrays that 
 *	implement linear lists by C arrays. The sorting works equally well indedependent
 *	of the prior order of elements.
 *	Array sets are used in such a way that for a set of n arrays a list of n-tuples
 *	are managed where each element of a tuple is an array entry for a particular
 *	index value.
 */

#include <stdint.h>
#include <vector>

#include "IPv6_addr.h"
#include "cflow.h"

void heapSort(int * a, int count);
void heapSort(uint64_t * a, int count);
void heapSort(long * a, int count);
void heapSort(long * a, int * b, int count);
void heapSort(double * a, int count);
void heapSort(double * a, int * b, int count);
void heapSort(int * a, int * b, int count);
void heapSort(std::vector<IPv6_addr> & a, std::vector<int> & b);
void heapSort(uint32_t * a, int * b, int count);
void heapSort(uint64_t * a, uint32_t * refs, int count);
void heapSort3Level(uint64_t * index1, uint64_t * index2, uint32_t * refs, uint32_t count);
void heapSort(int * a, int * b, int * c, int count);

#endif /* HEAPSORT_H_ */

