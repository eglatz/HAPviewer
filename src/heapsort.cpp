/**
 *	\file heapsort.cpp
 *	\brief Implementation file of the heapsort algorithm for array sets.
 *
 *	Input array is sorted in ascending order. Optionally associated arrays are re-arranged in such
 *	a way that entries stay aligned.
 */
#include "heapsort.h"
#include <iostream>
#include <stdlib.h>
#include <stdio.h>

//=================================================================================

/**
 *	Exchange the contents of two variables given by their address.
 *	\param x	First variable.
 *	\param y Second variable.
 */
static inline void swapi(int * x, int * y) {
	int temp = *x;
	*x = *y;
	*y = temp;
}

/**
 *	Exchange the contents of two variables given by their address.
 *	\param x	First variable.
 *	\param y Second variable.
 */
static inline void swapu(uint32_t * x, uint32_t * y) {
	uint32_t temp = *x;
	*x = *y;
	*y = temp;
}

/**
 *	Exchange the contents of two variables given by their address.
 *	\param x	First variable.
 *	\param y Second variable.
 */
static inline void swapl(uint64_t * x, uint64_t * y) {
	uint64_t temp = *x;
	*x = *y;
	*y = temp;
}

/**
 *	Exchange the contents of two variables given by their address.
 *	\param x	First variable.
 *	\param y Second variable.
 */
static inline void swapL(long * x, long * y) {
	long temp = *x;
	*x = *y;
	*y = temp;
}

/**
 *	Exchange the contents of two variables given by their address.
 *	\param x	First variable.
 *	\param y Second variable.
 */
static inline void swapD(double * x, double * y) {
	double temp = *x;
	*x = *y;
	*y = temp;
}

//=================================================================================

/**
 *	Sift down the heap.
 *	\param	a	Array of data elements.
 *	\param[in]	start	Where to start.
 *	\param[in]	end represents the limit of how far down the heap to sift.
 */
static inline void siftDown(int * a, int start, int end) {
	int root = start;

	while (root * 2 + 1 <= end) { // (While the root has at least one child)
		int child = root * 2 + 1; // (root*2+1 points to the left child)
		// (If the child has a sibling and the child's value is less than its sibling's...)
		if ((child < end) && (a[child] < a[child + 1])) {
			child++; // (... then point to the right child instead)
		}
		if (a[root] < a[child]) { // (out of max-heap order)
			swapi(&a[root], &a[child]);
			root = child; // (repeat to continue sifting down the child now)
		} else {
			return;
		}
	}
}

/**
 *	Heapify.
 *	\param a	Array of data elements.
 *	\param[in] count Array length count.
 *
 */
static inline void heapify(int * a, int count) {
	// (start is assigned the index in a of the last parent node)
	int start = (count - 1) / 2;

	while (start >= 0) {
		// (sift down the node at index start to the proper place such that all nodes below
		// the start index are in heap order)
		siftDown(a, start, count - 1);
		start--;
		// (after sifting down the root all nodes/elements are in heap order)
	}
}

/**
 *	Heapsort for an unordered array of elements.
 *	Sorts array a according to ascending a values.
 * 	\param a array to be sorted according to ascending a values.
 *	\param[in]	count Array length count.
 */
void heapSort(int * a, int count) {
	// (first place a in max-heap order)
	heapify(a, count);

	int end = count - 1;
	while (end > 0) {
		// (swap the root(maximum value) of the heap with the last element of the heap)
		swapi(&a[end], &a[0]);
		// (decrease the size of the heap by one so that the previous max value will
		// stay in its proper placement)
		end--;
		// (put the heap back in max-heap order)
		siftDown(a, 0, end);
	}
}
//=================================================================================

/**
 *	Sift down the heap.
 *	\param	a	Array of data elements.
 *	\param[in]	start	Where to start.
 *	\param[in]	end represents the limit of how far down the heap to sift.
 */
static inline void siftDownl(uint64_t * a, int start, int end) {
	int root = start;

	while (root * 2 + 1 <= end) { // (While the root has at least one child)
		int child = root * 2 + 1; // (root*2+1 points to the left child)
		// (If the child has a sibling and the child's value is less than its sibling's...)
		if ((child < end) && (a[child] < a[child + 1])) {
			child++; // (... then point to the right child instead)
		}
		if (a[root] < a[child]) { // (out of max-heap order)
			swapl(&a[root], &a[child]);
			root = child; // (repeat to continue sifting down the child now)
		} else {
			return;
		}
	}
}

/**
 *	Heapify.
 *	\param a	Array of data elements.
 *	\param[in] count Array length count.
 *
 */
static inline void heapifyl(uint64_t * a, int count) {
	// (start is assigned the index in a of the last parent node)
	int start = (count - 1) / 2;

	while (start >= 0) {
		// (sift down the node at index start to the proper place such that all nodes below
		// the start index are in heap order)
		siftDownl(a, start, count - 1);
		start--;
		// (after sifting down the root all nodes/elements are in heap order)
	}
}

/**
 *	Heapsort for an unordered array of elements.
 *	Sorts array a according to ascending a values.
 * 	\param a array to be sorted according to ascending a values.
 *	\param[in]	count Array length count.
 */
void heapSort(uint64_t * a, int count) {
	// (first place a in max-heap order)
	heapifyl(a, count);

	int end = count - 1;
	while (end > 0) {
		// (swap the root(maximum value) of the heap with the last element of the heap)
		swapl(&a[end], &a[0]);
		// (decrease the size of the heap by one so that the previous max value will
		// stay in its proper placement)
		end--;
		// (put the heap back in max-heap order)
		siftDownl(a, 0, end);
	}
}

//=================================================================================

/**
 *	Sift down the heap.
 *	\param	a	Array of data elements.
 *	\param[in]	start	Where to start.
 *	\param[in]	end represents the limit of how far down the heap to sift.
 */
static inline void siftDownL(long * a, int start, int end) {
	int root = start;

	while (root * 2 + 1 <= end) { // (While the root has at least one child)
		int child = root * 2 + 1; // (root*2+1 points to the left child)
		// (If the child has a sibling and the child's value is less than its sibling's...)
		if ((child < end) && (a[child] < a[child + 1])) {
			child++; // (... then point to the right child instead)
		}
		if (a[root] < a[child]) { // (out of max-heap order)
			swapL(&a[root], &a[child]);
			root = child; // (repeat to continue sifting down the child now)
		} else {
			return;
		}
	}
}

/**
 *	Heapify.
 *	\param a	Array of data elements.
 *	\param[in] count Array length count.
 *
 */
static inline void heapifyL(long * a, int count) {
	// (start is assigned the index in a of the last parent node)
	int start = (count - 1) / 2;

	while (start >= 0) {
		// (sift down the node at index start to the proper place such that all nodes below
		// the start index are in heap order)
		siftDownL(a, start, count - 1);
		start--;
		// (after sifting down the root all nodes/elements are in heap order)
	}
}

/**
 *	Heapsort for an unordered array of elements.
 *	Sorts array a according to ascending a values.
 * 	\param a array to be sorted according to ascending a values.
 *	\param[in]	count Array length count.
 */
void heapSort(long * a, int count) {
	// (first place a in max-heap order)
	heapifyL(a, count);

	int end = count - 1;
	while (end > 0) {
		// (swap the root(maximum value) of the heap with the last element of the heap)
		swapL(&a[end], &a[0]);
		// (decrease the size of the heap by one so that the previous max value will
		// stay in its proper placement)
		end--;
		// (put the heap back in max-heap order)
		siftDownL(a, 0, end);
	}
}

//=================================================================================

/**
 *	Sift down the heap.
 *	\param	a	Array of data elements.
 *	\param	b	Array of data elements.
 *	\param[in]	start	Where to start.
 *	\param[in]	end represents the limit of how far down the heap to sift.
 */
static inline void siftDownLI(long * a, int * b, int start, int end) {
	int root = start;

	while (root * 2 + 1 <= end) { // (While the root has at least one child)
		int child = root * 2 + 1; // (root*2+1 points to the left child)
		// (If the child has a sibling and the child's value is less than its sibling's...)
		if ((child < end) && (a[child] < a[child + 1])) {
			child++; // (... then point to the right child instead)
		}
		if (a[root] < a[child]) { // (out of max-heap order)
			swapL(&a[root], &a[child]);
			swapi(&b[root], &b[child]);
			root = child; // (repeat to continue sifting down the child now)
		} else {
			return;
		}
	}
}

/**
 *	Heapify.
 *	\param a	Array of data elements.
 *	\param	b	Array of data elements.
 *	\param[in] count Array length count.
 *
 */
static inline void heapifyLI(long * a, int * b, int count) {
	// (start is assigned the index in a of the last parent node)
	int start = (count - 1) / 2;

	while (start >= 0) {
		// (sift down the node at index start to the proper place such that all nodes below
		// the start index are in heap order)
		siftDownLI(a, b, start, count - 1);
		start--;
		// (after sifting down the root all nodes/elements are in heap order)
	}
}

/**
 *	Heapsort for an unordered array of elements.
 *	Sorts array a according to ascending a values.
 * 	\param a array to be sorted according to ascending a values.
 *	\param	b	Second array to be re-arranged along array a.
 *	\param[in]	count Array length count.
 */
void heapSort(long * a, int * b, int count) {
	// (first place a in max-heap order)
	heapifyLI(a, b, count);

	int end = count - 1;
	while (end > 0) {
		// (swap the root(maximum value) of the heap with the last element of the heap)
		swapL(&a[end], &a[0]);
		swapi(&b[end], &b[0]);
		// (decrease the size of the heap by one so that the previous max value will
		// stay in its proper placement)
		end--;
		// (put the heap back in max-heap order)
		siftDownLI(a, b, 0, end);
	}
}

//=================================================================================

/**
 *	Sift down the heap.
 *	\param	a	Array of data elements.
 *	\param[in]	start	Where to start.
 *	\param[in]	end represents the limit of how far down the heap to sift.
 */
static inline void siftDownD(double * a, int start, int end) {
	int root = start;

	while (root * 2 + 1 <= end) { // (While the root has at least one child)
		int child = root * 2 + 1; // (root*2+1 points to the left child)
		// (If the child has a sibling and the child's value is less than its sibling's...)
		if ((child < end) && (a[child] < a[child + 1])) {
			child++; // (... then point to the right child instead)
		}
		if (a[root] < a[child]) { // (out of max-heap order)
			swapD(&a[root], &a[child]);
			root = child; // (repeat to continue sifting down the child now)
		} else {
			return;
		}
	}
}

/**
 *	Heapify.
 *	\param a	Array of data elements.
 *	\param[in] count Array length count.
 *
 */
static inline void heapifyD(double * a, int count) {
	// (start is assigned the index in a of the last parent node)
	int start = (count - 1) / 2;

	while (start >= 0) {
		// (sift down the node at index start to the proper place such that all nodes below
		// the start index are in heap order)
		siftDownD(a, start, count - 1);
		start--;
		// (after sifting down the root all nodes/elements are in heap order)
	}
}

/**
 *	Heapsort for an unordered array of elements.
 *	Sorts array a according to ascending a values.
 * 	\param a array to be sorted according to ascending a values.
 *	\param[in]	count Array length count.
 */
void heapSort(double * a, int count) {
	// (first place a in max-heap order)
	heapifyD(a, count);

	int end = count - 1;
	while (end > 0) {
		// (swap the root(maximum value) of the heap with the last element of the heap)
		swapD(&a[end], &a[0]);
		// (decrease the size of the heap by one so that the previous max value will
		// stay in its proper placement)
		end--;
		// (put the heap back in max-heap order)
		siftDownD(a, 0, end);
	}
}

//=================================================================================

/**
 *	Sift down the heap.
 *	\param	a	Array of data elements.
 *	\param	b	Array of data elements.
 *	\param[in]	start	Where to start.
 *	\param[in]	end represents the limit of how far down the heap to sift.
 */
static inline void siftDownDI(double * a, int * b, int start, int end) {
	int root = start;

	while (root * 2 + 1 <= end) { // (While the root has at least one child)
		int child = root * 2 + 1; // (root*2+1 points to the left child)
		// (If the child has a sibling and the child's value is less than its sibling's...)
		if ((child < end) && (a[child] < a[child + 1])) {
			child++; // (... then point to the right child instead)
		}
		if (a[root] < a[child]) { // (out of max-heap order)
			swapD(&a[root], &a[child]);
			swapi(&b[root], &b[child]);
			root = child; // (repeat to continue sifting down the child now)
		} else {
			return;
		}
	}
}

/**
 *	Heapify.
 *	\param a	Array of data elements.
 *	\param	b	Array of data elements.
 *	\param[in] count Array length count.
 *
 */
static inline void heapifyDI(double * a, int * b, int count) {
	// (start is assigned the index in a of the last parent node)
	int start = (count - 1) / 2;

	while (start >= 0) {
		// (sift down the node at index start to the proper place such that all nodes below
		// the start index are in heap order)
		siftDownDI(a, b, start, count - 1);
		start--;
		// (after sifting down the root all nodes/elements are in heap order)
	}
}

/**
 *	Heapsort for an unordered array of elements.
 *	Sorts array a according to ascending a values.
 * 	\param a array to be sorted according to ascending a values.
 *	\param	b	Second array to be re-arranged along array a.
 *	\param[in]	count Array length count.
 */
void heapSort(double * a, int * b, int count) {
	// (first place a in max-heap order)
	heapifyDI(a, b, count);

	int end = count - 1;
	while (end > 0) {
		// (swap the root(maximum value) of the heap with the last element of the heap)
		swapD(&a[end], &a[0]);
		swapi(&b[end], &b[0]);
		// (decrease the size of the heap by one so that the previous max value will
		// stay in its proper placement)
		end--;
		// (put the heap back in max-heap order)
		siftDownDI(a, b, 0, end);
	}
}

//=================================================================================

/**
 *	Sift down the heap.
 *	\param	a	Array of data elements.
 *	\param[in]	start	Where to start.
 *	\param[in]	end represents the limit of how far down the heap to sift.
 */
static inline void siftDown2l(uint64_t * a, uint32_t * refs, int start, int end) {
	int root = start;

	while (root * 2 + 1 <= end) { // (While the root has at least one child)
		int child = root * 2 + 1; // (root*2+1 points to the left child)
		// (If the child has a sibling and the child's value is less than its sibling's...)
		if ((child < end) && (a[child] < a[child + 1])) {
			child++; // (... then point to the right child instead)
		}
		if (a[root] < a[child]) { // (out of max-heap order)
			swapl(&a[root], &a[child]);
			swapu(&refs[root], &refs[child]);
			root = child; // (repeat to continue sifting down the child now)
		} else {
			return;
		}
	}
}

/**
 *	Heapify.
 *	\param a	Array of data elements.
 *	\param[in] count Array length count.
 *
 */
static inline void heapify2l(uint64_t * a, uint32_t * refs, int count) {
	// (start is assigned the index in a of the last parent node)
	int start = (count - 1) / 2;

	while (start >= 0) {
		// (sift down the node at index start to the proper place such that all nodes below
		// the start index are in heap order)
		siftDown2l(a, refs, start, count - 1);
		start--;
		// (after sifting down the root all nodes/elements are in heap order)
	}
}

/**
 *	Heapsort for an unordered array of elements.
 *	Sorts array a according to ascending a values.
 * 	\param  refs A second array depending on a (sorted along a)
 * 	\param a array to be sorted according to ascending a values.
 *	\param[in]	count Array length count.
 */
void heapSort(uint64_t * a, uint32_t * refs, int count) {
	// (first place a in max-heap order)
	heapify2l(a, refs, count);

	int end = count - 1;
	while (end > 0) {
		// (swap the root(maximum value) of the heap with the last element of the heap)
		swapl(&a[end], &a[0]);
		swapu(&refs[end], &refs[0]);
		// (decrease the size of the heap by one so that the previous max value will
		// stay in its proper placement)
		end--;
		// (put the heap back in max-heap order)
		siftDown2l(a, refs, 0, end);
	}
}

//=================================================================================

/**
 *	Sift down the heap.
 *	\param	a	Array of data elements.
 *	\param	b	Second array associated with a.
 *	\param[in]	start	Where to start.
 *	\param[in]	end represents the limit of how far down the heap to sift.
 */
static inline void siftDown2(int * a, int * b, int start, int end) {
	int root = start;

	while (root * 2 + 1 <= end) { // (While the root has at least one child)
		int child = root * 2 + 1; // (root*2+1 points to the left child)
		// (If the child has a sibling and the child's value is less than its sibling's...)
		if ((child < end) && (a[child] < a[child + 1])) {
			child++; // (... then point to the right child instead)
		}
		if (a[root] < a[child]) { // (out of max-heap order)
			swapi(&a[root], &a[child]);
			swapi(&b[root], &b[child]);
			root = child; // (repeat to continue sifting down the child now)
		} else {
			return;
		}
	}
}

/**
 *	Heapify.
 *	\param a	Array of data elements.
 *	\param b	Second array associated with a.
 *	\param[in] count Array length count.
 *
 */
static inline void heapify2(int * a, int * b, int count) {
	// (start is assigned the index in a of the last parent node)
	int start = (count - 1) / 2;

	while (start >= 0) {
		// (sift down the node at index start to the proper place such that all nodes below
		// the start index are in heap order)
		siftDown2(a, b, start, count - 1);
		start--;
		// (after sifting down the root all nodes/elements are in heap order)
	}
}

/**
 *	Heapsort for an unordered array of elements where each elements consists
 *	of two value (first value stored in array a, second value in array b).
 *	Sorts arrays a,b according to ascending a values.
 * 	\param a array to be sorted according to ascending a values.
 *	\param b co-array included in sorting process.
 *	\param[in]	count Array length count.
 */
void heapSort(int * a, int * b, int count) {
	// (first place a in max-heap order)
	heapify2(a, b, count);

	int end = count - 1;
	while (end > 0) {
		// (swap the root(maximum value) of the heap with the last element of the heap)
		swapi(&a[end], &a[0]);
		swapi(&b[end], &b[0]);
		// (decrease the size of the heap by one so that the previous max value will
		// stay in its proper placement)
		end--;
		// (put the heap back in max-heap order)
		siftDown2(a, b, 0, end);
	}
}

//=================================================================================

/**
 *	Sift down the heap.
 *	\param	a	Array of data elements.
 *	\param	b	Second array associated with a.
 *	\param[in]	start	Where to start.
 *	\param[in]	end represents the limit of how far down the heap to sift.
 */
static inline void siftDown2(uint32_t * a, int * b, int start, int end) {
	int root = start;

	while (root * 2 + 1 <= end) { // (While the root has at least one child)
		int child = root * 2 + 1; // (root*2+1 points to the left child)
		// (If the child has a sibling and the child's value is less than its sibling's...)
		if ((child < end) && (a[child] < a[child + 1])) {
			child++; // (... then point to the right child instead)
		}
		if (a[root] < a[child]) { // (out of max-heap order)
			swapu(&a[root], &a[child]);
			swapi(&b[root], &b[child]);
			root = child; // (repeat to continue sifting down the child now)
		} else {
			return;
		}
	}
}

/**
 *	Heapify.
 *	\param a	Array of data elements.
 *	\param b	Second array associated with a.
 *	\param[in] count Array length count.
 *
 */
static inline void heapify2(uint32_t * a, int * b, int count) {
	// (start is assigned the index in a of the last parent node)
	int start = (count - 1) / 2;

	while (start >= 0) {
		// (sift down the node at index start to the proper place such that all nodes below
		// the start index are in heap order)
		siftDown2(a, b, start, count - 1);
		start--;
		// (after sifting down the root all nodes/elements are in heap order)
	}
}

/**
 *	Heapsort for an unordered array of elements where each elements consists
 *	of two value (first value stored in array a, second value in array b).
 *	Sorts arrays a,b according to ascending a values.
 * 	\param a array to be sorted according to ascending a values.
 *	\param b co-array included in sorting process.
 *	\param[in]	count Array length count.
 */
void heapSort(uint32_t * a, int * b, int count) {
	// (first place a in max-heap order)
	heapify2(a, b, count);

	int end = count - 1;
	while (end > 0) {
		// (swap the root(maximum value) of the heap with the last element of the heap)
		swapu(&a[end], &a[0]);
		swapi(&b[end], &b[0]);
		// (decrease the size of the heap by one so that the previous max value will
		// stay in its proper placement)
		end--;
		// (put the heap back in max-heap order)
		siftDown2(a, b, 0, end);
	}
}

//=================================================================================

/**
 *	Sift down the heap.
 *	\param	a	Array of data elements.
 *	\param	b	Second array associated with a.
 *	\param	c	Third array associated with a.
 *	\param[in]	start	Where to start.
 *	\param[in]	end represents the limit of how far down the heap to sift.
 */
static inline void siftDown3(int * a, int * b, int * c, int start, int end) {
	int root = start;

	while (root * 2 + 1 <= end) { // (While the root has at least one child)
		int child = root * 2 + 1; // (root*2+1 points to the left child)
		// (If the child has a sibling and the child's value is less than its sibling's...)
		if ((child < end) && (a[child] < a[child + 1])) {
			child++; // (... then point to the right child instead)
		}
		if (a[root] < a[child]) { // (out of max-heap order)
			swapi(&a[root], &a[child]);
			swapi(&b[root], &b[child]);
			swapi(&c[root], &c[child]);
			root = child; // (repeat to continue sifting down the child now)
		} else {
			return;
		}
	}
}

/**
 *	Heapify.
 *	\param a	Array of data elements.
 *	\param b	Second array associated with a.
 *	\param c	Third array associated with a.
 *	\param[in] count Array length count.
 *
 */
static inline void heapify3(int * a, int * b, int * c, int count) {
	// (start is assigned the index in a of the last parent node)
	int start = (count - 1) / 2;

	while (start >= 0) {
		// (sift down the node at index start to the proper place such that all nodes below
		// the start index are in heap order)
		siftDown3(a, b, c, start, count - 1);
		start--;
		// (after sifting down the root all nodes/elements are in heap order)
	}
}

/**
 *	Heapsort for an unordered array of elements where each elements consists
 *	of two value (first value stored in array a, second value in array b).
 *	Sorts arrays a,b according to ascending a values.
 * 	\param a array to be sorted according to ascending a values.
 *	\param b co-array included in sorting process.
 *	\param c	Third array associated with a.
 *	\param[in]	count Array length count.
 */
void heapSort(int * a, int * b, int * c, int count) {
	// (first place a in max-heap order)
	heapify3(a, b, c, count);

	int end = count - 1;
	while (end > 0) {
		// (swap the root(maximum value) of the heap with the last element of the heap)
		swapi(&a[end], &a[0]);
		swapi(&b[end], &b[0]);
		swapi(&c[end], &c[0]);
		// (decrease the size of the heap by one so that the previous max value will
		// stay in its proper placement)
		end--;
		// (put the heap back in max-heap order)
		siftDown3(a, b, c, 0, end);
	}
}

//=================================================================================

/**
 *	Sift down the heap.
 *	\param	a			Array of data elements.
 *	\param	b			Second array associated with a.
 *	\param	c			Third array associated with a.
 *	\param[in]	start	Where to start.
 *	\param[in]	end 	Represents the limit of how far down the heap to sift.
 */
static inline void siftDown3l(uint64_t * a, uint64_t * b, uint32_t * c, uint32_t start, uint32_t end) {
	uint32_t root = start;

	while (root * 2 + 1 <= end) { // (While the root has at least one child)
		uint32_t child = root * 2 + 1; // (root*2+1 points to the left child)
		// (If the child has a sibling and the child's value is less than its sibling's...)
		if ((child < end) && (a[child] < a[child + 1])) {
			child++; // (... then point to the right child instead)
		}
		if (a[root] < a[child]) { // (out of max-heap order)
			swapl(&a[root], &a[child]);
			swapl(&b[root], &b[child]);
			swapu(&c[root], &c[child]);
			root = child; // (repeat to continue sifting down the child now)
		} else {
			return;
		}
	}
}

/**
 *	Heapify.
 *	\param a			Array of data elements.
 *	\param b			Second array associated with a.
 *	\param c			Third array associated with a.
 *	\param count 	Array length count.
 *
 */
static inline void heapify3l(uint64_t * a, uint64_t * b, uint32_t * c, uint32_t count) {
	// (start is assigned the index in a of the last parent node)
	int start = (count - 1) / 2;

	while (start >= 0) {
		// (sift down the node at index start to the proper place such that all nodes below
		// the start index are in heap order)
		siftDown3l(a, b, c, start, count - 1);
		start--;
		// (after sifting down the root all nodes/elements are in heap order)
	}
}

/**
 *	Heapsort for an unordered array of elements where each elements consists
 *	of two value (first value stored in array a, second value in array b).
 *	Sorts arrays a,b according to ascending a values.
 * 	\param a 		array to be sorted according to ascending a values.
 *	\param b 		co-array included in sorting process.
 *	\param c			Third array associated with a.
 *	\param count 	Array length count.
 */
void heapSort(uint64_t * a, uint64_t * b, uint32_t * c, uint32_t count) {
	// (first place a in max-heap order)
	heapify3l(a, b, c, count);

	int end = count - 1;
	while (end > 0) {
		// (swap the root(maximum value) of the heap with the last element of the heap)
		swapl(&a[end], &a[0]);
		swapl(&b[end], &b[0]);
		swapu(&c[end], &c[0]);
		// (decrease the size of the heap by one so that the previous max value will
		// stay in its proper placement)
		end--;
		// (put the heap back in max-heap order)
		siftDown3l(a, b, c, 0, end);
	}
}

//=================================================================================

/**
 *	Sort a set of three associated arrays.
 *
 *	Three arrays index1, index2 and refs are sorted in combination such that
 *	the three-tuples {index1[i], index2[i], refs[i]} persist for each value of i.
 *	Sorting of this set of three-tuples is done according to ascending order of
 *	index1 values firstly and for ascending order of index2 values secondly.
 *
 *	\param	index1	Array giving ascending order for first level of sorting
 *	\param	index2	Array giving ascending order for second level of sorting
 *	\param	refs		Third array of array set (usually as an index into a more
 *							comprehensive list)
 * 	\param 	count		Count of elements contained in input array
 */
void heapSort2Level(uint64_t * index1, uint64_t * index2, uint32_t * refs, uint32_t count) {

	// Perform sorting for level 1 (ascending index1 values)
	heapSort(index1, index2, refs, count);

	// Perform sorting for level 2 (ascending index2 values for pre-sorted index1 values)
	uint64_t val = 0;
	uint32_t start = 0;
	uint32_t i = 0;
	uint32_t cnt = 0;

	do {
		val = index1[i];
		// Identify a range of identical index1 values
		while (1) {
			if ((index1[++i] != val) || (i >= count)) {
				// Found end of range
				cnt = i - start;
				break;
			}
		}
		if (cnt > 1) {
			// Sort inside of the current range for ascendig index2 values
			heapSort(&index2[start], &index1[start], &refs[start], cnt);
		}
		start = i;
	} while (i < count);
}
//--------------------------------------------------------------------------
static inline void swapIPv6(IPv6_addr * x, IPv6_addr * y) {
	IPv6_addr temp = *x;
	*x = *y;
	*y = temp;
}
static inline void siftDown2(std::vector<IPv6_addr> & a, std::vector<int> & b, int start, int end) {
	int root = start;

	while (root * 2 + 1 <= end) { // (While the root has at least one child)
		int child = root * 2 + 1; // (root*2+1 points to the left child)
		// (If the child has a sibling and the child's value is less than its sibling's...)
		if ((child < end) && (a[child] < a[child + 1])) {
			child++; // (... then point to the right child instead)
		}
		if (a[root] < a[child]) { // (out of max-heap order)
			swapIPv6(&a[root], &a[child]);
			swapi(&b[root], &b[child]);
			root = child; // (repeat to continue sifting down the child now)
		} else {
			return;
		}
	}
}
static inline void heapify2(std::vector<IPv6_addr> &a, std::vector<int> &b) {
	// (start is assigned the index in a of the last parent node)
	int start = (a.size() - 1) / 2;
	while (start >= 0) {
		// (sift down the node at index start to the proper place such that all nodes below
		// the start index are in heap order)
		siftDown2(a, b, start, a.size() - 1);
		start--;
		// (after sifting down the root all nodes/elements are in heap order)
	}
}
void heapSort(std::vector<IPv6_addr> &a, std::vector<int> &b) {
	// (first place a in max-heap order)
	heapify2(a, b);

	int end = a.size() - 1;
	while (end > 0) {
		// (swap the root(maximum value) of the heap with the last element of the heap)
		swapIPv6(&a[end], &a[0]);
		swapi(&b[end], &b[0]);
		// (decrease the size of the heap by one so that the previous max value will
		// stay in its proper placement)
		end--;
		// (put the heap back in max-heap order)
		siftDown2(a, b, 0, end);
	}
}
//--------------------------------------------------------------------------

#ifdef MAIN_TEST

using namespace std;

// This main is provided for unit test of the class.

int main(int argc, char * argv[])
{
	bool verbose = false;

	cout << "\nRunning unit tests for module heapsort.cpp:\n\n";

	// 4. Test of heapSort(long *, int *, int)
	// ***************************************
	//
	cout << "Test 1: heapsort(long *, int *, int):\n";

	long aLI[] = {1345, 1, 5, 345, 100000, 289, 20000000, 2, 9, 7}; // To be sorted 10 values
	int bLI[] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9}; // To be aligned with aLI

	int newbLI[] = {1, 7, 2, 9, 8, 5, 3, 0, 4, 6}; // Expected result for bLI

	if (verbose) {
		cout << "Unsorted list (array set):\n";
		cout << "#\ti1\ti2\n";
		for (int i=0; i<10; i++) {
			cout << aLI[i] << "\t" << bLI[i] << endl;
		}
		cout << "Performing sort now.\n";
	}

	heapSort(aLI, bLI, 10);

	bool error4 = false;
	for (int i=0; i<10; i++) {
		if (bLI[i] != newbLI[i]) error4=true;
	}
	if (error4) {
		cout << "ERROR: test failed.\n";
		cout << "Sorted list (array set):\n";

		for (int i=0; i<10; i++) {
			cout << aLI[i] << "\t" << bLI[i] << endl;
		}
	} else {
		cout << "Test passed.\n\n";
	}

	// 7. Test of heapSort (uint64_t *, uint64_t *, uint32_t *, uint32_t)
	// ******************************************************************
	//
	// two-level sorting

	cout << "Test 7: heapSort2L(uint64_t *, uint64_t *, uint32_t *, uint32_t) (two-level list sort):\n";
	uint32_t c3[] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9}; // Record #
	uint32_t newc3[] = {1, 9, 7, 8, 3, 0, 4, 2, 6, 5}; // Expected c3 after sorting

	uint64_t a3[] = {
		0x6000000005,
		0x0600000000,
		0x6000000006,
		0x6000000005,
		0x6000000005,
		0x7000000004,
		0x7000000004,
		0x1000000000,
		0x1000000004,
		0x1000000000}; // index 1 (use 64 bit values)
	uint64_t b3[] = {4, 6, 3, 0, 7, 5, 4, 1, 89, 0}; // index 2

	uint32_t cnt = sizeof(a3)/sizeof(uint64_t);

	if (verbose) {
		cout << "Unsorted list (array set):\n";
		cout << "#\ti1\ti2\n";
		for (uint32_t i=0; i<cnt; i++) {
			cout << hex << a3[i] << "\t" << b3[i] << "\t" << dec << c3[i]<< endl;
		}
		cout << "Performing sort now.\n";
	}

	heapSort2Level(a3, b3, c3, cnt);

	bool error7 = false;
	for (int i=0; i<10; i++) {
		if (c3[i] != newc3[i]) error7=true;
	}
	if (error7) {
		cout << "ERROR: test failed.\n";
		cout << "Sorted list (array set):\n";

		for (uint32_t i=0; i<cnt; i++) {
			cout << "\t" << hex << a3[i] << "\t" << b3[i] << c3[i] << endl;
		}
	} else {
		cout << "Test passed.\n\n";
	}

	return 0;
}
#endif

