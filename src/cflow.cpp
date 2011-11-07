/**
 *	\file cflow.cpp
 *	\brief Filtering by flow type and protocol as configured in preferences "pref"..
 */

#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <boost/array.hpp>
#include <iomanip>
#include <iostream>
#include <sstream>

#include "global.h"
#include "cflow.h"
#include "grole.h"
#include "gutil.h"

using namespace std;

/**
 *	Constructor: Default constructor. Initializes to 0 and sets magic to CFLOW_6_MAGIC_NUMBER
 */
cflow6::cflow6() {
	this->magic = CFLOW_6_MAGIC_NUMBER;
	this->localIP = IPv6_addr();
	this->localPort = 0;
	this->remoteIP = IPv6_addr();
	this->remotePort = 0;
	this->prot = 0;
	this->flowtype = 0;
	this->startMs = 0;
	this->durationMs = 0;
	this->dOctets = 0;
	this->dPkts = 0;
	this->localAS = 0;
	this->remoteAS = 0;
	this->tos_flags = 0;
}

/**
 *	Constructor: Sets the value of all elements, magic to CFLOW_6_MAGIC_NUMBER
 *
 *	\param localIP Local IP
 *	\param localPort Local port
 *	\param remoteIP Remote IP
 *	\param remotePort Remote port
 *	\param prot IP Protocol number
 *	\param flowtype Flow type or direction (for values see enum flow_type_t)
 *	\param startMs Flow start time in milliseconds since the epoch
 *	\param durationMs Flow duration in milliseconds
 *	\param dOctets flow size in byte
 *	\param dPkts number of packets contained in flow
 */
cflow6::cflow6(const IPv6_addr & localIP, uint16_t localPort, const IPv6_addr & remoteIP, uint16_t remotePort, uint8_t prot, uint8_t flowtype,
      uint64_t startMs, uint32_t durationMs, uint64_t dOctets, uint32_t dPkts, uint8_t magic) {
	this->magic = magic;
	this->localIP = localIP;
	this->localPort = localPort;
	this->remoteIP = remoteIP;
	this->remotePort = remotePort;
	this->prot = prot;
	this->flowtype = flowtype;
	this->startMs = startMs;
	this->durationMs = durationMs;
	this->dOctets = dOctets;
	this->dPkts = dPkts;
	this->localAS = 0;
	this->remoteAS = 0;
	tos_flags = 0;
}

/**
 *	Writes a cflow6 to ostream
 *
 *	\param out Reference to the ostream where the cflow6 should be written to
 */
void cflow6::print(std::ostream & out) const {

	if (localIP.isIPv6()) {
		out << setw(4) << left << util::ipV6ProtocolToString(prot) << ": " << right << util::print_flowtype(dir) << " " << util::getIPandPortWithStableSize(
		      localIP, localPort) << " -> " << util::getIPandPortWithStableSize(remoteIP, remotePort) << " AS:" << setw(6) << localAS << "->" << setw(6)
		      << remoteAS << ", " << setw(4) << dOctets << " Byte," << setw(5) << dPkts << " Pkts, " << "start=" << util::seconds2daytime(startMs) << ", "
		      << "dur=" << setprecision(3) << fixed << (durationMs) / 1000.0 << "s, " << "ToS=" << (int) tos_flags << ", " << "magic=" << (int) magic;
	} else {
		out << setw(4) << left << util::ipV6ProtocolToString(prot) << ": " << right << util::print_flowtype(dir) << " " << setw(INET_ADDRSTRLEN) << right
		      << localIP << ":" << setw(5) << left << localPort << " -> " << setw(INET_ADDRSTRLEN) << right << remoteIP << left << ":" << setw(5) << remotePort
		      << " " << right << "AS:" << setw(5) << localAS << " -> " << setw(5) << remoteAS << ", " << setw(7) << dOctets << " Byte," << setw(5) << dPkts
		      << " Pkts, " << "start=" << util::seconds2daytime(startMs) << ", " << "dur=" << setprecision(3) << fixed << (durationMs) / 1000.0 << "s, "
		      << "ToS=" << (int) tos_flags << ", " << "magic=" << (int) magic;
	}
}

/**
 *	Implements the "less than" operator
 *
 *	\param flow Reference to the cflow6 which this object should be compared to
 *
 *	\return True if this object is smaller than other
 */
bool cflow6::operator<(const cflow6 & other) const {
	if (localIP != other.localIP)
		return localIP < other.localIP;
	if (remoteIP != other.remoteIP)
		return remoteIP < other.remoteIP;
	return startMs < other.startMs;
}

/**
 *	Implements the operator for cflow6
 *
 *	\param os Reference to the ostream where the cflow6 should be written to
 *	\param flow Cflow to be written to ostream
 *
 *	\return ostream Reference to the submitted ostream
 */
std::ostream & operator<<(std::ostream & os, const cflow6 & flow) {
	flow.print(os);
	return os;
}

/**
 *	Constructor: Default constructor. Set initializedBegin and initializedEnd to false.
 */
Subflowlist::Subflowlist() {
	initializedBegin = false;
	initializedEnd = false;
}

/**
 *	Constructor: Point _begin and _end to the given iterator, set initializedBegin and initializedEnd to true
 *
 *	\param begin Element to initialize from
 *	\param end One element behind the latest one to initialize from
 */
Subflowlist::Subflowlist(const_iterator begin, const_iterator end) {
	_begin = begin;
	_end = end;
	initializedBegin = true;
	initializedEnd = true;
}

/**
 *	Constructor: Point _begin and _end to the first()/end() of the given Subflowlist, set initializedBegin and initializedEnd to true.
 *
 *	\param subflowlist Subflowlist to initialize from.
 */
Subflowlist::Subflowlist(const Subflowlist & subflowlist) {
	_begin = subflowlist.begin();
	_end = subflowlist.end();
	initializedBegin = true;
	initializedEnd = true;
}

/**
 *	Constructor: Point _begin and _end to the first()/end() of the given CFlowList, set initializedBegin and initializedEnd to true.
 *
 *	\param CFlowList CFlowList to initialize from.
 */
Subflowlist::Subflowlist(const CFlowList & flowlist) {
	_begin = flowlist.begin();
	_end = flowlist.end();
	initializedBegin = true;
	initializedEnd = true;
}

/**
 *	Point _begin to the given element, set initializedBegin to true
 *
 *	\param begin First element
 */
void Subflowlist::setBegin(const_iterator begin) {
	assert(!initializedBegin);
	_begin = begin;
	initializedBegin = true;
}

/**
 *	Point _end to the given element, set initializedEnd to true
 *
 *	\param end One element behind the last one
 */
void Subflowlist::setEnd(const_iterator end) {
	assert(!initializedEnd);
	_end = end;
	initializedEnd = true;
}

/**
 *	Invalidate _begin and _end
 */
void Subflowlist::invalidate() {
	initializedBegin = false;
	initializedEnd = false;
}

/**
 *	Invalidate _begin
 */
void Subflowlist::invalidateBegin() {
	initializedBegin = false;
}

/**
 *	Invalidate _end
 */
void Subflowlist::invalidateEnd() {
	initializedEnd = false;
}

/**
 *	Get iterator pointing to one element behind the latest one.
 *
 *	\return const_iterator Iterator pointing to one element behind the latest one.
 */
Subflowlist::const_iterator Subflowlist::end() const {
	assert(initializedEnd);
	return _end;
}

/**
 *	Get iterator pointing to the first element.
 *
 *	\return const_iterator Iterator pointing the first element.
 */
Subflowlist::const_iterator Subflowlist::begin() const {
	assert(initializedBegin);
	return _begin;
}

/**
 *	Get size of Subflowlist.
 *
 *	\return size_type Number of element in this Subflowlist.
 */
Subflowlist::size_type Subflowlist::size() const {
	assert(initializedBegin && initializedEnd);
	return std::distance(_begin, _end);
}

/**
 *	Get a const reference to element at N.
 *
 *	\param n Index of element to retrieve.
 *
 *	\return cflow_t Element at index n.
 */
const cflow_t & Subflowlist::operator[](difference_type n) const {
	assert(initializedBegin && initializedEnd);
	assert(std::distance(_begin, _end) > n);
	return *(_begin + n);
}

/**
 *	Constructor:	CFlowFilter
 *
 *	\param	subflowlist	Vector of flows
 *	\param	prefs	Filter settings
 */
CFlowFilter::CFlowFilter(const Subflowlist & subflowlist, const prefs_t & prefs) :
	flow_filter(subflowlist.size()) {
	// Define a filter that defines which flowtypes are filtered
	flowtype_filter = 0;
	not_flowtype_filter = 0;
	if (prefs.filter_biflows)
		flowtype_filter = biflow;
	if (prefs.filter_uniflows)
		flowtype_filter |= uniflow;
	if (prefs.filter_unprod_inflows) {
		flowtype_filter |= inflow;
		not_flowtype_filter = unibiflow;
	}
	if (prefs.filter_unprod_outflows) {
		flowtype_filter |= outflow;
		not_flowtype_filter = unibiflow;
	}
	// Apply flow direction type filter
	for (unsigned int i = 0; i < subflowlist.size(); i++) {
		if (((subflowlist[i].flowtype & flowtype_filter) != 0) && ((subflowlist[i].flowtype & not_flowtype_filter) == 0)) {
			flow_filter[i] = true;
		} else {
			flow_filter[i] = false;
		}
	}

	// Apply protocol filter
	if (prefs.filter_TCP || prefs.filter_UDP || prefs.filter_ICMP || prefs.filter_OTHER) {
		for (uint i = 0; i < subflowlist.size(); i++) {
			switch (subflowlist[i].prot) {
				case IPPROTO_TCP:
					if (prefs.filter_TCP)
						flow_filter[i] = true;
					break;
				case IPPROTO_UDP:
					if (prefs.filter_UDP)
						flow_filter[i] = true;
					break;
				case IPPROTO_ICMP:
					if (prefs.filter_ICMP)
						flow_filter[i] = true;
					break;
				default:
					if (prefs.filter_OTHER)
						flow_filter[i] = true;
					break;
			}
		}
	}
}

std::string role_associations::toString(const role_associations & ra) {
	std::stringstream ss;
	ss << "client:\t" << std::fixed << std::setprecision(3) << ra.client;
	ss << " server:\t" << std::fixed << std::setprecision(3) << ra.server;
	ss << " p2p:\t" << std::fixed << std::setprecision(3) << ra.p2p;
	return ss.str();
}

/**
 *	Returns if flow at specific index has to be filtered or not
 *
 *	\param flow_num Index of flow in question
 *
 *	\return True if flow is filtered
 */
bool CFlowFilter::filter_flow(unsigned int flow_num) const {
	if ((unsigned int) flow_num > flow_filter.size()) {
		return true;
	} else {
		return flow_filter[flow_num];
	}
}
