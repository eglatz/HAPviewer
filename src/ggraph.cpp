/**
 *	\file ggraph.cpp
 *	\brief Class CGraphlet for graphlet inference.
 *
 *	Transforms flow and role data into graph descriptions.
 *
 *	So far, we only support the binary "hpg" format defined in hpg.h.
 *	This format is very space efficient as it was originally introduced
 *	to store a large number of graphlets in a file efficiently.
 */
#include <string>
#include <boost/lexical_cast.hpp>

#include "ggraph.h"
#include "gutil.h"
#include "hpg.h"
#include "gsummarynodeinfo.h"

using namespace std;

#ifdef NDEBUG
const bool dbg = false;
const bool dbg2 = false;
#else
const bool dbg = true;
const bool dbg2 = true;
#endif

/**
 *	Constructor
 *
 *	\param	hpg_filename Name of output file for binary graph data
 *	\param	roleMembership Role membership of graphlet
 *
 *	\exception string Errormessage
 */
CGraphlet::CGraphlet(std::string hpg_filename, CRoleMembership & roleMembership) {
	proleMembership = &roleMembership;

	// Open output file to write hpg graphlet edges to.
	try {
		util::open_outfile(outfs, hpg_filename);
	} catch (string & e) {
		throw e;
	}

	totalbytes = 0; // Counts bytes over all flows belonging to a graphlet
	hostnum = 0;

	// Derive a fully annotated graphlet in form of a k-partite graph (k=5)
	// Use k-1 hash tables to capture edges between the k partitions
	// Additionally, one more hash map is used to keep track of unique host numbers
	// Partitions are: localIP, prot, localPort, remotePort, remoteIP

	// k1--k2
	// ******
	hm_localIp_prot = new graphletHashMap(); // localIP--prot

	// k2--k3
	// ******
	// Local port number is not shared between protocols and hosts
	// (we have one host only, but might have several protocols)
	// -> store protocol enum code together with port number (use enum values as protocol code)
	hm_prot_localPort_11 = new graphletHashMap(); // prot--localPort
	hm_prot_localPort_1n = new graphletHashMap(); // prot--localPort

	// k3--k4
	// ******
	// Remote port numbers are not shared between remote hosts and protocols
	// (we might have several protocols and several remoteIPs)
	// -> store protocol enum code and remote host number together with port number
	hm_localPort_remotePort_11 = new graphletHashMap(); // localPort--remotePort
	hm_localPort_remotePort_n1 = new graphletHashMap(); // localPort--remotePort
	hm_localPort_remotePort_1n = new graphletHashMap(); // localPort--remotePort
	hm_localPort_remotePort_nn = new graphletHashMap(); // localPort--remotePort

	// To store byte/packet counts
	hm_localPort_remotePortE = new graphletHashMap(); // localPort--remotePort (extension)

	// k4--k5
	// ******
	// Each remote port (enhanced with protocol enum code and host number) is associated
	// with exactly one remote host. To save space we do not identify remote host by its IP address,
	// but with a consecutively allocated host number (host code).
	// -> store unique remote Ips together with a host code (starting at 0; up to (2**14)-1)
	hm_hnum_remoteIp = new graphletHashMap(); // Auxiliary hash map for unique remote host numbers
	// Each remote port per protocol is associated with exactly one remoteIp.
	hm_remotePort_remoteIp_11 = new graphletHashMap(); // remotePort--remoteIP
	hm_remotePort_remoteIp_n1 = new graphletHashMap(); // remotePort--remoteIP
	hm_remotePort_remoteIp_1n = new graphletHashMap(); // remotePort--remoteIP
	hm_remotePort_remoteIp_nn = new graphletHashMap(); // remotePort--remoteIP
	// To store flow counts
	hm_remotePort_remoteIpE = new graphletHashMap(); // remotePort--remoteIP (extension)
	if (hap4nfsen) {
		nodeInfos = new CSummaryNodeInfos();
	}
}

/**
 * Destructor
 */
CGraphlet::~CGraphlet() {
	delete hm_localIp_prot;
	delete hm_prot_localPort_11;
	delete hm_prot_localPort_1n;
	delete hm_hnum_remoteIp;
	delete hm_localPort_remotePort_11;
	delete hm_localPort_remotePort_n1;
	delete hm_localPort_remotePort_1n;
	delete hm_localPort_remotePort_nn;
	delete hm_localPort_remotePortE;
	delete hm_remotePort_remoteIp_11;
	delete hm_remotePort_remoteIp_n1;
	delete hm_remotePort_remoteIp_1n;
	delete hm_remotePort_remoteIp_nn;
	delete hm_remotePort_remoteIpE;
	if (hap4nfsen) {
		delete nodeInfos;
	}
	outfs.close();
}

/**
 * Updates existing edge and adds the number of flows and packets from another edge
 *
 * \param fp2 Edge containing the additional number of flows and packets
 */
void CGraphlet::HashMapEdge::addflowsPackets(const HashMapEdge fp2) {
	valueC.flows += fp2.valueC.flows;
	valueB.packets += fp2.valueB.packets;
}

/**
 * Updates existing edge and adds the number of bytes and packets from another edge
 *
 * \param fp2 Edge containing the additional number of bytes and packets
 */
void CGraphlet::HashMapEdge::addBytesPackets(const HashMapEdge fp2) {
	valueA.bytes += fp2.valueA.bytes;
	valueB.packets += fp2.valueB.packets;
}

/**
 * Default constructor for edges, initializes all values with 0
 */
CGraphlet::HashMapEdge::HashMapEdge() {
	std::fill(ip.begin(), ip.end(), 0);
	valueA.proto = 0;
	valueB.port1 = 0;
	valueC.port2 = 0;
}

/**
 * Encodes protocol and ip into a hash map edge
 *
 * \param proto Protocol
 * \param ip (Local) IP address
 *
 * \return HashMapEdge containing encoded fields
 */
CGraphlet::HashMapEdge CGraphlet::ipProtoToEdge(const IPv6_addr & ip, const uint32_t proto) {
	HashMapEdge edge;
	edge.ip = ip;
	edge.valueA.proto = proto;
	return edge;
}

/**
 * Encodes protocol and port into a hash map edge
 *
 * \param proto Protocol
 * \param port Port
 *
 * \return HashMapEdge containing encoded fields
 */
CGraphlet::HashMapEdge CGraphlet::protoEportToEdge(const uint32_t proto, const uint64_t port) {
	HashMapEdge edge;
	edge.valueA.proto = proto;
	edge.valueB.port1 = port;
	return edge;
}

/**
 * Encodes host number and ip into a hash map edge
 *
 * \param hnum Host number
 * \param ip IP address
 *
 * \return HashMapEdge containing encoded fields
 */
CGraphlet::HashMapEdge CGraphlet::hNumRIpToEdge(const uint16_t hnum, const IPv6_addr & ip) {
	HashMapEdge edge;
	edge.valueA.hnum = hnum;
	edge.ip = ip;
	return edge;
}

/**
 * Encodes ports into a hash map edge
 *
 * \param port1 Port 1
 * \param port2 Port 2
 *
 * \return HashMapEdge containing encoded fields
 */
CGraphlet::HashMapEdge CGraphlet::ePort1EPort2ToEdge(const uint64_t port1, const uint64_t port2) {
	HashMapEdge edge;
	edge.valueB.port1 = port1;
	edge.valueC.port2 = port2;
	return edge;
}

/**
 * Encodes port and ip into a hash map edge
 *
 * \param port Port
 * \param ip IP address
 *
 * \return HashMapEdge containing encoded fields
 */
CGraphlet::HashMapEdge CGraphlet::ePortIpToEdge(const uint64_t port, const IPv6_addr & ip) {
	HashMapEdge edge;
	edge.valueB.port1 = port;
	edge.ip = ip;
	return edge;
}

/**
 * Encodes the number of packets and bytes into a hash map edge
 *
 * \param packets Number of packets
 * \param bytes Number of bytes
 *
 * \return HashMapEdge containing encoded fields
 */
CGraphlet::HashMapEdge CGraphlet::rBytesRPacketsToEdge(const uint32_t bytes, const uint32_t packets) {
	HashMapEdge edge;
	edge.valueA.bytes = bytes;
	edge.valueB.packets = packets;
	return edge;
}

/**
 * Encodes the number of packets and flows into a hash map edge
 *
 * \param packets Number of packets
 * \param flows Number of flows
 *
 * \return HashMapEdge containing encoded fields
 */
CGraphlet::HashMapEdge CGraphlet::flowsPacketsToEdge(const uint32_t flows, const uint32_t packets) {
	HashMapEdge edge;
	edge.valueB.packets = packets;
	edge.valueC.flows = flows;
	return edge;
}

/**
 * Encodes port and rolnum_clients into a hash map edge
 *
 * \param port Port
 * \param rolnum_clients rolnum_clients
 *
 * \return HashMapEdge containing encoded fields
 */
CGraphlet::HashMapEdge CGraphlet::ePortRolnumClientsToEdge(const uint64_t port, const uint64_t rolnum_clients) {
	HashMapEdge edge;
	edge.valueA.rolnum_clients = rolnum_clients;
	edge.valueB.port1 = port;
	return edge;
}

/**
 * Encodes the number of bytes and flows into a hash map edge
 *
 * \param bytes Number of bytes
 * \param flows Number of flows
 *
 * \return HashMapEdge containing encoded fields
 */
CGraphlet::HashMapEdge CGraphlet::bytesFlowsToEdge(const uint32_t bytes, const uint32_t flows) {
	HashMapEdge edge;
	edge.valueA.bytes = bytes;
	edge.valueC.flows = flows;
	return edge;
}

/**
 *	Add a single flow to graphlet
 *
 *	\param pflow	Flow to be added
 *	\param role_num	Role number assigned to single flow
 *	\param flow_idx	Index used to access flow in the active flow list
 */
void CGraphlet::add_single_flow(const cflow_t & pflow, int role_num, int flow_idx) {
	totalbytes += pflow.dOctets; // Update total byte count per graphlet

	if (hap4nfsen) {
		nodeInfos->addNodeInfo(CSummaryNodeInfo::generate_node_info(local_ip, pflow), pflow.localIP.toNumericString());
	}

	// Add flow to host profile graphlet
	// ---------------------------------
	// Avoid multiple graphlet edges

	// localIP -- protocol (key1/entry1)
	//
	// Check if localIp--prot edge is already contained in hash map: if not then add it.
	// Basically, we could leave localIP out of key as we assemble graphlets per localIP only.
	// But, taking it as a part of the key when can use the same hm type for all edges.
	uint8_t prot = pflow.prot;
	if (hap4nfsen) {
		nodeInfos->addNodeInfo(CSummaryNodeInfo::generate_node_info(proto, pflow), boost::lexical_cast<string>(static_cast<int> (prot)));
	}
	graphletHashKey myIpProtkey(pflow.localIP, prot);
	iterIpProt = hm_localIp_prot->find(myIpProtkey);
	if (iterIpProt == hm_localIp_prot->end()) {
		(*hm_localIp_prot)[myIpProtkey];
		(*hm_localIp_prot)[myIpProtkey] = ipProtoToEdge((IPv6_addr) (pflow.localIP), prot);
	}

	// protocol -- localPort (key2/entry2)
	//
	// Assemble localEport value.
	// Check if Prot--localPort edge is already contained in hash map: if not then add it
	// Use key for localEport without protocol type, but entry including protocol type
	uint64_t localEportKey = getLocalEportKey(map_protonum(prot), pflow.localPort);
	uint64_t localEport = getLocalEport(pflow.flowtype, localEportKey);
	if (hap4nfsen) {
		nodeInfos->addNodeInfo(CSummaryNodeInfo::generate_node_info(local_port, pflow), boost::lexical_cast<string>(localEport & LOCAL_EPORT0_MASK));
	}
	graphletHashKey myProtEportkey(prot, localEportKey);
	iterProtEport = hm_prot_localPort_11->find(myProtEportkey);
	if (iterProtEport == hm_prot_localPort_11->end()) {
		(*hm_prot_localPort_11)[myProtEportkey] = protoEportToEdge(prot, localEport);
	}

	/*
	// Update unique remote host list (auxiliary list for unique remote port labeling: a remote
	// port is associated with a remoteIP!). This list is maintained to assign to each remoteIP a unique
	// host number. As host numbers stored in hpg edges are limited to 12 bits the uniqueness is
	// not perfect but sufficiently good to distinguish ports that are not identical access points
	// to the transport layer as they use different protocols and are located on different hosts.
	//
	//  (key3/entry3)
	//
	uint32_t current_hostnum = 0;
	graphletHashKey myHnumIpkey(0, (IPv6_addr) (pflow.remoteIP)); // Use remoteIP as key only
	iterHnumIp = hm_hnum_remoteIp->find(myHnumIpkey);
	if (iterHnumIp == hm_hnum_remoteIp->end()) {
		(*hm_hnum_remoteIp)[myHnumIpkey] = hNumRIpToEdge(hostnum, (IPv6_addr) (pflow.localIP));
		current_hostnum = hostnum++; // May wrap around
	} else {
		// Fetch current host number from hash map
		current_hostnum = ((HashMapEdge) iterHnumIp->second).valueA.hnum;
	}
	*/

	// localPort -- remotePort  (key4/entry4)
	//
	// Assemble remoteEport value (use a 24 bit hash representing the ip)
	uint64_t remoteEport = getRemoteEport(pflow.flowtype, map_protonum(pflow.prot), pflow.remoteIP.get24bitHash(), pflow.remotePort, (uint16_t)role_num);
	if (hap4nfsen) {
		nodeInfos->addNodeInfo(CSummaryNodeInfo::generate_node_info(remote_port, pflow), boost::lexical_cast<string>(remoteEport));
	}
	graphletHashKey myEport2key(localEportKey, remoteEport);
	iterEport2 = hm_localPort_remotePort_11->find(myEport2key);
	if (iterEport2 == hm_localPort_remotePort_11->end()) {
		(*hm_localPort_remotePort_11)[myEport2key] = ePort1EPort2ToEdge(localEport, remoteEport);
	}

	// Use an extra hm to store byte and packet count of flow
	iterEport3 = hm_localPort_remotePortE->find(myEport2key);
	if (iterEport3 == hm_localPort_remotePortE->end()) {
		//(*hm_localPort_remotePortE)[myEport2key] = bytesFlowsToEdge(pflow.dOctets, pflow.dPkts);
		(*hm_localPort_remotePortE)[myEport2key] = rBytesRPacketsToEdge(pflow.dOctets, pflow.dPkts);
	}

	// remotePort -- remoteIP  (key5/entry5)

	// Handle multi-connected remote hosts
	struct CRoleMembership::sumnode_t * sn = proleMembership->get_summaryNode(pflow.remoteIP);
	if (sn != NULL && sn->clients > 1) {
		// Use summary identifier (a negative role number)
		uint32_t sumid = sn->role_num;
		graphletHashKey myEportIpkey(remoteEport, (uint64_t) sumid);
		if (hap4nfsen) {
			nodeInfos->addNodeInfo(CSummaryNodeInfo::generate_node_info(remote_ip, pflow), boost::lexical_cast<string>((uint64_t) sumid));
		}
		iterEportIp = hm_remotePort_remoteIp_1n->find(myEportIpkey);
		if (iterEportIp == hm_remotePort_remoteIp_1n->end()) {
			(*hm_remotePort_remoteIp_1n)[myEportIpkey] = ePortRolnumClientsToEdge(remoteEport, getRolnumClients(sumid, sn->clients));
		}
		// Use an extra hm to store flow count
		iterEport3 = hm_remotePort_remoteIpE->find(myEportIpkey);
		if (iterEport3 == hm_remotePort_remoteIpE->end()) {
			int packets = 0;
			int flows = sn->get_flowpacket_count(role_num, packets);
			(*hm_remotePort_remoteIpE)[myEportIpkey] = flowsPacketsToEdge(flows, packets);
		} else {
			// Link already exists: update link annotation
			HashMapEdge oldval = (HashMapEdge) iterEport3->second;
			int packets = 0;
			int flows = sn->get_flowpacket_count(role_num, packets);
			HashMapEdge newval = flowsPacketsToEdge(flows, packets);
			newval.addflowsPackets(oldval);
			(*hm_remotePort_remoteIpE)[myEportIpkey] = newval;
		}
	} else {
		// Use node with single remote IP address
		graphletHashKey myEportIpkey(remoteEport, pflow.remoteIP);
		//nodeInfos->addNodeInfo(CSummaryNodeInfo::generate_node_info(remote_ip, pflow), pflow.remoteIP.toIdString());
		iterEportIp = hm_remotePort_remoteIp_11->find(myEportIpkey);
		if (iterEportIp == hm_remotePort_remoteIp_11->end()) {
			(*hm_remotePort_remoteIp_11)[myEportIpkey] = ePortIpToEdge(remoteEport, pflow.remoteIP);
		}
		// Use an extra hm to store flow count
		iterEport3 = hm_remotePort_remoteIpE->find(myEportIpkey);
		if (iterEport3 == hm_remotePort_remoteIpE->end()) {
			(*hm_remotePort_remoteIpE)[myEportIpkey] = flowsPacketsToEdge(1, pflow.dPkts);
		} else {
			// Link already exists: update link annotation
			HashMapEdge oldval = (HashMapEdge) iterEport3->second;
			int packets = pflow.dPkts;
			int flows = 1;
			HashMapEdge newval = flowsPacketsToEdge(flows, packets);
			newval.addflowsPackets(oldval);
			(*hm_remotePort_remoteIpE)[myEportIpkey] = newval;
		}
	}
}

/**
 * Add a generic role to graphlet
 *
 * \param role Role to be added to the graphlet
 * \param parent_role "role"'s parent role
 * \param lastIP Last IP
 * \param flow_list List containing all CFlows
 *
 * \throw std::string Errormessage
 */
void CGraphlet::add_generic_role(CRole::role_t & role, const CRole::role_t& parent_role, IPv6_addr lastIP, Subflowlist flow_list) {
	if (dbg) {
		cout << "adding generic role(num:" << role.role_num << ", parent num:" << parent_role.role_num << ") with pattern:"
		      << util::graphletSummarizationToString(role.pattern) << ", parent pattern:" << util::graphletSummarizationToString(parent_role.pattern) << " with "
		      << role.flows << "flows" << endl;
	}

	bool is_fully_desummarized = role.pattern == single_flow;

	totalbytes += role.bytes;
	set<int> flows;
	flows.insert(parent_role.flow_set->begin(), parent_role.flow_set->end());
	if (parent_role.role_type == 'm' || parent_role.role_type == 'p') {
		for (set<CRole::role_t*>::const_iterator role_id = parent_role.role_set_->begin(); role_id != parent_role.role_set_->end(); role_id++) {
			flows.insert((*role_id)->flow_set->begin(), (*role_id)->flow_set->end());
		}
	}

	//cout<<flows.size()<<"/"<<role.flows<<endl;
	if (flows.size() == 0) {
		return;
	}assert(flows.size()>0);

	const cflow_t* flow = &(flow_list[*(flows.begin())]);
	if (hap4nfsen) {
		nodeInfos->addNodeInfo(CSummaryNodeInfo::generate_node_info(local_ip, ' ', role.pattern, flows, flow_list), flow->localIP.toNumericString());
	}

	// localIP -- protocol
	if (role.get_partition_association(local_ip, proto) != gpa_1_1) {
		cerr << "ERROR: unsupported graphlet association between partitions local_ip and proto" << endl;
		assert(false);
	}
	graphletHashKey myIpProtkey(lastIP, role.prot);
	if (hap4nfsen) {
		nodeInfos->addNodeInfo(CSummaryNodeInfo::generate_node_info(proto, role.role_type, role.pattern, flows, flow_list), boost::lexical_cast<string>(static_cast<int> (role.prot)));
	}
	iterIpProt = hm_localIp_prot->find(myIpProtkey);
	if (iterIpProt == hm_localIp_prot->end()) {
		(*hm_localIp_prot)[myIpProtkey] = ipProtoToEdge(lastIP, role.prot);
	}

	// protocol -- localPort
	graphlet_partition_association proto_lport_association = role.get_partition_association(proto, local_port);
	if (proto_lport_association != gpa_1_1 && proto_lport_association != gpa_1_n) {
		cerr << "ERROR: unsupported graphlet association between partitions proto and local_port" << endl;
		assert(false);
	}

	vector<uint64_t> localEports;
	vector<uint64_t> localEportKeys;
	for (set<int>::const_iterator flow_id = flows.begin(); flow_id != flows.end(); flow_id++) {
		const cflow_t* flow = &(flow_list[*flow_id]);
		if (proto_lport_association == gpa_1_1) {
			uint64_t localEportKey = getLocalEportKey(map_protonum(flow->prot), flow->localPort);
			uint64_t localEport = getLocalEport(role.flowtype, localEportKey);
			graphletHashKey myProtEportkey((uint64_t) role.prot, localEportKey);
			iterProtEport = hm_prot_localPort_11->find(myProtEportkey);
			if (iterProtEport == hm_prot_localPort_11->end()) {
				(*hm_prot_localPort_11)[myProtEportkey] = protoEportToEdge(role.prot, localEport);
			}
			//cout<<localEport<<"-"<<localEportKey<<"-"<<(localEport&LOCAL_EPORT0_MASK)<<"-"<<(localEportKey&LOCAL_EPORT0_MASK)<<endl;
			if (hap4nfsen) {
				nodeInfos->addNodeInfo(CSummaryNodeInfo::generate_node_info(local_port, role.role_type, role.pattern, flows, flow_list), boost::lexical_cast<string>(localEport & LOCAL_EPORT0_MASK));
			}
			localEports.push_back(localEport);
			localEportKeys.push_back(localEportKey);
		} else { // must be gpa_1_n
			//util::printFlow(*flow);
			uint64_t localEport = getLocalEport(role.flowtype, role.getSubRoleId(local_port, parent_role), role.flows);
			graphletHashKey myProtEportkey((uint64_t) role.prot, localEport);
			iterProtEport = hm_prot_localPort_1n->find(myProtEportkey);
			if (iterProtEport == hm_prot_localPort_1n->end()) {
				(*hm_prot_localPort_1n)[myProtEportkey] = protoEportToEdge(role.prot, localEport);
			}
			localEports.push_back(localEport);
			localEportKeys.push_back(0);
			if (hap4nfsen) {
				nodeInfos->addNodeInfo(CSummaryNodeInfo::generate_node_info(local_port, role.role_type, role.pattern, flows, flow_list), boost::lexical_cast<string>(localEport));
			}
			break; // no need to read the other flows
		}
	}

	assert(localEports.size() == localEportKeys.size());
	// localPort -- remotePort
	graphlet_partition_association lport_rport_association = role.get_partition_association(local_port, remote_port);
	uint32_t localEport_id = 0;
	vector<uint64_t> remoteEports;
	bool rp_sum_node_created = false;
	for (set<int>::const_iterator flow_id = flows.begin(); flow_id != flows.end(); flow_id++) {
		const cflow_t* flow = &(flow_list[*flow_id]);
		uint64_t localEport = localEports[localEport_id];
		uint64_t localEportKey = localEports[localEport_id];
		uint64_t remoteEport;
		graphletHashKey myEport2key((uint32_t) 0, (uint32_t) 0);
		if (lport_rport_association == gpa_1_1) {
			if (role.get_partition_association(remote_port, remote_ip) == gpa_1_1) {
				uint16_t f_id = (is_fully_desummarized)?(uint16_t)(*flow_id):0;
				remoteEport = getRemoteEport(role.flowtype, map_protonum(role.prot), flow->remoteIP.get24bitHash(), flow->remotePort, f_id);
			} else {
				remoteEport = getRemoteEport(role.flowtype, role.role_num, flow->remotePort);
			}
			myEport2key = graphletHashKey(localEportKey, remoteEport);
			iterEport2 = hm_localPort_remotePort_11->find(myEport2key);
			if (iterEport2 == hm_localPort_remotePort_11->end()) {
				(*hm_localPort_remotePort_11)[myEport2key] = ePort1EPort2ToEdge(localEport, remoteEport);
			}
			if (hap4nfsen) {
				nodeInfos->addNodeInfo(CSummaryNodeInfo::generate_node_info(remote_port, role.role_type, role.pattern, flows, flow_list), boost::lexical_cast<string>(remoteEport));
			}
		} else if (lport_rport_association == gpa_1_n) {
			remoteEport = getRemoteEport(role.flowtype, role.getSubRoleId(remote_port, parent_role), role.flows);
			myEport2key = graphletHashKey(localEportKey, remoteEport);
			iterEport2 = hm_localPort_remotePort_1n->find(myEport2key);
			if (iterEport2 == hm_localPort_remotePort_1n->end()) {
				(*hm_localPort_remotePort_1n)[myEport2key] = ePort1EPort2ToEdge(localEport, remoteEport);
			}
			if (!rp_sum_node_created) {
				if (hap4nfsen) {
					nodeInfos->addNodeInfo(CSummaryNodeInfo::generate_node_info(remote_port, role.role_type, role.pattern, flows, flow_list), boost::lexical_cast<string>(remoteEport));
				}
				rp_sum_node_created = true;
			}
		} else if (lport_rport_association == gpa_n_1) {
			localEport = localEports[0];
			// Update unique remote host list
			uint32_t current_hostnum = 0;
			graphletHashKey myHnumIpkey(0, (role.remoteIP)); // Use remoteIP as key only
			iterHnumIp = hm_hnum_remoteIp->find(myHnumIpkey);
			if (iterHnumIp == hm_hnum_remoteIp->end()) {
				(*hm_hnum_remoteIp)[myHnumIpkey] = hNumRIpToEdge(hostnum, role.remoteIP);
				current_hostnum = hostnum++; // May wrap around
			} else {
				// Fetch current host number from hash map
				current_hostnum = ((HashMapEdge) iterHnumIp->second).valueA.hnum;
			}
			// Assemble remoteEport value
			uint16_t f_id = (is_fully_desummarized)?(uint16_t)(*flow_id):0;
			remoteEport = getRemoteEport(role.flowtype, map_protonum(flow->prot), current_hostnum, flow->remotePort, f_id);
			myEport2key = graphletHashKey(localEport, remoteEport);
			iterEport2 = hm_localPort_remotePort_n1->find(myEport2key);
			if (iterEport2 == hm_localPort_remotePort_n1->end()) {
				(*hm_localPort_remotePort_n1)[myEport2key] = ePort1EPort2ToEdge(localEport, remoteEport);
			}
			if (hap4nfsen) {
				nodeInfos->addNodeInfo(CSummaryNodeInfo::generate_node_info(remote_port, role.role_type, role.pattern, flows, flow_list), boost::lexical_cast<string>(remoteEport));
			}
		} else { // must be gpa_n_n
			remoteEport = getRemoteEport(role.flowtype, role.getSubRoleId(remote_port, parent_role), role.flows);
			myEport2key = graphletHashKey(localEport, remoteEport);
			iterEport2 = hm_localPort_remotePort_nn->find(myEport2key);
			if (iterEport2 == hm_localPort_remotePort_nn->end()) {
				(*hm_localPort_remotePort_nn)[myEport2key] = ePort1EPort2ToEdge(localEport, remoteEport);
			}
			if (!rp_sum_node_created) {
				if (hap4nfsen) {
					nodeInfos->addNodeInfo(CSummaryNodeInfo::generate_node_info(remote_port, role.role_type, role.pattern, flows, flow_list), boost::lexical_cast<string>(remoteEport));
				}
				rp_sum_node_created = true;
			}
		}

		// Use an extra hm to store byte and packet count of role
		iterEport3 = hm_localPort_remotePortE->find(myEport2key);
		if (iterEport3 == hm_localPort_remotePortE->end()) {
			HashMapEdge newEdge;
			if (lport_rport_association == gpa_n_n) {
				newEdge = rBytesRPacketsToEdge(role.bytes, role.packets);
			} else {
				//cerr<<"new l_port<->r_port edge(r_port,bytes,pckts):\t"<<flow->remotePort<<"-"<<flow->dOctets<<"-"<<flow->dPkts<<endl;
				newEdge = rBytesRPacketsToEdge(flow->dOctets, flow->dPkts);
			}
			(*hm_localPort_remotePortE)[myEport2key] = newEdge;
		} else { // update existing edge
			HashMapEdge oldval = (HashMapEdge) iterEport3->second;
			HashMapEdge newval = rBytesRPacketsToEdge(flow->dOctets, flow->dPkts);
			newval.addBytesPackets(oldval);
			(*hm_localPort_remotePortE)[myEport2key] = newval;

		}
		remoteEports.push_back(remoteEport);
		++localEport_id;
		if (lport_rport_association == gpa_n_n) {
			break; // only one connection between summary nodes -> no need to go through all ips
		}
	}

	// remotePort -- remoteIP
	graphlet_partition_association rport_rip_association = role.get_partition_association(remote_port, remote_ip);
	uint32_t remoteEport_id = 0;
	bool rip_sum_node_created = false;
	for (set<int>::iterator flow_id = flows.begin(); flow_id != flows.end(); flow_id++) {
		const cflow_t* flow = &(flow_list[*flow_id]);
		uint64_t remoteEport = remoteEports[remoteEport_id];
		struct CRoleMembership::sumnode_t * sn = proleMembership->get_summaryNode(flow->remoteIP);
		if (rport_rip_association == gpa_1_n) {
			if (sn != NULL && sn->clients >= 1) {
				// Use summary identifier (a negative role number)
				graphletHashKey myEportIpkey(remoteEport, sn->role_num);
				if (hap4nfsen) {
					nodeInfos->addNodeInfo(CSummaryNodeInfo::generate_node_info(remote_ip, role.role_type, role.pattern, flows, flow_list), getSummaryNodeIdString(sn));
				}
				if (sn->clients == 1) {
					iterEportIp = hm_remotePort_remoteIp_11->find(myEportIpkey);
					if (iterEportIp == hm_remotePort_remoteIp_11->end()) {
						(*hm_remotePort_remoteIp_11)[myEportIpkey] = ePortIpToEdge(remoteEport, flow->remoteIP);
					}
				} else {
					iterEportIp = hm_remotePort_remoteIp_1n->find(myEportIpkey);
					if (iterEportIp == hm_remotePort_remoteIp_1n->end()) {
						(*hm_remotePort_remoteIp_1n)[myEportIpkey] = ePortRolnumClientsToEdge(remoteEport, getRolnumClients(sn->role_num, sn->clients));
					}
				}
				// Use an extra hm to store flow count
				iterEport3 = hm_remotePort_remoteIpE->find(myEportIpkey);
				if (iterEport3 == hm_remotePort_remoteIpE->end()) {
					(*hm_remotePort_remoteIpE)[myEportIpkey] = flowsPacketsToEdge(1, flow->dPkts);
				} else {
					// Link already exists: update link annotation
					HashMapEdge oldval = (HashMapEdge) iterEport3->second;
					HashMapEdge newval = flowsPacketsToEdge(1, flow->dPkts);
					newval.addflowsPackets(oldval);
					(*hm_remotePort_remoteIpE)[myEportIpkey] = newval;
				}
			} else { // add new summary node
				//cerr << "adding new node" << endl;
				graphletHashKey myEportIpkey(remoteEport, role.role_num);
				if (!rip_sum_node_created) {
					/*
					if (hap4nfsen) {
						nodeInfos->addNodeInfo(CSummaryNodeInfo::generate_node_info(remote_ip, role.role_type, flows, flow_list), boost::lexical_cast<string>(((uint64_t)role.role_num)&ROLE_NR_BIT_MASK));
					}
					*/
					rip_sum_node_created = true;
				}
				iterEportIp = hm_remotePort_remoteIp_1n->find(myEportIpkey);
				if (iterEportIp == hm_remotePort_remoteIp_1n->end()) {
					(*hm_remotePort_remoteIp_1n)[myEportIpkey] = ePortRolnumClientsToEdge(remoteEport,
					      getRolnumClients(role.getSubRoleId(remote_ip, parent_role), role.rIP_set->size()));
				}
				// Use an extra hm to store flow count
				iterEport3 = hm_remotePort_remoteIpE->find(myEportIpkey);
				if (iterEport3 == hm_remotePort_remoteIpE->end()) {
					(*hm_remotePort_remoteIpE)[myEportIpkey] = flowsPacketsToEdge(role.flows, role.packets);
				}
			}
		} else if (rport_rip_association == gpa_1_1) {
			graphletHashKey myEportIpkey(remoteEport, flow->remoteIP);

			if (sn != NULL && sn->role_map.size()>=2) {
				if (hm_remotePort_remoteIp_11->find(myEportIpkey) == hm_remotePort_remoteIp_11->end()) {
					myEportIpkey = graphletHashKey(remoteEport, sn->role_num);
				}
			}
			//nodeInfos->addNodeInfo(CSummaryNodeInfo::generate_node_info(remote_ip, role.role_type, flows, flow_list), flow->remoteIP.toIdString());
			iterEportIp = hm_remotePort_remoteIp_11->find(myEportIpkey);
			if (iterEportIp == hm_remotePort_remoteIp_11->end()) {
				(*hm_remotePort_remoteIp_11)[myEportIpkey] = ePortIpToEdge(remoteEport, flow->remoteIP);
			}
			// Use an extra hm to store flow count
			iterEport3 = hm_remotePort_remoteIpE->find(myEportIpkey);
			if (iterEport3 == hm_remotePort_remoteIpE->end()) {
				(*hm_remotePort_remoteIpE)[myEportIpkey] = flowsPacketsToEdge(1, flow->dPkts);
			} else {
				// Link already exists: update link annotation
				HashMapEdge oldval = (HashMapEdge) iterEport3->second;
				HashMapEdge newval = flowsPacketsToEdge(1, flow->dPkts);
				newval.addflowsPackets(oldval);
				(*hm_remotePort_remoteIpE)[myEportIpkey] = newval;
			}
		} else { // must be gpa_n_1 or gpa_n_n
			remoteEport = remoteEports[0];
			int client_count = role.rIP_set->size();
			for (set<IPv6_addr>::const_iterator it = role.rIP_set->begin(); (rport_rip_association == gpa_n_n) && (it != role.rIP_set->end()); it++) {
				struct CRoleMembership::sumnode_t * sn = proleMembership->get_summaryNode(*it);
				if (sn != NULL) {
					client_count--;
					// Add link to multi-summarynode
					graphletHashKey myEportIpkey(remoteEport, sn->role_num);
					if (sn->clients > 1) {
						iterEportIp = hm_remotePort_remoteIp_nn->find(myEportIpkey);
						if (iterEportIp == hm_remotePort_remoteIp_nn->end()) {
							(*hm_remotePort_remoteIp_nn)[myEportIpkey] = ePortRolnumClientsToEdge(remoteEport, getRolnumClients(sn->role_num, sn->clients));
						}
					} else {
						iterEportIp = hm_remotePort_remoteIp_n1->find(myEportIpkey);
						if (iterEportIp == hm_remotePort_remoteIp_n1->end()) {
							(*hm_remotePort_remoteIp_n1)[myEportIpkey] = ePortIpToEdge(remoteEport, *it);
						}
					}
					if (!rip_sum_node_created) {
						if (hap4nfsen) {
							nodeInfos->addNodeInfo(CSummaryNodeInfo::generate_node_info(remote_ip, role.role_type, role.pattern, flows, flow_list), getSummaryNodeIdString(sn));
						}
						rip_sum_node_created = true;
					}
					// Use an extra hm to store flow count
					iterEport3 = hm_remotePort_remoteIpE->find(myEportIpkey);
					if (iterEport3 == hm_remotePort_remoteIpE->end()) {
						int packets = 0;
						int flows = sn->get_flowpacket_count(parent_role.role_num, packets);
						(*hm_remotePort_remoteIpE)[myEportIpkey] = flowsPacketsToEdge(flows, packets);
					} else {
					}
					int sn_packets = 0;
					int sn_flows = proleMembership->get_role_flowpacket_count(*it, parent_role.role_num, sn_packets);
					if (sn_flows == 0) {
						stringstream error;
						error << "Critical error in " << __FILE__ << ": #" << __LINE__ << "\n\n";
						throw error.str();
					}
					role.flows -= sn_flows;
					role.packets -= sn_packets;
				}
			}
			if (client_count == 1 || rport_rip_association == gpa_n_1) { // Show single client with it's IP address
				// Use node with single remote IP address
				IPv6_addr remoteIP = flow->remoteIP;
				graphletHashKey myEportIpkey(remoteEport, remoteIP);
				//nodeInfos->addNodeInfo(CSummaryNodeInfo::generate_node_info(remote_ip, role.role_type, flows, flow_list), remoteIP.toIdString());
				iterEportIp = hm_remotePort_remoteIp_11->find(myEportIpkey);
				if (iterEportIp == hm_remotePort_remoteIp_11->end()) {
					(*hm_remotePort_remoteIp_11)[myEportIpkey] = ePortIpToEdge(remoteEport, remoteIP);
				}
				// Use an extra hm to store flow count
				iterEport3 = hm_remotePort_remoteIpE->find(myEportIpkey);
				if (iterEport3 == hm_remotePort_remoteIpE->end()) {
					HashMapEdge edge;
					if (rport_rip_association == gpa_n_1) {
						edge = flowsPacketsToEdge(1, flow->dPkts);
					} else { // rport_rip_association == gpa_n_n
						edge = flowsPacketsToEdge(role.flows, role.packets);
					}
					(*hm_remotePort_remoteIpE)[myEportIpkey] = edge;
				} else {
					HashMapEdge oldval = (HashMapEdge) iterEport3->second;
					HashMapEdge newval = flowsPacketsToEdge(1, flow->dPkts);
					newval.addflowsPackets(oldval);
					(*hm_remotePort_remoteIpE)[myEportIpkey] = newval;
				}
			} else if (client_count > 0) { // Avoid summary node for zero clients
				graphletHashKey myEportIpkey(remoteEport, (uint64_t) role.role_num);
				if (hap4nfsen) {
					nodeInfos->addNodeInfo(CSummaryNodeInfo::generate_node_info(remote_ip, role.role_type, role.pattern, flows, flow_list), boost::lexical_cast<string>((uint64_t) role.role_num));
				}
				iterEportIp = hm_remotePort_remoteIp_nn->find(myEportIpkey);
				if (iterEportIp == hm_remotePort_remoteIp_nn->end()) {
					// Store #clients as node annotation
					(*hm_remotePort_remoteIp_nn)[myEportIpkey] = ePortRolnumClientsToEdge(remoteEport, getRolnumClients(role.role_num, client_count));
				}
				// Use an extra hm to store flow count
				iterEport3 = hm_remotePort_remoteIpE->find(myEportIpkey);
				if (iterEport3 == hm_remotePort_remoteIpE->end()) {
					(*hm_remotePort_remoteIpE)[myEportIpkey] = flowsPacketsToEdge(role.flows, role.packets);
				}
			}
		}
		++remoteEport_id;
		if (rport_rip_association == gpa_n_n) {
			break; // only a single connection between two summary nodes. no need to check all flows.
		}
	}
}

/**
 * Generates an id used in DOT file to identify a summary node
 *
 * \param node A summary node
 *
 * \return std::string The generated id
 */
inline std::string CGraphlet::getSummaryNodeIdString(const CRoleMembership::sumnode_t* node) {
	hpg_field tmp_fld;
	tmp_fld.reset();
	tmp_fld.eightbytevalue.data = getRolnumClients(node->role_num, node->clients);
	IPv6_addr id(tmp_fld.data);
	return id.toNumericString();
}

/**
 * Encodes flow-type, role number and flow_count into a 8 byte value
 *
 * \param flow_type Flow-type(see hpg.h)
 * \param role_nr Role number
 * \param flow_count Number of flows
 *
 * \return uint64_t 8 byte number with fields encoded according to the HPG specification
 */
inline uint64_t CGraphlet::getLocalEport(const uint8_t flow_type, const uint32_t role_nr, const uint32_t flow_count) {
	uint64_t localEportKey = (((uint64_t) role_nr & ROLE_NR_BIT_MASK) << ROLE_SHIFT3) + (flow_count & FLOW_COUNT_BIT_MASK);
	return getLocalEport(flow_type, localEportKey);
}
/**
 * Encodes flow-type and remote port into a 8 byte value
 *
 * \param flow_type Flow-type(see hpg.h)
 * \param localEportKey LocalEportKey
 *
 * \return uint64_t 8 byte number with fields encoded according to the HPG specification
 */
inline uint64_t CGraphlet::getLocalEport(const uint8_t flow_type, const uint64_t localEportKey) {
	return localEportKey + ((uint64_t) flow_type << FLOWTYPE_SHIFT3);
}
/**
 * Encodes porto and local port into a 8 byte value
 *
 * \param protocol Protocol
 * \param local_port Local port
 *
 * \return uint64_t 8 byte number with fields encoded according to the HPG specification
 */
inline uint64_t CGraphlet::getLocalEportKey(const uint8_t protocol, const uint16_t local_port) {
	return ((uint64_t) protocol << PROTCODE_SHIFT3) + local_port;
}

/**
 * Encodes flow-type, hostnum and remote port into a 8 byte value
 *
 * \param flowtype Flow-type(see hpg.h)
 * \param hostnum Host number
 * \param remote_port Remote port
 *
 * \return uint64_t 8 byte number with fields encoded according to the HPG specification
 */
inline uint64_t CGraphlet::getRemoteEport(const uint8_t flowtype, const uint32_t role_num, const uint32_t remote_port) {
	uint8_t color = flowtype2colorcode(flowtype);
	uint64_t color_shift = ((uint64_t) color << COLORTYPE_SHIFT);
	uint64_t role_flowtype_shift = ((uint64_t) flowtype << FLOWTYPE_SHIFT3);
	return color_shift + role_flowtype_shift + (((uint64_t) role_num & ROLE_NR_BIT_MASK) << ROLE_SHIFT3) + (remote_port & FLOW_COUNT_BIT_MASK);
}

/**
 * Encodes flow-type, porto, hostnum and remote port into a 8 byte value
 *
 * \param flowtype Flow-type(see hpg.h)
 * \param protocol Protocol
 * \param hostnum Host number
 * \param remote_port Remote port
 * \param flow_id Flow identifyer(subflowlist index)
 * \return uint64_t 8 byte number with fields encoded according to the HPG specification
 */
inline uint64_t CGraphlet::getRemoteEport(const uint8_t flowtype, const uint8_t protocol, const uint32_t hostnum, const uint16_t remote_port, const uint16_t flow_id) {
	// key has to be split to fit unused space
	uint8_t key_p1 = flow_id >> sizeof(uint8_t); // second byte
	uint8_t key_p2 = flow_id & 0xf; // first byte
	uint8_t color = flowtype2colorcode(flowtype);
	uint64_t color_shift = ((uint64_t) color << COLORTYPE_SHIFT);
	uint64_t flow_key = (((uint64_t)key_p1) << (sizeof(uint16_t)*8)) + (((uint64_t)key_p2) << FLOWTYPE_SHIFT3);
	return color_shift + ((uint64_t) protocol << PROTCODE_SHIFT3) + (((uint64_t) hostnum & HOSTNUM_BIT_MASK) << HOSTNUM_SHIFT) + remote_port + flow_key;
}

/**
 * Encodes role number and client count into a 8 byte value
 *
 * \param role_nr Role Number
 * \param client_count Number of clients
 * \return uint64_t 8 byte number with fields encoded according to the HPG specification
 */
inline uint64_t CGraphlet::getRolnumClients(const uint32_t role_nr, const uint32_t client_count) {
	return (((uint64_t) role_nr & ROLE_NR_BIT_MASK) << ROLE_SHIFT3) + (client_count & CLIENT_COUNT_BIT_MASK);
}

/**
 *	Finalize graphlet and write hpg edge data to file.
 *
 *	\param	graphlet_nr	Number to assign to graphlet finalized
 */
void CGraphlet::finalize_graphlet(int graphlet_nr) {
	hpg_field value[3];
	value[0].reset();
	value[1].reset();
	value[2].reset();
	// Put a version info edge right at the begin
	value[0].eightbytevalue.data = (graphlet_nr << 4) + version;
	value[1].eightbytevalue.data = 3;
	value[2].eightbytevalue.data = 0;
	outfs.write((char *) value, sizeof(value));

	// localIP_prot
	// ============
	rank_t rank = localIP_prot;
	value[0].eightbytevalue.data = (graphlet_nr << 4) + rank;
	int localIP_prot_count = 0;
	for (iterIpProt = hm_localIp_prot->begin(); iterIpProt != hm_localIp_prot->end(); iterIpProt++) {
		value[1].reset();
		value[2].reset();
		HashMapEdge edge = (HashMapEdge) iterIpProt->second;
		value[1].data = edge.ip; // localIP
		value[2].eightbytevalue.data = edge.valueA.proto/* & 0xff*/; // prot
		outfs.write((char *) value, sizeof(value));
		localIP_prot_count++;
		//cout<<"[w]value[0].fourbytevalue.data:"<<value[0].fourbytevalue.data<<endl;
		//cout<<"[w]value[1].fourbytevalue.data:"<<value[1].fourbytevalue.data<<endl;
		//cout<<"[w]value[2].fourbytevalue.data:"<<value[2].fourbytevalue.data<<endl;
	}

	// prot_localPort
	// ==============
	rank = prot_localPort;
	value[0].eightbytevalue.data = (graphlet_nr << 4) + rank;
	int prot_localPort_count = 0;
	for (iterProtEport = hm_prot_localPort_11->begin(); iterProtEport != hm_prot_localPort_11->end(); iterProtEport++) {
		value[1].reset();
		value[2].reset();
		HashMapEdge edge = (HashMapEdge) iterProtEport->second;
		value[1].eightbytevalue.data = edge.valueA.proto; // prot
		value[2].eightbytevalue.data = edge.valueB.port1; // localPort (eport)
		outfs.write((char *) value, sizeof(value));
		prot_localPort_count++;
	}

	// prot_localPortSum
	// ==============
	rank = prot_localPortSum;
	value[0].eightbytevalue.data = (graphlet_nr << 4) + rank;
	for (iterProtEport = hm_prot_localPort_1n->begin(); iterProtEport != hm_prot_localPort_1n->end(); iterProtEport++) {
		value[1].reset();
		value[2].reset();
		HashMapEdge edge = (HashMapEdge) iterProtEport->second;
		value[1].eightbytevalue.data = edge.valueA.proto; // prot
		value[2].eightbytevalue.data = edge.valueB.port1; // localPort (eport)
		outfs.write((char *) value, sizeof(value));
		prot_localPort_count++;
	}

	// localPort_remotePort
	// ====================
	rank = localPort_remotePort;
	value[0].eightbytevalue.data = (graphlet_nr << 4) + rank;
	int localPort_remotePort_count = 0;
	for (iterEport2 = hm_localPort_remotePort_11->begin(); iterEport2 != hm_localPort_remotePort_11->end(); iterEport2++) {
		value[1].reset();
		value[2].reset();
		HashMapEdge edge = (HashMapEdge) iterEport2->second;
		value[1].eightbytevalue.data = edge.valueB.port1; // localPort (eport)
		value[2].eightbytevalue.data = edge.valueC.port2; // remotePort (eport)
		outfs.write((char *) value, sizeof(value));

		// Process extra info as an additional edge entry
		rank_t rankE = edge_label;
		hpg_field valueE[3];
		valueE[0].reset();
		valueE[1].reset();
		valueE[2].reset();
		valueE[0].eightbytevalue.data = (graphlet_nr << 4) + rankE;
		iterEport3 = hm_localPort_remotePortE->find(iterEport2->first);
		if (iterEport3 != hm_localPort_remotePortE->end()) {
			HashMapEdge edge = (HashMapEdge) iterEport3->second;
			valueE[1].eightbytevalue.data = edge.valueA.bytes; // Bytes
			valueE[2].eightbytevalue.data = edge.valueB.packets; // Packets
			outfs.write((char *) valueE, sizeof(valueE));
		} else {
			cerr << "ERROR: key not found in hm_localPort_remotePortE\n\n";
		}

		localPort_remotePort_count++;
	}

	// localPortSum_remotePort
	// ====================
	rank = localPortSum_remotePort;
	value[0].eightbytevalue.data = (graphlet_nr << 4) + rank;
	for (iterEport2 = hm_localPort_remotePort_n1->begin(); iterEport2 != hm_localPort_remotePort_n1->end(); iterEport2++) {
		value[1].reset();
		value[2].reset();
		HashMapEdge edge = (HashMapEdge) iterEport2->second;
		value[1].eightbytevalue.data = edge.valueB.port1; // localPort (eport)
		value[2].eightbytevalue.data = edge.valueC.port2; // remotePort (eport)
		outfs.write((char *) value, sizeof(value));

		// Process extra info as an additional edge entry
		rank_t rankE = edge_label;
		hpg_field valueE[3];
		valueE[0].eightbytevalue.data = (graphlet_nr << 4) + rankE;
		iterEport3 = hm_localPort_remotePortE->find(iterEport2->first);
		if (iterEport3 != hm_localPort_remotePortE->end()) {
			HashMapEdge edge = (HashMapEdge) iterEport3->second;
			valueE[1].eightbytevalue.data = edge.valueA.bytes; // Bytes
			valueE[2].eightbytevalue.data = edge.valueB.packets; // Packets
			outfs.write((char *) valueE, sizeof(valueE));
		} else {
			cerr << "ERROR: key not found in hm_localPort_remotePortE\n\n";
		}

		localPort_remotePort_count++;
	}

	// localPort_remotePortSum
	// ====================
	rank = localPort_remotePortSum;
	value[0].eightbytevalue.data = (graphlet_nr << 4) + rank;
	for (iterEport2 = hm_localPort_remotePort_1n->begin(); iterEport2 != hm_localPort_remotePort_1n->end(); iterEport2++) {
		value[1].reset();
		value[2].reset();
		HashMapEdge edge = (HashMapEdge) iterEport2->second;
		value[1].eightbytevalue.data = edge.valueB.port1; // localPort (eport)
		value[2].eightbytevalue.data = edge.valueC.port2; // remotePort (eport)
		//uint16_t rn = edge.valueC.port2&0xffff;
		//uint16_t cl = (edge.valueC.port2&0xffff0000)>>16;
		//uint16_t rn2 = (edge.valueC.port2>>16)%256;
		//cout<<rn<<"|"<<cl<<"|"<<rn2<<endl;
		//cout<<edge.valueA.rolnum_clients<<endl;
		outfs.write((char *) value, sizeof(value));

		// Process extra info as an additional edge entry
		rank_t rankE = edge_label;
		hpg_field valueE[3];
		valueE[0].eightbytevalue.data = (graphlet_nr << 4) + rankE;
		iterEport3 = hm_localPort_remotePortE->find(iterEport2->first);
		if (iterEport3 != hm_localPort_remotePortE->end()) {
			HashMapEdge edge = (HashMapEdge) iterEport3->second;
			valueE[1].eightbytevalue.data = edge.valueA.bytes; // Bytes
			valueE[2].eightbytevalue.data = edge.valueB.packets; // Packets
			outfs.write((char *) valueE, sizeof(valueE));
		} else {
			cerr << "ERROR: key not found in hm_localPort_remotePortE\n\n";
		}

		localPort_remotePort_count++;
	}

	// localPortSum_remotePortSum
	// ====================
	rank = localPortSum_remotePortSum;
	value[0].eightbytevalue.data = (graphlet_nr << 4) + rank;
	for (iterEport2 = hm_localPort_remotePort_nn->begin(); iterEport2 != hm_localPort_remotePort_nn->end(); iterEport2++) {
		value[1].reset();
		value[2].reset();
		HashMapEdge edge = (HashMapEdge) iterEport2->second;
		value[1].eightbytevalue.data = edge.valueB.port1; // localPort (eport)
		value[2].eightbytevalue.data = edge.valueC.port2; // remotePort (eport)
		outfs.write((char *) value, sizeof(value));

		// Process extra info as an additional edge entry
		rank_t rankE = edge_label;
		hpg_field valueE[3];
		valueE[0].eightbytevalue.data = (graphlet_nr << 4) + rankE;
		iterEport3 = hm_localPort_remotePortE->find(iterEport2->first);
		if (iterEport3 != hm_localPort_remotePortE->end()) {
			HashMapEdge edge = (HashMapEdge) iterEport3->second;
			valueE[1].eightbytevalue.data = edge.valueA.bytes; // Bytes
			valueE[2].eightbytevalue.data = edge.valueB.packets; // Packets
			outfs.write((char *) valueE, sizeof(valueE));
		} else {
			cerr << "ERROR: key not found in hm_localPort_remotePortE\n\n";
		}

		localPort_remotePort_count++;
	}

	// remotePort_remoteIp
	// ===================
	rank = remotePort_remoteIP;
	value[0].eightbytevalue.data = (graphlet_nr << 4) + rank;
	int remotePort_remoteIP_count = 0;
	for (iterEportIp = hm_remotePort_remoteIp_11->begin(); iterEportIp != hm_remotePort_remoteIp_11->end(); iterEportIp++) {
		value[1].reset();
		value[2].reset();
		HashMapEdge edge = (HashMapEdge) iterEportIp->second;
		value[1].eightbytevalue.data = edge.valueB.port1; // remotePort (eport)
		value[2].data = edge.ip; // remoteIp (eport)
		outfs.write((char *) value, sizeof(value));
		// Process extra info as an additional edge entry
		rank_t rankE = edge_label;
		hpg_field valueE[3];
		valueE[0].eightbytevalue.data = (graphlet_nr << 4) + rankE;
		iterEport3 = hm_remotePort_remoteIpE->find(iterEportIp->first);
		if (iterEport3 != hm_remotePort_remoteIpE->end()) {
			HashMapEdge edge = (HashMapEdge) iterEport3->second;
			valueE[1].eightbytevalue.data = edge.valueC.flows; // Flows
			double flows = (double) valueE[1].eightbytevalue.data;
			double packets = (double) edge.valueB.packets;
			//cout<<"remotePort_remoteIp"<<((double)valueE[1].fourbytevalue.data)<<"-"<<((double)edge.valueB.packets)<<endl;
			if (flows == 0) {
				cerr << "ERROR in CGraphlet::finalize_graphlet(): invalid flow (packet) count 0 (" << packets << ")\n";
				valueE[2].eightbytevalue.data = 0;
			} else {
				double ppf = packets / flows;
				uint32_t ppf10 = (uint32_t) (10.0 * ppf);
				valueE[2].eightbytevalue.data = ppf10 | 0x80000000; // Packets
			}
			outfs.write((char *) valueE, sizeof(valueE));
		}
		remotePort_remoteIP_count++;
	}

	// remotePortSum_remoteIP
	// ====================
	rank = remotePortSum_remoteIP;
	value[0].eightbytevalue.data = (graphlet_nr << 4) + rank;
	for (iterEportIp = hm_remotePort_remoteIp_n1->begin(); iterEportIp != hm_remotePort_remoteIp_n1->end(); iterEportIp++) {
		value[1].reset();
		value[2].reset();
		HashMapEdge edge = (HashMapEdge) iterEportIp->second;
		value[1].eightbytevalue.data = edge.valueB.port1; // remotePort (eport)
		value[2].data = edge.ip; // remoteIp (eport)
		outfs.write((char *) value, sizeof(value));
		// Process extra info as an additional edge entry
		rank_t rankE = edge_label;
		hpg_field valueE[3];
		valueE[0].eightbytevalue.data = (graphlet_nr << 4) + rankE;
		iterEport3 = hm_remotePort_remoteIpE->find(iterEportIp->first);
		if (iterEport3 != hm_remotePort_remoteIpE->end()) {
			HashMapEdge edge = (HashMapEdge) iterEport3->second;
			valueE[1].eightbytevalue.data = edge.valueC.flows; // Flows
			double flows = (double) valueE[1].eightbytevalue.data;
			double packets = (double) edge.valueB.packets; // packets
			if (flows == 0) {
				cerr << "ERROR in CGraphlet::finalize_graphlet(): invalid flow (packet) count 0 (" << packets << ")\n";
				valueE[2].eightbytevalue.data = 0;
			} else {
				double ppf = packets / flows;
				uint32_t ppf10 = (uint32_t) (10.0 * ppf);
				valueE[2].eightbytevalue.data = ppf10 | 0x80000000; // Packets
			}
			outfs.write((char *) valueE, sizeof(valueE));
		}
		remotePort_remoteIP_count++;
	}

	// remotePort_remoteIPsum
	// ====================
	rank = remotePort_remoteIPsum;
	value[0].eightbytevalue.data = (graphlet_nr << 4) + rank;
	for (iterEportIp = hm_remotePort_remoteIp_1n->begin(); iterEportIp != hm_remotePort_remoteIp_1n->end(); iterEportIp++) {
		value[1].reset();
		value[2].reset();
		HashMapEdge edge = (HashMapEdge) iterEportIp->second;
		value[1].eightbytevalue.data = edge.valueB.port1; // remotePort (eport)
		value[2].eightbytevalue.data = edge.valueA.rolnum_clients; // 24bit: role number, 24bit: #clients/peers
		outfs.write((char *) value, sizeof(value));
		// Process extra info as an additional edge entry
		rank_t rankE = edge_label;
		hpg_field valueE[3];
		valueE[0].eightbytevalue.data = (graphlet_nr << 4) + rankE;
		iterEport3 = hm_remotePort_remoteIpE->find(iterEportIp->first);
		if (iterEport3 != hm_remotePort_remoteIpE->end()) {
			HashMapEdge edge = (HashMapEdge) iterEport3->second;
			valueE[1].eightbytevalue.data = edge.valueC.flows; // Flows
			double flows = (double) valueE[1].eightbytevalue.data;
			double packets = (double) edge.valueB.packets; // packets
			if (flows == 0) {
				cerr << "ERROR in CGraphlet::finalize_graphlet(): invalid flow (packet) count 0 (" << packets << ")\n";
				valueE[2].eightbytevalue.data = 0;
			} else {
				double ppf = packets / flows;
				uint32_t ppf10 = (uint32_t) (10.0 * ppf);
				valueE[2].eightbytevalue.data = ppf10 | 0x80000000; // Packets
			}
			outfs.write((char *) valueE, sizeof(valueE));
		}
		remotePort_remoteIP_count++;
	}

	// remotePortSum_remoteIPsum
	// ====================
	rank = remotePortSum_remoteIPsum;
	value[0].eightbytevalue.data = (graphlet_nr << 4) + rank;
	for (iterEportIp = hm_remotePort_remoteIp_nn->begin(); iterEportIp != hm_remotePort_remoteIp_nn->end(); iterEportIp++) {
		value[1].reset();
		value[2].reset();
		HashMapEdge edge = (HashMapEdge) iterEportIp->second;
		value[1].eightbytevalue.data = edge.valueB.port1; // remotePort (eport)
		value[2].eightbytevalue.data = edge.valueA.rolnum_clients; // 24bit: role number, 24bit: #clients/peers
		outfs.write((char *) value, sizeof(value));
		// Process extra info as an additional edge entry
		rank_t rankE = edge_label;
		hpg_field valueE[3];
		valueE[0].eightbytevalue.data = (graphlet_nr << 4) + rankE;
		iterEport3 = hm_remotePort_remoteIpE->find(iterEportIp->first);
		if (iterEport3 != hm_remotePort_remoteIpE->end()) {
			HashMapEdge edge = (HashMapEdge) iterEport3->second;
			valueE[1].eightbytevalue.data = edge.valueC.flows; // Flows
			double flows = (double) valueE[1].eightbytevalue.data;
			double packets = (double) edge.valueB.packets; // packets
			if (flows == 0) {
				cerr << "ERROR in CGraphlet::finalize_graphlet(): invalid flow (packet) count 0 (" << packets << ")\n";
				valueE[2].eightbytevalue.data = 0;
			} else {
				double ppf = packets / flows;
				uint32_t ppf10 = (uint32_t) (10.0 * ppf);
				valueE[2].eightbytevalue.data = ppf10 | 0x80000000; // Packets
			}
			outfs.write((char *) valueE, sizeof(valueE));
		}
		remotePort_remoteIP_count++;
	}

	// Finally, add the pseudo edge for total byte count
	// =================================================
	rank = totalBytes;
	value[0].eightbytevalue.data = (graphlet_nr << 4) + rank;
	value[1].eightbytevalue.data = (uint32_t) (totalbytes >> 32); // High 32 bits
	value[2].eightbytevalue.data = (uint32_t) (totalbytes & 0xffffffff); // Low 32 bits
	outfs.write((char *) value, sizeof(value));
	totalbytes = 0; // Prepare for next graphlet

	// Clear hash maps to be prepared for next graphlet
	// Up to 1000+(?) entries a clear-fill cycle is faster than a dele/new/fill-cycle.
	hm_localIp_prot->clear();
	hm_prot_localPort_11->clear();
	hm_prot_localPort_1n->clear();
	hm_hnum_remoteIp->clear();
	hm_localPort_remotePort_11->clear();
	hm_localPort_remotePort_n1->clear();
	hm_localPort_remotePort_1n->clear();
	hm_localPort_remotePort_nn->clear();
	hm_remotePort_remoteIp_11->clear();
	hm_remotePort_remoteIp_n1->clear();
	hm_remotePort_remoteIp_1n->clear();
	hm_remotePort_remoteIp_nn->clear();
}

/**
 * Get color code for a given flow direction type.
 *
 *	\param flowtype	Flow direction type as defined by flowtype_t
 *
 *	\return uint8_t color code (0: black, 1: red, 2: green, 3: invalid)
 */
uint8_t CGraphlet::flowtype2colorcode(const uint8_t flowtype) {
	int color = 0;
	if (flowtype != 0) {
		switch (flowtype) {
			case biflow:
				color = 0;
				break;
			case inflow:
			case outflow:
				color = 1;
				break;
			case (inflow | unibiflow):
			case (outflow | unibiflow):
				color = 2;
				break;
			default:
				assert(false);
				break;
		}
	}
	return color;
}
