#include <stdint.h>
#include "cute.h"
#include "ide_listener.h"
#include "cute_runner.h"
#include "cflow.h"
#include "gutil.h"

void isUnion() {
	cflow_t cf;
	memset(&cf, 0, sizeof(cf));
	cf.dir = -1;
	ASSERTM("dir and flowtype are union", cf.dir == cf.flowtype);
	cf.dir = 1;
	ASSERTM("flowtype = 1", cf.flowtype == 1);
}

void subflowlist_size() {
	CFlowList list1;
	Subflowlist sublist1(list1.begin(), list1.end());
	ASSERT_EQUAL(list1.size(), sublist1.size());
	CFlowList list2;
	list2.push_back(cflow_t());
	list2.push_back(cflow_t());
	Subflowlist sublist2(list2.begin(), list2.end());
	ASSERT_EQUAL(list2.size(), sublist2.size());
}

void cflow_t_is_cflow6() {
	cflow_t current_CF;
	// cflow_t is typedef for cflow6. Update test if this changes
	ASSERT_EQUAL(current_CF.magic, CFLOW_6_MAGIC_NUMBER);
	ASSERT_EQUAL(typeid(cflow_t), typeid(cflow6));
	ASSERT_EQUAL(typeid(cflow_t), typeid(cflow6));
}

void cflow6_offsets() {
	cflow6 cflow;

	int n = 0;
	ASSERT_EQUAL(1, sizeof(cflow.magic));
	ASSERT_EQUAL((char*)&cflow, (char*)&cflow.magic);

	ASSERT_EQUAL(1, sizeof(cflow.prot));
	ASSERT_EQUAL(n += sizeof(cflow.magic), (char*)&cflow.prot - (char*)&cflow);

	ASSERT_EQUAL(1, sizeof(cflow.dir));
	ASSERT_EQUAL(n += sizeof(cflow.prot), (char*)&cflow.dir - (char*)&cflow);

	ASSERT_EQUAL(1, sizeof(cflow.flowtype));
	ASSERT_EQUAL(n, (char*)&cflow.flowtype - (char*)&cflow);

	ASSERT_EQUAL(1, sizeof(cflow.tos_flags));
	ASSERT_EQUAL(n += sizeof(cflow.dir), (char*)&cflow.tos_flags - (char*)&cflow);

	ASSERT_EQUAL(4, sizeof(cflow.durationMs));
	ASSERT_EQUAL(n += sizeof(cflow.tos_flags), (char*)&cflow.durationMs - (char*)&cflow);

	ASSERT_EQUAL(8, sizeof(cflow.startMs));
	ASSERT_EQUAL(n += sizeof(cflow.durationMs), (char*)&cflow.startMs - (char*)&cflow);

	ASSERT_EQUAL(16, sizeof(cflow.localIP));
	ASSERT_EQUAL(n += sizeof(cflow.startMs), (char*)&cflow.localIP - (char*)&cflow);

	ASSERT_EQUAL(16, sizeof(cflow.remoteIP));
	ASSERT_EQUAL(n += sizeof(cflow.localIP), (char*)&cflow.remoteIP - (char*)&cflow);

	ASSERT_EQUAL(8, sizeof(cflow.dOctets));
	ASSERT_EQUAL(n += sizeof(cflow.remoteIP), (char*)&cflow.dOctets - (char*)&cflow);

	ASSERT_EQUAL(4, sizeof(cflow.dPkts));
	ASSERT_EQUAL(n += sizeof(cflow.dOctets), (char*)&cflow.dPkts - (char*)&cflow);

	ASSERT_EQUAL(2, sizeof(cflow.localPort));
	ASSERT_EQUAL(n += sizeof(cflow.dPkts), (char*)&cflow.localPort - (char*)&cflow);

	ASSERT_EQUAL(2, sizeof(cflow.remotePort));
	ASSERT_EQUAL(n += sizeof(cflow.localPort), (char*)&cflow.remotePort - (char*)&cflow);

	ASSERT_EQUAL(4, sizeof(cflow.localAS));
	ASSERT_EQUAL(n += sizeof(cflow.remotePort), (char*)&cflow.localAS - (char*)&cflow);

	ASSERT_EQUAL(4, sizeof(cflow.remoteAS));
	ASSERT_EQUAL(n += sizeof(cflow.localAS), (char*)&cflow.remoteAS - (char*)&cflow);
}

void cflow4_offsets() {
	cflow4 cflow;

	int n = 0;
	ASSERT_EQUAL(4, sizeof(cflow.localIP));
	ASSERT_EQUAL((char*)&cflow, (char*)&cflow.localIP);
	ASSERT_EQUAL(4, sizeof(cflow.serverIP));
	ASSERT_EQUAL((char*)&cflow, (char*)&cflow.serverIP);
	ASSERT_EQUAL(4, sizeof(cflow.clientIP));
	ASSERT_EQUAL((char*)&cflow, (char*)&cflow.clientIP);

	ASSERT_EQUAL(4, sizeof(cflow.remoteIP));
	ASSERT_EQUAL(n += sizeof(cflow.localIP), (char*)&cflow.remoteIP - (char*)&cflow);
	ASSERT_EQUAL(4, sizeof(cflow.connections));
	ASSERT_EQUAL(n, (char*)&cflow.connections - (char*)&cflow);

	ASSERT_EQUAL(8, sizeof(cflow.startMs));
	ASSERT_EQUAL(n += sizeof(cflow.remoteIP), (char*)&cflow.startMs - (char*)&cflow);

	ASSERT_EQUAL(4, sizeof(cflow.durationMs));
	ASSERT_EQUAL(n += sizeof(cflow.startMs), (char*)&cflow.durationMs - (char*)&cflow);
	ASSERT_EQUAL(4, sizeof(cflow.summaryIn));
	ASSERT_EQUAL(n, (char*)&cflow.summaryIn - (char*)&cflow);

	ASSERT_EQUAL(2, sizeof(cflow.localPort));
	ASSERT_EQUAL(n += sizeof(cflow.durationMs), (char*)&cflow.localPort - (char*)&cflow);
	ASSERT_EQUAL(2, sizeof(cflow.servicePort));
	ASSERT_EQUAL(n, (char*)&cflow.servicePort - (char*)&cflow);

	ASSERT_EQUAL(2, sizeof(cflow.remotePort));
	ASSERT_EQUAL(n += sizeof(cflow.localPort), (char*)&cflow.remotePort - (char*)&cflow);
	ASSERT_EQUAL(2, sizeof(cflow.clients));
	ASSERT_EQUAL(n, (char*)&cflow.clients - (char*)&cflow);

	ASSERT_EQUAL(8, sizeof(cflow.dOctets));
	ASSERT_EQUAL(n += sizeof(cflow.localPort), (char*)&cflow.dOctets - (char*)&cflow);

	ASSERT_EQUAL(4, sizeof(cflow.dPkts));
	ASSERT_EQUAL(n += sizeof(cflow.dOctets), (char*)&cflow.dPkts - (char*)&cflow);

	ASSERT_EQUAL(4, sizeof(cflow.summaryOut));
	ASSERT_EQUAL(n += sizeof(cflow.dPkts), (char*)&cflow.summaryOut - (char*)&cflow);
	ASSERT_EQUAL(4, sizeof(cflow.AS));
	ASSERT_EQUAL(n, (char*)&cflow.AS - (char*)&cflow);
	ASSERT_EQUAL(2, sizeof(cflow.AS.local));
	ASSERT_EQUAL(n, (char*)&cflow.AS.local - (char*)&cflow);
	ASSERT_EQUAL(2, sizeof(cflow.AS.remote));
	ASSERT_EQUAL(n += sizeof(cflow.AS.local), (char*)&cflow.AS.remote - (char*)&cflow);

	ASSERT_EQUAL(sizeof(cflow.prot), 1);
	ASSERT_EQUAL(n += sizeof(cflow.AS.remote), (char*)&cflow.prot - (char*)&cflow);

	ASSERT_EQUAL(sizeof(cflow.dir), 1);
	ASSERT_EQUAL(n += sizeof(cflow.prot), (char*)&cflow.dir - (char*)&cflow);
	ASSERT_EQUAL(sizeof(cflow.flowtype), 1);
	ASSERT_EQUAL(n, (char*)&cflow.flowtype - (char*)&cflow);

	ASSERT_EQUAL(sizeof(cflow.tos_flags), 1);
	ASSERT_EQUAL(n += sizeof(cflow.flowtype), (char*)&cflow.tos_flags - (char*)&cflow);

	ASSERT_EQUAL(sizeof(cflow.magic), 1);
	ASSERT_EQUAL(n += sizeof(cflow.tos_flags), (char*)&cflow.magic - (char*)&cflow);

	ASSERT_EQUAL(sizeof(cflow.padding), 4);
	ASSERT_EQUAL(n += sizeof(cflow.magic), (char*)&cflow.padding - (char*)&cflow);
}

void cflow6_size() {
	ASSERT_EQUAL(sizeof(cflow6), 72);
}

void cflow4_size() {
	ASSERT_EQUAL(sizeof(cflow4), 48);
}

void cflow6_aligned() {
	ASSERT_EQUAL(0, sizeof(cflow6) % 8);
}

void cflow4_aligned() {
	ASSERT_EQUAL(0, sizeof(cflow4) % 8);
}

void runSuite() {
	cute::suite s;
	s.push_back(CUTE(isUnion));
	s.push_back(CUTE(subflowlist_size));
	s.push_back(CUTE(cflow_t_is_cflow6));
	s.push_back(CUTE(cflow6_size));
	s.push_back(CUTE(cflow6_aligned));
	s.push_back(CUTE(cflow6_offsets));
	s.push_back(CUTE(cflow4_size));
	s.push_back(CUTE(cflow4_aligned));
	s.push_back(CUTE(cflow4_offsets));
	cute::ide_listener lis;
	cute::makeRunner(lis)(s, "test_cflow");
}

int main() {
	runSuite();
	return 0;
}
