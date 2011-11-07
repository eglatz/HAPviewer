#include <stdint.h>
#include <boost/assign.hpp>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <sys/socket.h>
#include <iostream>
#include <stdexcept>

#include "cute.h"
#include "ide_listener.h"
#include "cute_runner.h"

#include "gutil.h"

using namespace std;

IPv6_addr get9_9_9_9() {
	using namespace std;
	using namespace boost::assign;
	IPv6_addr ip = list_of(0x0)(0x0)(0x0)(0x0)(0x0)(0x0)(0x0)(0x0)(0x0)(0x0)(0xff)(0xff)(0x9)(0x9)(0x9)(0x9).to_array(ip);
	return ip;
}

void test_ipV4ToIpV6() {
	using namespace std;
	using namespace boost::assign;
	IPv6_addr expectedresult = get9_9_9_9();

	uint32_t IPv4 = 0;
	string IPv4_string = "9.9.9.9";
	inet_pton(AF_INET, IPv4_string.c_str(), &IPv4);
	IPv6_addr result = IPv6_addr(IPv4);
	ASSERT_EQUAL(expectedresult, result);
}

void test_p2IPv6() {
	using namespace std;
	using namespace boost::assign;
	IPv6_addr calculated_ip("::ffff:9.9.9.9");
	IPv6_addr expected_ip = get9_9_9_9();
	ASSERT_EQUAL(calculated_ip, expected_ip);
}

void test_getDummyIpV6() {
	using namespace std;
	using namespace boost::assign;
	IPv6_addr calculated_ip;
	IPv6_addr expected_ip = list_of(0x0)(0x0)(0x0)(0x0)(0x0)(0x0)(0x0)(0x0)(0x0)(0x0)(0x0)(0x0)(0x0)(0x0)(0x0)(0x0).to_array(expected_ip);
	ASSERT_EQUAL(calculated_ip, expected_ip);
}

void test_getNetmask() {
	using namespace boost::assign;
	IPv6_addr nme_128;
	IPv6_addr nme_32;
	IPv6_addr nme_1;
	IPv6_addr nme_2;
	IPv6_addr nme_3;
	fill(nme_128.begin(), nme_128.end(), 0xff);
	fill(nme_32.begin(), nme_32.end(), 0);
	fill(nme_32.begin(), nme_32.begin() + 4, 0xff);
	nme_1 = list_of(0x0)(0x1)(0x0)(0x0)(0x0)(0x0)(0x0)(0x0)(0x0)(0x0)(0x0)(0x0)(0x0)(0x0)(0x0)(0x0).to_array(nme_1);
	nme_2 = list_of(0x0)(0x4)(0x0)(0x0)(0x0)(0x0)(0x0)(0x0)(0x0)(0x0)(0x0)(0x0)(0x0)(0x0)(0x0)(0x0).to_array(nme_2);
	nme_3 = list_of(0xff)(0xff)(0xff)(0xff)(0x0)(0x1)(0x0)(0x0)(0x0)(0x0)(0x0)(0x0)(0x0)(0x0)(0x0)(0x0).to_array(nme_3);

	IPv6_addr nmc_128 = IPv6_addr::getNetmask(128);
	IPv6_addr nmc_32 = IPv6_addr::getNetmask(32);
	IPv6_addr nmc_1 = IPv6_addr::getNetmask(1);
	IPv6_addr nmc_2 = IPv6_addr::getNetmask(3);
	IPv6_addr nmc_3 = IPv6_addr::getNetmask(33);

	ASSERT_EQUAL(nme_128, nmc_128);
	ASSERT_EQUAL(nme_32, nmc_32);
	ASSERT_EQUAL(nme_1, nmc_1);
	ASSERT_EQUAL(nme_2, nmc_2);
	ASSERT_EQUAL(nme_3, nmc_3);

	try {
		IPv6_addr::getNetmask(0);
		ASSERTM("Requesting a netmask with 0 leading bits should trow an error", false);
	} catch (string & e) {
		ASSERTM("Requesting a netmask with 0 leading throws an error", true);
	} catch (...) {
		ASSERTM("Requesting a netmask with 0 leading bits should trow a string", false);
	}
}

void test_lessthan() {
	IPv6_addr a("a::");
	IPv6_addr aa("a:a::");
	IPv6_addr ab("a:b::");
	IPv6_addr A("A::");
	IPv6_addr b("b::");
	IPv6_addr ipv4("192.168.0.1");

	ASSERTM("a:: is not smaller than A::", ! (a < A));
	ASSERTM("a:: is smaller than b::", a < b);
	ASSERTM("a:a:: is smaller than a:b::", aa < ab);
	ASSERTM("ipv4 is smaller than a:b::", ipv4 < ab);
}

void runSuite() {
	cute::suite s;
	s.push_back(CUTE(test_ipV4ToIpV6));
	s.push_back(CUTE(test_p2IPv6));
	s.push_back(CUTE(test_getDummyIpV6));
	s.push_back(CUTE(test_getNetmask));
	s.push_back(CUTE(test_lessthan));
	cute::ide_listener lis;
	cute::makeRunner(lis)(s, "test_gutil");
}

int main() {
	runSuite();
	return 0;
}
