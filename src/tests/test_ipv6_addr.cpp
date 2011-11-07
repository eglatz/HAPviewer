#include "cute.h"
#include "ide_listener.h"
#include "cute_runner.h"

#include <stdint.h>
#include <boost/assign.hpp>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <sys/socket.h>
#include <iostream>

#include "IPv6_addr.h"

IPv6_addr get_IPv4_0() {
	using namespace std;
	using namespace boost::assign;
	IPv6_addr ip = list_of(0x0)(0x0)(0x0)(0x0)(0x0)(0x0)(0x0)(0x0)(0x0)(0x0)(0xff)(0xff)(0x0)(0x0)(0x0)(0x0).to_array(ip);
	return ip;
}

IPv6_addr get_IPv4_9_9_9_9() {
	using namespace std;
	using namespace boost::assign;
	IPv6_addr ip = list_of(0x0)(0x0)(0x0)(0x0)(0x0)(0x0)(0x0)(0x0)(0x0)(0x0)(0xff)(0xff)(0x9)(0x9)(0x9)(0x9).to_array(ip);
	return ip;
}

IPv6_addr get_IPv4_127_0_0_1() {
	using namespace std;
	using namespace boost::assign;
	IPv6_addr ip = list_of(0x0)(0x0)(0x0)(0x0)(0x0)(0x0)(0x0)(0x0)(0x0)(0x0)(0xff)(0xff)(0x7f)(0x0)(0x0)(0x1).to_array(ip);
	return ip;
}

IPv6_addr get_IPv4_255_255_255_255() {
	using namespace std;
	using namespace boost::assign;
	IPv6_addr ip = list_of(0x0)(0x0)(0x0)(0x0)(0x0)(0x0)(0x0)(0x0)(0x0)(0x0)(0xff)(0xff)(0xff)(0xff)(0xff)(0xff).to_array(ip);
	return ip;
}

IPv6_addr get_IPv6_0() {
	using namespace std;
	using namespace boost::assign;
	IPv6_addr ip = list_of(0x0)(0x0)(0x0)(0x0)(0x0)(0x0)(0x0)(0x0)(0x0)(0x0)(0x0)(0x0)(0x0)(0x0)(0x0)(0x0).to_array(ip);
	return ip;
}

IPv6_addr get_IPv6_1_to_8() {
	using namespace std;
	using namespace boost::assign;
	IPv6_addr ip = list_of(0x0)(0x1)(0x0)(0x2)(0x0)(0x3)(0x0)(0x4)(0x0)(0x5)(0x0)(0x6)(0x0)(0x7)(0x0)(0x8).to_array(ip);
	return ip;
}

IPv6_addr get_IPv6_0_to_7() {
	using namespace std;
	using namespace boost::assign;
	IPv6_addr ip = list_of(0x0)(0x0)(0x0)(0x1)(0x0)(0x2)(0x0)(0x3)(0x0)(0x4)(0x0)(0x5)(0x0)(0x6)(0x0)(0x7).to_array(ip);
	return ip;
}

IPv6_addr get_IPv6_2_to_7() {
	using namespace std;
	using namespace boost::assign;
	IPv6_addr ip = list_of(0x0)(0x0)(0x0)(0x0)(0x0)(0x2)(0x0)(0x3)(0x0)(0x4)(0x0)(0x5)(0x0)(0x6)(0x0)(0x7).to_array(ip);
	return ip;
}

IPv6_addr get_IPv6_0_1() {
	using namespace std;
	using namespace boost::assign;
	IPv6_addr ip = list_of(0x0)(0x0)(0x0)(0x0)(0x0)(0x0)(0x0)(0x0)(0x0)(0x0)(0x0)(0x0)(0x0)(0x0)(0x0)(0x1).to_array(ip);
	return ip;
}

IPv6_addr get_IPv6_1_to_2_0_1_to_5() {
	using namespace std;
	using namespace boost::assign;
	IPv6_addr ip = list_of(0x0)(0x1)(0x0)(0x2)(0x0)(0x0)(0x0)(0x1)(0x0)(0x2)(0x0)(0x3)(0x0)(0x4)(0x0)(0x5).to_array(ip);
	return ip;
}

IPv6_addr get_IPv6_1_to_2_0_0_1_to_4() {
	using namespace std;
	using namespace boost::assign;
	IPv6_addr ip = list_of(0x0)(0x1)(0x0)(0x2)(0x0)(0x0)(0x0)(0x0)(0x0)(0x1)(0x0)(0x2)(0x0)(0x3)(0x0)(0x4).to_array(ip);
	return ip;
}

void test_ConstructorFromString() {
	using namespace std;
	using namespace boost::assign;
	IPv6_addr expectedresult1 = get_IPv4_9_9_9_9();
	IPv6_addr expectedresult2 = get_IPv4_0();
	IPv6_addr expectedresult3 = get_IPv6_0();
	IPv6_addr expectedresult4 = get_IPv6_0_1();
	IPv6_addr expectedresult5 = get_IPv6_0_to_7();
	IPv6_addr expectedresult6 = get_IPv6_1_to_8();
	IPv6_addr expectedresult7 = get_IPv6_1_to_2_0_1_to_5();

	IPv6_addr result1("9.9.9.9");
	IPv6_addr result2("0.0.0.0");
	IPv6_addr result3("::");
	IPv6_addr result4("::1");
	IPv6_addr result5("::1:2:3:4:5:6:7");
	IPv6_addr result6("1:2:3:4:5:6:7:8");
	IPv6_addr result7("1:2::1:2:3:4:5");

	IPv6_addr result1_witherrors("9.9.9.9\t");
	IPv6_addr result2_witherrors("0.0.0.0\n");
	IPv6_addr result3_witherrors("\f: :");
	IPv6_addr result4_witherrors("::*1");
	IPv6_addr result5_witherrors(":P*++(:1:2:3:p4:5:6:7");
	IPv6_addr result6_witherrors("1:2:3:4:5:\n6:7:8");
	IPv6_addr result7_witherrors("1:2::1:2:3:4:5ö");

	ASSERT_EQUAL(expectedresult1, result1);
	ASSERT_EQUAL(expectedresult2, result2);
	ASSERT_EQUAL(expectedresult3, result3);
	ASSERT_EQUAL(expectedresult4, result4);
	ASSERT_EQUAL(expectedresult5, result5);
	ASSERT_EQUAL(expectedresult6, result6);
	ASSERT_EQUAL(expectedresult7, result7);

	ASSERT_EQUAL(expectedresult1, result1_witherrors);
	ASSERT_EQUAL(expectedresult2, result2_witherrors);
	ASSERT_EQUAL(expectedresult3, result3_witherrors);
	ASSERT_EQUAL(expectedresult4, result4_witherrors);
	ASSERT_EQUAL(expectedresult5, result5_witherrors);
	ASSERT_EQUAL(expectedresult6, result6_witherrors);
	ASSERT_EQUAL(expectedresult7, result7_witherrors);
}

void test_ConstructorFromUint32_t() {
	using namespace std;
	using namespace boost::assign;
	IPv6_addr expectedresult1 = get_IPv4_9_9_9_9();
	IPv6_addr expectedresult2 = get_IPv4_0();
	IPv6_addr expectedresult3 = get_IPv4_127_0_0_1();
	IPv6_addr expectedresult4 = get_IPv4_255_255_255_255();

	uint32_t ip4;
	inet_pton(AF_INET, string("9.9.9.9").c_str(), &ip4);
	IPv6_addr result1(ntohl(ip4));
	IPv6_addr result2(0x0);
	IPv6_addr result3(0x7f000001);
	IPv6_addr result4(0xffffffff);

	ASSERT_EQUAL(expectedresult1, result1);
	ASSERT_EQUAL(expectedresult2, result2);
	ASSERT_EQUAL(expectedresult3, result3);
	ASSERT_EQUAL(expectedresult4, result4);
}

void test_ConstructorFromIn6_addr() {
	using namespace std;
	using namespace boost::assign;
	IPv6_addr expectedresult1 = get_IPv4_9_9_9_9();
	IPv6_addr expectedresult2 = get_IPv4_0();
	IPv6_addr expectedresult3 = get_IPv4_127_0_0_1();
	IPv6_addr expectedresult4 = get_IPv4_255_255_255_255();

	in6_addr buf;
	inet_pton(AF_INET6, string("::ffff:9.9.9.9").c_str(), &buf);
	IPv6_addr result1(buf);

	inet_pton(AF_INET6, string("::ffff:0.0.0.0").c_str(), &buf);
	IPv6_addr result2(buf);

	inet_pton(AF_INET6, string("::ffff:127.0.0.1").c_str(), &buf);
	IPv6_addr result3(buf);

	inet_pton(AF_INET6, string("::ffff:255.255.255.255").c_str(), &buf);
	IPv6_addr result4(buf);

	ASSERT_EQUAL(expectedresult1, result1);
	ASSERT_EQUAL(expectedresult2, result2);
	ASSERT_EQUAL(expectedresult3, result3);
	ASSERT_EQUAL(expectedresult4, result4);
}

void test_ConstructorDefault() {
	using namespace std;
	using namespace boost::assign;
	IPv6_addr expectedresult1 = get_IPv6_0();
	IPv6_addr result1;

	ASSERT_EQUAL(expectedresult1, result1);
}

void test_ipV6AddressToString() {
	using namespace std;
	using namespace boost::assign;
	IPv6_addr result1 = get_IPv4_9_9_9_9();
	IPv6_addr result2 = get_IPv4_0();
	IPv6_addr result3 = get_IPv6_0();
	IPv6_addr result4 = get_IPv6_0_1();
	IPv6_addr result5 = get_IPv6_0_to_7();
	IPv6_addr result6 = get_IPv6_2_to_7();
	IPv6_addr result7 = get_IPv6_1_to_8();
	IPv6_addr result8 = get_IPv6_1_to_2_0_1_to_5();
	IPv6_addr result9 = get_IPv6_1_to_2_0_0_1_to_4();

	string expectedresult1("9.9.9.9");
	string expectedresult2("0.0.0.0");
	string expectedresult3("::");
	string expectedresult4("::1");
	string expectedresult5("0:1:2:3:4:5:6:7");
	string expectedresult6("::2:3:4:5:6:7");
	string expectedresult7("1:2:3:4:5:6:7:8");
	string expectedresult8("1:2:0:1:2:3:4:5");
	string expectedresult9("1:2::1:2:3:4");

	ASSERT_EQUAL(expectedresult1, result1.toString());
	ASSERT_EQUAL(expectedresult2, result2.toString());
	ASSERT_EQUAL(expectedresult3, result3.toString());
	ASSERT_EQUAL(expectedresult4, result4.toString());
	ASSERT_EQUAL(expectedresult5, result5.toString());
	ASSERT_EQUAL(expectedresult6, result6.toString());
	ASSERT_EQUAL(expectedresult7, result7.toString());
	ASSERT_EQUAL(expectedresult8, result8.toString());
	ASSERT_EQUAL(expectedresult9, result9.toString());
}

void test_andOperator() {
	using namespace std;
	using namespace boost::assign;
	IPv6_addr expectedresult1 = get_IPv6_0();
	IPv6_addr testvalue1_1 = get_IPv4_0();
	IPv6_addr testvalue1_2 = get_IPv6_0();

	IPv6_addr expectedresult2 = get_IPv4_127_0_0_1();
	IPv6_addr testvalue2_1 = get_IPv4_255_255_255_255();
	IPv6_addr testvalue2_2 = get_IPv4_127_0_0_1();

	IPv6_addr expectedresult3 = get_IPv4_0();
	IPv6_addr testvalue3_1 = get_IPv4_0();
	IPv6_addr testvalue3_2 = get_IPv4_0();

	IPv6_addr expectedresult4 = get_IPv4_255_255_255_255();
	IPv6_addr testvalue4_1 = get_IPv4_255_255_255_255();
	IPv6_addr testvalue4_2 = get_IPv4_255_255_255_255();

	ASSERT_EQUAL(expectedresult1, testvalue1_1 & testvalue1_2);
	ASSERT_EQUAL(expectedresult2, testvalue2_1 & testvalue2_2);
	ASSERT_EQUAL(expectedresult3, testvalue3_1 & testvalue3_2);
	ASSERT_EQUAL(expectedresult4, testvalue4_1 & testvalue4_2);
}

void test_lessOperator() {
	IPv6_addr localhost("::1");
	IPv6_addr zero("::");
	IPv6_addr huge("ffff::");
	IPv6_addr huge2("ffff::");
	ASSERT_EQUAL(true, zero < huge);
	ASSERT_EQUAL(true, localhost < huge);
	ASSERT_EQUAL(false, zero < zero);
	ASSERT_EQUAL(false, huge < huge);
	ASSERT_EQUAL(false, huge < huge2);
}

void runSuite() {
	cute::suite s;
	s.push_back(CUTE(test_ConstructorFromUint32_t));
	s.push_back(CUTE(test_ConstructorFromIn6_addr));
	s.push_back(CUTE(test_ConstructorFromString));
	s.push_back(CUTE(test_ConstructorDefault));
	s.push_back(CUTE(test_ipV6AddressToString));
	s.push_back(CUTE(test_andOperator));
	s.push_back(CUTE(test_lessOperator));
	cute::ide_listener lis;
	cute::makeRunner(lis)(s, "test_ipv6_addr");
}

int main() {
	runSuite();
	return 0;
}
