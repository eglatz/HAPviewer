#include "cute.h"
#include "ide_listener.h"
#include "cute_runner.h"
#include "HashMapE.h"

#include <stdint.h>
#include "gutil.h"

void HashKeyIPv6Pair_HashKeyIPv4Pair() {
	IPv6_addr a = IPv6_addr(1), b = IPv6_addr(2);
	HashKeyIPv6Pair hkp(a, b);
	ASSERT_EQUAL(*(IPv6_addr*)(&hkp.getkey()), a);
	ASSERT_EQUAL(*(IPv6_addr*)(&hkp.getkey()[16]), b);
}

void runSuite() {
	cute::suite s;
	s.push_back(CUTE(HashKeyIPv6Pair_HashKeyIPv4Pair));
	cute::ide_listener lis;
	cute::makeRunner(lis)(s, "hash_map");
}

int main() {
	runSuite();
	return 0;
}
