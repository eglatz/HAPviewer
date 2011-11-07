#include <string>
#include <libgen.h>

#include "cute.h"
#include "ide_listener.h"
#include "cute_runner.h"

#include "gfilter_pcap.h"

void testAcceptFilename() {
	GFilter_pcap testImport;
	// bad filenames
	ASSERTM("Should not accept filename nfcapd.201009212300", !testImport.acceptFilename("nfcapd.201009212300"));
	ASSERTM("Should not accept filename demo-glatz.gz", !testImport.acceptFilename("demo-glatz.gz"));
	ASSERTM("Should not accept filename ipv6-ping-ipv6.google.com-2a00:1828:2000:12::dead:fefe.dat",
	      !testImport.acceptFilename("ipv6-ping-ipv6.google.com-2a00:1828:2000:12::dead:fefe.dat"));
	ASSERTM("Should not accept an empty filename", !testImport.acceptFilename(""));
	// good filenames
	ASSERTM("Should accept filename wireshark.pcap", testImport.acceptFilename("wireshark.pcap"));
	ASSERTM("Should accept filename ipv6-ssh-thinkpad2c2d-fe80::21c:25ff:fe16:d4f4.pcap",
	      testImport.acceptFilename("ipv6-ssh-thinkpad2c2d-fe80::21c:25ff:fe16:d4f4.pcap"));
}

void runSuite() {
	cute::suite s;
	s.push_back(CUTE(testAcceptFilename));
	cute::ide_listener lis;
	cute::makeRunner(lis)(s, "test_GFilter_pcap");
}

int main() {
	runSuite();
	return 0;
}
