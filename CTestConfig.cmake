set(CTEST_PROJECT_NAME "HAPviewerV2")
set(CTEST_NIGHTLY_START_TIME "00:00:00 EST")
set(CTEST_DROP_SITE_CDASH TRUE)

if(NOT DEFINED CTEST_DROP_METHOD)
	set(CTEST_DROP_METHOD "http")
	#set(CTEST_DROP_METHOD "https") # many distributions deliver a libcurl without ssl :(
endif(NOT DEFINED CTEST_DROP_METHOD)

if(CTEST_DROP_METHOD MATCHES "http")
	set(CTEST_DROP_SITE "cdash.hap4nfsen.ch")
	set(CTEST_DROP_LOCATION "/submit.php?project=HAPviewerV2")
	set(CTEST_TRIGGER_SITE "")
endif()
