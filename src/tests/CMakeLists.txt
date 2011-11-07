cmake_minimum_required (VERSION 2.6)

#include all test files
#file(GLOB test_sources test_*.cpp)
set(test_sources "test_gfilter.cpp")
set(test_sources ${test_sources} "test_gutil.cpp")
set(test_sources ${test_sources} "test_HashMapE.cpp")
set(test_sources ${test_sources} "test_ipv6_addr.cpp")
if(HAPVIEWER_ENABLE_PCAP)
	set(test_sources ${test_sources} "test_gfilter_pcap.cpp")
endif()
#if(HAPVIEWER_ENABLE_IPFIX)
#	set(test_sources ${test_sources} "test_gfilter_ipfix.cpp")
#endif()
if(HAPVIEWER_ENABLE_NFDUMP)
	set(test_sources ${test_sources} "test_gfilter_nfdump.cpp")
endif()
if(HAPVIEWER_ENABLE_CFLOW)
	set(test_sources ${test_sources} "test_cflow.cpp")
endif()

#add the cute-headers as well as the ones of our own application
include_directories("../" "cute/")

foreach(test ${test_sources} )
	string(REGEX REPLACE ".*test_(.*)" "\\1" basename "${test}")
	string(REGEX REPLACE "(.*)(.cpp)" "\\1" noext "${basename}")
	add_executable(testexe_${noext} ${test})
	find_package(Threads REQUIRED)
	target_link_libraries(testexe_${noext} 
		hapviz
		${HAPVIEWER_CORELIBS}
		${CMAKE_THREAD_LIBS_INIT}
	)
	add_test(test_${noext} ${EXECUTABLE_OUTPUT_PATH}/testexe_${noext})
	set_tests_properties(test_${noext} PROPERTIES FAIL_REGULAR_EXPRESSION "failure") #this test fails if cute detects an error
endforeach()
