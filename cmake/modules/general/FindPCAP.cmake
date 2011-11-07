# - Try to find PCAP
# Once done this will define
#
#  PCAP_FOUND - system has PCAP
#  PCAP_INCLUDE_DIRS - the PCAP include directory
#  PCAP_LIBRARIES - Link these to use PCAP
#  PCAP_DEFINITIONS - Compiler switches required for using PCAP
#
#  Copyright (c) 2010 Reto Schneider <reto ATDONOTSPAMMEPLEASEAT reto-schneider.ch>
#
#  Redistribution and use is allowed according to the terms of the New
#  BSD license.
#  For details see the accompanying COPYING-CMAKE-SCRIPTS file.
#


if (PCAP_LIBRARIES AND PCAP_INCLUDE_DIRS)
  # in cache already
  set(PCAP_FOUND TRUE)
else (PCAP_LIBRARIES AND PCAP_INCLUDE_DIRS)
  find_path(PCAP_INCLUDE_DIR
    NAMES
      pcap.h
    PATHS
      /usr/include
      /usr/local/include
      /opt/local/include
      /sw/include
      $ENV{HOME}/bin/include
      $ENV{HOME}/local/include
      $ENV{HOME}/bin/local/include
  )

  find_library(PCAP_LIBRARY
    NAMES
      pcap
    PATHS
      /usr/lib
      /usr/local/lib
      /opt/local/lib
      /sw/lib
      $ENV{HOME}/bin/lib
      $ENV{HOME}/local/lib
      $ENV{HOME}/bin/local/lib
  )

  set(PCAP_INCLUDE_DIRS
    ${PCAP_INCLUDE_DIR}
  )
  set(PCAP_LIBRARIES
    ${PCAP_LIBRARY}
)

  if (PCAP_INCLUDE_DIRS AND PCAP_LIBRARIES)
     set(PCAP_FOUND TRUE)
  endif (PCAP_INCLUDE_DIRS AND PCAP_LIBRARIES)

  if (PCAP_FOUND)
    if (NOT PCAP_FIND_QUIETLY)
      message(STATUS "Found PCAP: ${PCAP_LIBRARIES}")
    endif (NOT PCAP_FIND_QUIETLY)
  else (PCAP_FOUND)
    if (PCAP_FIND_REQUIRED)
      message(FATAL_ERROR "Could not find PCAP")
    endif (PCAP_FIND_REQUIRED)
  endif (PCAP_FOUND)

  # show the PCAP_INCLUDE_DIRS and PCAP_LIBRARIES variables only in the advanced view
  mark_as_advanced(PCAP_INCLUDE_DIRS PCAP_LIBRARIES)

endif (PCAP_LIBRARIES AND PCAP_INCLUDE_DIRS)

