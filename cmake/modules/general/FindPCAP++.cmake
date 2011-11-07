# - Try to find PCAP++
# Once done this will define
#
#  PCAP++_FOUND - system has PCAP++
#  PCAP++_INCLUDE_DIRS - the PCAP++ include directory
#  PCAP++_LIBRARIES - Link these to use PCAP++
#  PCAP++_DEFINITIONS - Compiler switches required for using PCAP++
#
#  Copyright (c) 2010 Reto Schneider <reto ATDONOTSPAMMEPLEASEAT reto-schneider.ch>
#
#  Redistribution and use is allowed according to the terms of the New
#  BSD license.
#  For details see the accompanying COPYING-CMAKE-SCRIPTS file.
#


if (PCAP++_LIBRARIES AND PCAP++_INCLUDE_DIRS)
  # in cache already
  set(PCAP++_FOUND TRUE)
else (PCAP++_LIBRARIES AND PCAP++_INCLUDE_DIRS)
  find_path(PCAP++_INCLUDE_DIR
    NAMES
      pcap++.h
    PATHS
      /usr/include
      /usr/local/include
      /opt/local/include
      /sw/include
      $ENV{HOME}/bin/include
      $ENV{HOME}/local/include
      $ENV{HOME}/bin/local/include
  )

  find_library(PCAP++_LIBRARY
    NAMES
      pcap++
    PATHS
      /usr/lib
      /usr/local/lib
      /opt/local/lib
      /sw/lib
      $ENV{HOME}/bin/lib
      $ENV{HOME}/local/lib
      $ENV{HOME}/bin/local/lib
  )

  set(PCAP++_INCLUDE_DIRS
    ${PCAP++_INCLUDE_DIR}
  )
  set(PCAP++_LIBRARIES
    ${PCAP++_LIBRARY}
)

  if (PCAP++_INCLUDE_DIRS AND PCAP++_LIBRARIES)
     set(PCAP++_FOUND TRUE)
  endif (PCAP++_INCLUDE_DIRS AND PCAP++_LIBRARIES)

  if (PCAP++_FOUND)
    if (NOT PCAP++_FIND_QUIETLY)
      message(STATUS "Found PCAP++: ${PCAP++_LIBRARIES}")
    endif (NOT PCAP++_FIND_QUIETLY)
  else (PCAP++_FOUND)
    if (PCAP++_FIND_REQUIRED)
      message(FATAL_ERROR "Could not find PCAP++")
    endif (PCAP++_FIND_REQUIRED)
  endif (PCAP++_FOUND)

  # show the PCAP++_INCLUDE_DIRS and PCAP++_LIBRARIES variables only in the advanced view
  mark_as_advanced(PCAP++_INCLUDE_DIRS PCAP++_LIBRARIES)

endif (PCAP++_LIBRARIES AND PCAP++_INCLUDE_DIRS)

