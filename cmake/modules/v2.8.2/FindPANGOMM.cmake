# - Try to find PANGOMM
# Once done this will define
#
#  PANGOMM_FOUND - system has PANGOMM
#  PANGOMM_INCLUDE_DIRS - the PANGOMM include directory
#  PANGOMM_LIBRARIES - Link these to use PANGOMM
#  PANGOMM_DEFINITIONS - Compiler switches required for using PANGOMM
#
#  Copyright (c) 2010 Reto Schneider <reto ATDONOTSPAMMEPLEASEAT reto-schneider.ch>
#
#  Redistribution and use is allowed according to the terms of the New
#  BSD license.
#  For details see the accompanying COPYING-CMAKE-SCRIPTS file.
#


if (PANGOMM_LIBRARIES AND PANGOMM_INCLUDE_DIRS)
  # in cache already
  set(PANGOMM_FOUND TRUE)
else (PANGOMM_LIBRARIES AND PANGOMM_INCLUDE_DIRS)
  # use pkg-config to get the directories and then use these values
  # in the FIND_PATH() and FIND_LIBRARY() calls
  #include(UsePkgConfig)

  #pkgconfig(pangomm-1.4 _PANGOMMIncDir _PANGOMMLinkDir _PANGOMMLinkFlags _PANGOMMCflags)

  set(PANGOMM_DEFINITIONS ${_PANGOMMCflags})

  find_path(PANGOMM_INCLUDE_DIR
    NAMES
      pangomm.h
    PATHS
      ${_PANGOMMIncDir}
      /usr/include
      /usr/local/include
      /opt/local/include
      /sw/include
      $ENV{HOME}/bin/include
      $ENV{HOME}/local/include
      $ENV{HOME}/bin/local/include
    PATH_SUFFIXES
      pangomm-1.4
  )

  find_library(PANGOMM-1.4_LIBRARY
    NAMES
      pangomm-1.4
    PATHS
      ${_PANGOMMLinkDir}
      /usr/lib
      /usr/local/lib
      /opt/local/lib
      /sw/lib
      $ENV{HOME}/bin/lib
      $ENV{HOME}/local/lib
      $ENV{HOME}/bin/local/lib
  )

  set(PANGOMM_INCLUDE_DIRS
    ${PANGOMM_INCLUDE_DIR}
	 /usr/lib/pangomm-1.4/include/	#ugly....
	 /usr/local/lib/pangomm-1.4/include/ #ugly....
  )
  set(PANGOMM_LIBRARIES
    ${PANGOMM-1.4_LIBRARY}
)

  if (PANGOMM_INCLUDE_DIRS AND PANGOMM_LIBRARIES)
     set(PANGOMM_FOUND TRUE)
  endif (PANGOMM_INCLUDE_DIRS AND PANGOMM_LIBRARIES)

  if (PANGOMM_FOUND)
    if (NOT PANGOMM_FIND_QUIETLY)
      message(STATUS "Found PANGOMM: ${PANGOMM_LIBRARIES}")
    endif (NOT PANGOMM_FIND_QUIETLY)
  else (PANGOMM_FOUND)
    if (PANGOMM_FIND_REQUIRED)
      message(FATAL_ERROR "Could not find PANGOMM")
    endif (PANGOMM_FIND_REQUIRED)
  endif (PANGOMM_FOUND)

  # show the PANGOMM_INCLUDE_DIRS and PANGOMM_LIBRARIES variables only in the advanced view
  mark_as_advanced(PANGOMM_INCLUDE_DIRS PANGOMM_LIBRARIES)

endif (PANGOMM_LIBRARIES AND PANGOMM_INCLUDE_DIRS)

