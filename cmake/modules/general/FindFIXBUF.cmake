# - Try to find FIXBUF
# Once done this will define
#
#  FIXBUF_FOUND - system has FIXBUF
#  FIXBUF_INCLUDE_DIRS - the FIXBUF include directory
#  FIXBUF_LIBRARIES - Link these to use FIXBUF
#  FIXBUF_DEFINITIONS - Compiler switches required for using FIXBUF
#
#  Copyright (c) 2010 Reto Schneider <reto ATDONOTSPAMMEPLEASEAT reto-schneider.ch>
#
#  Redistribution and use is allowed according to the terms of the New
#  BSD license.
#  For details see the accompanying COPYING-CMAKE-SCRIPTS file.
#


if (FIXBUF_LIBRARIES AND FIXBUF_INCLUDE_DIRS)
  # in cache already
  set(FIXBUF_FOUND TRUE)
else (FIXBUF_LIBRARIES AND FIXBUF_INCLUDE_DIRS)
  find_path(FIXBUF_INCLUDE_DIR
    NAMES
      fixbuf/public.h
    PATHS
      /usr/include
      /usr/local/include
      /opt/local/include
      /sw/include
      $ENV{HOME}/bin/include
      $ENV{HOME}/local/include
      $ENV{HOME}/bin/local/include
  )

  find_library(FIXBUF_LIBRARY
    NAMES
      fixbuf
    PATHS
      /usr/lib
      /usr/local/lib
      /opt/local/lib
      /sw/lib
      $ENV{HOME}/bin/lib
      $ENV{HOME}/local/lib
      $ENV{HOME}/bin/local/lib
  )

  set(FIXBUF_INCLUDE_DIRS
    ${FIXBUF_INCLUDE_DIR}
  )
  set(FIXBUF_LIBRARIES
    ${FIXBUF_LIBRARY}
)

  if (FIXBUF_INCLUDE_DIRS AND FIXBUF_LIBRARIES)
     set(FIXBUF_FOUND TRUE)
  endif (FIXBUF_INCLUDE_DIRS AND FIXBUF_LIBRARIES)

  if (FIXBUF_FOUND)
    if (NOT FIXBUF_FIND_QUIETLY)
      message(STATUS "Found FIXBUF: ${FIXBUF_LIBRARIES}")
    endif (NOT FIXBUF_FIND_QUIETLY)
  else (FIXBUF_FOUND)
    if (FIXBUF_FIND_REQUIRED)
      message(FATAL_ERROR "Could not find FIXBUF")
    endif (FIXBUF_FIND_REQUIRED)
  endif (FIXBUF_FOUND)

  # show the FIXBUF_INCLUDE_DIRS and FIXBUF_LIBRARIES variables only in the advanced view
  mark_as_advanced(FIXBUF_INCLUDE_DIRS FIXBUF_LIBRARIES)

endif (FIXBUF_LIBRARIES AND FIXBUF_INCLUDE_DIRS)

