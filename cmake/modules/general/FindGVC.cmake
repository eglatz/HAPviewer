# - Try to find GVC
# Once done this will define
#
#  GVC_FOUND - system has GVC
#  GVC_INCLUDE_DIRS - the GVC include directory
#  GVC_LIBRARIES - Link these to use GVC
#  GVC_DEFINITIONS - Compiler switches required for using GVC
#
#  Copyright (c) 2010 Reto Schneider <reto ATDONOTSPAMMEPLEASEAT reto-schneider.ch>
#
#  Redistribution and use is allowed according to the terms of the New
#  BSD license.
#  For details see the accompanying COPYING-CMAKE-SCRIPTS file.
#


if (GVC_LIBRARIES AND GVC_INCLUDE_DIRS)
  # in cache already
  set(GVC_FOUND TRUE)
else (GVC_LIBRARIES AND GVC_INCLUDE_DIRS)
  find_path(GVC_INCLUDE_DIR
    NAMES
      gvc.h
    PATHS
      /usr/include
      /usr/local/include
      /opt/local/include
      /sw/include
      $ENV{HOME}/bin/include
      $ENV{HOME}/local/include
      $ENV{HOME}/bin/local/include
    PATH_SUFFIXES
      graphviz
  )

  find_library(GVC_LIBRARY
    NAMES
      gvc
    PATHS
      /usr/lib
      /usr/local/lib
      /opt/local/lib
      /sw/lib
      $ENV{HOME}/bin/lib
      $ENV{HOME}/local/lib
      $ENV{HOME}/bin/local/lib
    PATH_SUFFIXES
      graphviz
  )

  set(GVC_INCLUDE_DIRS
    ${GVC_INCLUDE_DIR}
  )
  set(GVC_LIBRARIES
    ${GVC_LIBRARY}
)

  if (GVC_INCLUDE_DIRS AND GVC_LIBRARIES)
     set(GVC_FOUND TRUE)
  endif (GVC_INCLUDE_DIRS AND GVC_LIBRARIES)

  if (GVC_FOUND)
    if (NOT GVC_FIND_QUIETLY)
      message(STATUS "Found GVC: ${GVC_LIBRARIES}")
    endif (NOT GVC_FIND_QUIETLY)
  else (GVC_FOUND)
    if (GVC_FIND_REQUIRED)
      message(FATAL_ERROR "Could not find GVC")
    endif (GVC_FIND_REQUIRED)
  endif (GVC_FOUND)

  # show the GVC_INCLUDE_DIRS and GVC_LIBRARIES variables only in the advanced view
  mark_as_advanced(GVC_INCLUDE_DIRS GVC_LIBRARIES)

endif (GVC_LIBRARIES AND GVC_INCLUDE_DIRS)

