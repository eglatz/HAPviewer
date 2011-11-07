# - Try to find GTK-PIXBUF
# Once done this will define
#
#  GTK-PIXBUF_FOUND - system has GTK-PIXBUF
#  GTK-PIXBUF_INCLUDE_DIRS - the GTK-PIXBUF include directory
#  GTK-PIXBUF_LIBRARIES - Link these to use GTK-PIXBUF
#  GTK-PIXBUF_DEFINITIONS - Compiler switches required for using GTK-PIXBUF
#
#  Copyright (c) 2010 Reto Schneider <reto ATDONOTSPAMMEPLEASEAT reto-schneider.ch>
#
#  Redistribution and use is allowed according to the terms of the New
#  BSD license.
#  For details see the accompanying COPYING-CMAKE-SCRIPTS file.
#


if (GTK-PIXBUF_LIBRARIES AND GTK-PIXBUF_INCLUDE_DIRS)
  # in cache already
  set(GTK-PIXBUF_FOUND TRUE)
else (GTK-PIXBUF_LIBRARIES AND GTK-PIXBUF_INCLUDE_DIRS)
  # use pkg-config to get the directories and then use these values
  # in the FIND_PATH() and FIND_LIBRARY() calls
  #include(UsePkgConfig)

  #pkgconfig(gdk-pixbuf-2.0 _GTK-PIXBUFIncDir _GTK-PIXBUFLinkDir _GTK-PIXBUFLinkFlags _GTK-PIXBUFCflags)

  set(GTK-PIXBUF_DEFINITIONS ${_GTK-PIXBUFCflags})

  find_path(GTK-PIXBUF_INCLUDE_DIR
    NAMES
      gdk-pixbuf/gdk-pixdata.h
    PATHS
      ${_GTK-PIXBUFIncDir}
      /usr/include
      /usr/local/include
      /opt/local/include
      /sw/include
      $ENV{HOME}/bin/include
      $ENV{HOME}/local/include
      $ENV{HOME}/bin/local/include
    PATH_SUFFIXES
      gdk-pixbuf-2.0
  )

  find_library(GDK_PIXBUF-2.0_LIBRARY
    NAMES
      gdk_pixbuf-2.0
    PATHS
      ${_GTK-PIXBUFLinkDir}
      /usr/lib
      /usr/local/lib
      /opt/local/lib
      /sw/lib
      $ENV{HOME}/bin/lib
      $ENV{HOME}/local/lib
      $ENV{HOME}/bin/local/lib
  )

  set(GTK-PIXBUF_INCLUDE_DIRS
    ${GTK-PIXBUF_INCLUDE_DIR}
  )
  set(GTK-PIXBUF_LIBRARIES
    ${GDK_PIXBUF-2.0_LIBRARY}
)

  if (GTK-PIXBUF_INCLUDE_DIRS AND GTK-PIXBUF_LIBRARIES)
     set(GTK-PIXBUF_FOUND TRUE)
  endif (GTK-PIXBUF_INCLUDE_DIRS AND GTK-PIXBUF_LIBRARIES)

  if (GTK-PIXBUF_FOUND)
    if (NOT GTK-PIXBUF_FIND_QUIETLY)
      message(STATUS "Found GTK-PIXBUF: ${GTK-PIXBUF_LIBRARIES}")
    endif (NOT GTK-PIXBUF_FIND_QUIETLY)
  else (GTK-PIXBUF_FOUND)
    if (GTK-PIXBUF_FIND_REQUIRED)
      message(FATAL_ERROR "Could not find GTK-PIXBUF")
    endif (GTK-PIXBUF_FIND_REQUIRED)
  endif (GTK-PIXBUF_FOUND)

  # show the GTK-PIXBUF_INCLUDE_DIRS and GTK-PIXBUF_LIBRARIES variables only in the advanced view
  mark_as_advanced(GTK-PIXBUF_INCLUDE_DIRS GTK-PIXBUF_LIBRARIES)

endif (GTK-PIXBUF_LIBRARIES AND GTK-PIXBUF_INCLUDE_DIRS)

