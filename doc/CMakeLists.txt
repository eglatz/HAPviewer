cmake_minimum_required (VERSION 2.6)

configure_file (
    "${PROJECT_SOURCE_DIR}/doc/Doxyfile.in"
    "${PROJECT_BINARY_DIR}/Doxyfile"
)

add_custom_target(doxygen
    #build the doxygen documentation
    COMMAND cd "${PROJECT_BINARY_DIR}" && ${DOXYGEN_EXECUTABLE} Doxyfile
)

# add doxygen as dependency to doc-target
get_target_property(DOC_TARGET doc TYPE)
if(NOT DOC_TARGET)
	add_custom_target(doc)
endif()
add_dependencies(doc doxygen)


install(DIRECTORY "${PROJECT_BINARY_DIR}/doxygen_docu" DESTINATION share/doc/hapviewer)
