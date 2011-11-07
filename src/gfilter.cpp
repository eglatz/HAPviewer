/**
 *	\file gfilter.cpp
 *	\brief Filter to import and export various file formats
 */

#include <string>
#include <boost/regex.hpp>
#include <libgen.h>

#include "gfilter.h"

using namespace std;

/**
 *	Constructor
 *
 *	\param	formatName	Name of this format
 *	\param	humanReadablePattern	A simple name pattern for files of this type, used by e.g. the GUI
 *	\param	regexPattern	Regex pattern used internally
 */
GFilter::GFilter(std::string formatName, std::string humanReadablePattern, std::string regexPattern) :
	formatName(formatName), humanReadablePattern(humanReadablePattern), regexPattern(regexPattern) {
	// nothing to do here
}

/**
 *	Decide if this filter supports this file, using the filename to decide
 *
 *	\param in_filename Inputfilename
 *
 *	\return True if the file is supported by this filter
 *
 */
bool GFilter::acceptFilename(std::string in_filename) const {
	boost::regex e(regexPattern);
	char * in_filename_cstr = strdup(in_filename.c_str());
	string filename(basename(in_filename_cstr));
	free(in_filename_cstr);

	if (boost::regex_match(filename, e))
		return true;
	return false;
}

/**
 *	Gives the format name back
 *
 *	\return std::string Format name
 */
std::string GFilter::getFormatName() const {
	return formatName;
}

/**
 *	Gives a human readable pattern for the file name, e.g. *.gz
 *
 *	\return std::string Human readable pattern
 */
std::string GFilter::getHumanReadablePattern() const {
	return humanReadablePattern;
}

/**
 *	Return if this GFilter can write to a file
 *
 *	\param in_filename Inputfilenam
 *
 *	\return bool True if this GFilter can write to a file
 */
bool GFilter::acceptFileForWriting(std::string in_filename) const {
	return false;
}

/**
 *	Write to a file
 *
 *	\param in_filename Filename to the file to write to
 *	\param flowlist A vector of cflow's to write
 *	\param appendIfExisting If true, GFilter will try to append to a possibly already existing file
 *
 *	\exception std::string If function gets called even when canWrite() fails.
 */
void GFilter::write_file(const std::string & in_filename, const Subflowlist subflowlist, bool appendIfExisting) const {
	throw "This filter does not support writing";
}
