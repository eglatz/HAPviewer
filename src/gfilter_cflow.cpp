/**
 *	\file gfilter_cflow.cpp
 *	\brief Filter to import and export cflow files
 */

#include <iostream>
#include <sstream>
#include <boost/iostreams/filtering_streambuf.hpp>
#include <boost/iostreams/filtering_stream.hpp>
#include <boost/iostreams/filter/gzip.hpp>
#include <boost/iostreams/device/file.hpp>

#include "gfilter_cflow.h"
#include "gutil.h"
#include "cflow.h"

using namespace std;

/**
 *	\class	GFilter_cflow
 *	\brief	Abstract basis class to import cflow_t files
 *
 *	\param	formatName	Name of this format
 *	\param	humanReadablePattern	A simple name pattern for files of this type, used by e.g. the GUI
 *	\param	regexPattern	Regex pattern used internally
 */
GFilter_cflow::GFilter_cflow(string formatName, string humanReadablePattern, string regexPattern) :
	GFilter(formatName, humanReadablePattern, regexPattern) {
	// nothing to do here
}

/**
 *	Returns the version of the cflow_t file. Decision is based on the comments in the gzip file (or their absence)
 *	Details: http://www.gzip.org/zlib/rfc-gzip.html#specification
 *
 *	\param in_filename File which should be tested
 *
 *	\return Cflow version of the file
 *
 *	\exception std::string Errortext
 */
GFilter_cflow::cflow_version GFilter_cflow::detect_cflow_version(string in_filename) const {
	ifstream cflow_inputstream;
	cflow_version version = none;
	try {
		util::open_infile(cflow_inputstream, in_filename);
	} catch (...) {
		string errormsg = "ERROR: check input file " + in_filename + " and try again.";
		throw errormsg;
	}

	// Verify that it is a GZIP file (check GZIP metadata)
	uint8_t HDR[4]; // First three bytes of header
	cflow_inputstream.read((char *) HDR, 4); // Get first four bytes
	unsigned int ID1 = HDR[0];
	unsigned int ID2 = HDR[1];
	unsigned int CM = HDR[2];
	unsigned int FLG = HDR[3];

	if (ID1 == 0x1f && ID2 == 0x8b && CM == 8) {
		//cout << "File recognized to have GZIP format according to RFC1952 (magic numbers comply).\n";
	} else {
		string errtext = "ERROR: input file does not comply with GZIP-format according to RFC1952.";
		// cerr << "One or more incorrect magic numbers ID1 = " << hex << ID1 << ", ID2 = " << ID1 << dec << ", CM = " << CM << endl;
		throw errtext;
	}

	cflow_inputstream.seekg(10, ios::beg); // move behind the fixed-length header

	if (FLG & 0x4) { // Detect if there is an extra field and jump over if
		uint16_t xlen = 0;
		cflow_inputstream.read((char*) &xlen, 2);
		cout << "Input file has FLG.FEXTRA set, size = " << xlen << endl;
		long newpos = cflow_inputstream.tellg();
		newpos += (long) xlen;
		cflow_inputstream.seekg(newpos);
	}

	if (FLG & 0x8) { // Detect if there is an extra field and jump over if
		stringstream originalname;
		char newchar = 'x';
		while (true) {
			cflow_inputstream.read(&newchar, 1);
			if (newchar != '\0')
				originalname << newchar;
			else
				break;
		}
		cout << "Input file has FLG.NAME set: " << originalname.str() << endl;
		cflow_inputstream.get(); // Jump over the 0 byte
	}

	if (FLG & 0x16) { // If there is a comment, we assume that the format is cflow6
		version = v_cflow6;
		string comment;
		getline(cflow_inputstream, comment, '\0');
		cflow_inputstream.get(); // Jump over the 0 byte
	} else {
		version = v_cflow4;
	}

	if (!cflow_inputstream.good())
		throw "Unexpected end of file.";
	cflow_inputstream.close();
	return version;
}

/**
 *	Returns the number of bytes the uncompressed gz-file contains
 *
 *	\param in_filename Filestream for which the size gets looked up
 *
 *	\return Number of bytes
 */
uint32_t GFilter_cflow::getUncompressedFileSize(ifstream & in_filestream) const {
	uint32_t isize = 0; // By default, GZIP can just store up to 4GiBytes of data
	long old_pos = in_filestream.tellg();

	in_filestream.seekg(-4, ios::end);

	// read the (uncompressed) filesize
	in_filestream.read((char *) &isize, 4); // FIXME: big endian will freak out here
	in_filestream.seekg(old_pos);
	return isize;
}

/**
 *	Creates a stream which uncompresses a gz-file
 *
 *	\param in_filestream The resulting, uncompressed stream
 *	\param in_filename Filename of the compressed file
 *
 *	\exception std::string Errortext
 */
void GFilter_cflow::openGunzipStream(boost::iostreams::filtering_istream & in_filestream, boost::iostreams::file_source & infs, const string & in_filename) const {
	// Add stream decompressor
	in_filestream.push(boost::iostreams::gzip_decompressor());

	// Open input file and link it to stream chain
	if (!infs.is_open()) {
		string errtext = "ERROR: could not open file source \"" + in_filename + "\".";
		throw errtext;
	}
	in_filestream.push(infs);
	cout << "Reading file " << in_filename << ":\n";
}

/**
 *	Reads a given file into a given flowlist.
 *
 *	\param filename Filename of the compressed cflow_t file
 *	\param flowlist List which will be filled with the cflows
 *	\param local_net Contains the IP
 *	\param netmask Contains the netmask
 *	\param append If true, do not clear the flowlist, instead append it to the existing data (not yet used)
 */
void GFilter_cflow::read_file(std::string filename, CFlowList & flowlist, const IPv6_addr & local_net, const IPv6_addr & netmask, bool append) const {
	read_file(filename, flowlist, append);
	return;
}

/**
 *	Reads a given file into a given flowlist.
 *
 *	\param filename Filename of the compressed cflow_t file
 *	\param flowlist List which will be filled with the cflows
 *	\param append If true, do not clear the flowlist, instead append it to the existing data (not yet used)
 *
 *	\exception std::string Errortext
 */
void GFilter_cflow::read_file(string in_filename, CFlowList & flowlist, bool append) const {
	// TODO: take care about the append flag
	ifstream cflow_compressed_inputstream;
	uint32_t uncompressed_size = 0;

	try {
		util::open_infile(cflow_compressed_inputstream, in_filename);
	} catch (...) {
		string errormsg = "ERROR: check input file " + in_filename + " and try again.";
		throw errormsg;
	}

	uncompressed_size = getUncompressedFileSize(cflow_compressed_inputstream);

	// Check if this file can be a cflow_t-file
	if (!checkCflowFileSize(uncompressed_size)) {
		string errortext = in_filename;
		errortext += " does not look like a cflow file (wrong size)";
		throw errortext;
	}

	//close the file for now
	cflow_compressed_inputstream.close();

	// Open up a stream chain
	boost::iostreams::filtering_istream cflow_uncompressed_inputstream;
	boost::iostreams::file_source infs(in_filename);
	openGunzipStream(cflow_uncompressed_inputstream, infs, in_filename);

	unsigned int maxnum_flows = getNumberOfFlows(uncompressed_size);

	// Resize flowlist to fit for all cflows
	flowlist.resize(maxnum_flows);

	CFlowList::iterator flowlist_iterator = flowlist.begin();

	// Read file data: get all flows
	while (flowlist_iterator != flowlist.end()) {
		try {
			read_flow(cflow_uncompressed_inputstream, *flowlist_iterator);
		} catch (string & error) {
			throw error;
		}
		// advance to next index in flowlist
		flowlist_iterator++;

		// Clear early/late attributes
		flowlist_iterator->flowtype &= (flow_type_t) simpleflow;
	}

	// tellg() does not work on boost::iostreams::filtering_istream, so we have to work around
	char tmpChar = 'X';
	cflow_uncompressed_inputstream.read(&tmpChar, 1);

	// if this is still good, something went wrong
	if (cflow_uncompressed_inputstream.good()) {
		string error = "ERROR: flow list overflow. ";
		error += "Calculated flow count ";
		error += maxnum_flows;
		error += " from input file isize ";
		error += uncompressed_size;
		error += " is exceeded.";
		throw error;
	}
}

/**
 *	Writes a given flowlist into a given filename. Appends to already existing files if requested.
 *
 *	\param in_filename Filename of the compressed cflow_t file
 *	\param flowlist List which will be filled with the cflows
 *	\param appendIfExisting If true, do not fail if the file is already existing, instead append out flowlist to it
 *
 *	\exception std::string Errortext
 */
void GFilter_cflow::write_file(const std::string & out_filename, const Subflowlist subflowlist, bool appendIfExisting) const {
	CFlowList oldflowlist;
	if (util::fileExists(out_filename) && appendIfExisting) {
		GFilter_cflow4 gfilter_cflow4;
		GFilter_cflow6 gfilter_cflow6;
		if (gfilter_cflow4.acceptFileForReading(out_filename))
			gfilter_cflow4.read_file(out_filename, oldflowlist, false);
		else if (gfilter_cflow6.acceptFileForReading(out_filename))
			gfilter_cflow6.read_file(out_filename, oldflowlist, false);
		else {
			stringstream error;
			error << "Can not append to " << out_filename << ". Can not read in this file.";
			throw error.str();
		}
	}

	if (util::fileExists(out_filename)) {
		if (unlink(out_filename.c_str()) == -1) {
			stringstream error;
			error << "ERROR: could not delete old file \"" << out_filename << "\"";
			throw error.str();
		}
	}
	boost::iostreams::file_sink out_filesink(out_filename); // File sink object for serialized data
	// File sink is closed when object is destroyed (at function end)
	boost::iostreams::filtering_ostream out_filestream; // Output stream object for serialized data
	openGzipStream(out_filestream, out_filesink, out_filename);

	if(oldflowlist.size() > 0) {
		copy(subflowlist.begin(), subflowlist.end(), back_inserter(oldflowlist));
		sort(oldflowlist.begin(), oldflowlist.end());
		for (CFlowList::const_iterator it = oldflowlist.begin(); it != oldflowlist.end() && appendIfExisting; it++)
			write_flow(out_filestream, *it);
	} else {
		for (CFlowList::const_iterator it = subflowlist.begin(); it != subflowlist.end(); it++)
			write_flow(out_filestream, *it);
	}
}

/**
 * Writes a single flow to filtering_ostream
 *
 * @param out_filestream Filename to write
 * @param cf flow to write
 *
 * @exception std::string Errortext
 */
void GFilter_cflow::write_flow(boost::iostreams::filtering_ostream & out_filestream, const cflow_t & cf) const {
	throw "This filter does not support writing";
}

/**
 *	Creates a stream which compresses to a gz-file
 *
 *	@param in_filestream The resulting, uncompressed stream
 *	@param in_filename Filename of the compressed file
 *
 *	@exception std::string Errortext
 */
void GFilter_cflow::openGzipStream(boost::iostreams::filtering_ostream & out_filestream, boost::iostreams::file_sink & out_filesink,
      const std::string & in_filename) const {
	throw "This filter does not support writing";
}

/**
 *	\class	GFilter_cflow4
 *	\brief	Class to import old cflow4 files
 *
 *	\param	formatName	Name of this format
 *	\param	humanReadablePattern	A simple name pattern for files of this type, used by e.g. the GUI
 *	\param	regexPattern	Regex pattern used internally
 */
GFilter_cflow4::GFilter_cflow4(std::string formatName, std::string humanReadablePattern, std::string regexPattern) :
	GFilter_cflow(formatName, humanReadablePattern, regexPattern) {
	// nothing to do here
}

/**
 *	Decides if this file contains cflow4 flows
 *
 *	\param in_filename File which should be tested
 *
 *	\return True if this file contains cflow4 flows, false if not
 */
bool GFilter_cflow4::acceptFileForReading(string in_filename) const {
	if (GFilter::acceptFilename(in_filename)) {
		try {
			if (detect_cflow_version(in_filename) == v_cflow4)
				return true;
		} catch (string & e) {
			cerr << e << endl;
		}
	}
	return false;
}

/**
 *	Decides, if the given number of bytes is a multiple of the size of a cflow4 struct
 *
 *	\param uncompressed_size Size in bytes of the whole e.g. file
 *
 *	\return True if the given number is a multiple of sizeof(cflow4)
 */
bool GFilter_cflow4::checkCflowFileSize(uint32_t uncompressed_size) const {
	if (uncompressed_size % sizeof(cflow4) != 0) {
		string errtext = "\nERROR: input file data size is not a multiple of a cflow4 record.\n";
		errtext += "Possibly this is not a gzipped file containing cflow4 data.\n";
		stringstream ss;
		ss << "File size is: " << uncompressed_size << ", sizeof(struct cflow4) is: " << sizeof(struct cflow4) << "\n";
		errtext += ss.str();
		cerr << errtext;
		return false;
	}
	return true;
}

/**
 *	Return the number of flows which can be stored in a given filesize
 *
 *	\param size Size in bytes of the whole e.g. file
 *
 *	\return Number of cflow4 version flows fit into this size
 */
unsigned int GFilter_cflow4::getNumberOfFlows(uint32_t size) const {
	return size / (sizeof(struct cflow4));
}

/**
 *	Reads a single flow and stores it into a cflow_t struct
 *
 *	\param infs Inputstream to read from
 *	\param cf Cflow struct to write to
 *	\param oldmagic stores the old magic number before it got updated (assumes that all magic numbers are the same in single file)
 */
void GFilter_cflow4::read_flow(boost::iostreams::filtering_istream & infs, cflow_t & cf, uint8_t & oldmagic) const {
	oldmagic = CFLOW_4_MAGIC_NUMBER;
	read_flow(infs, cf);
}

/**
 *	Reads a single flow and stores it into a cflow_t struct
 *
 *	\param infs Inputstream to read from
 *	\param cf Cflow struct to write to
 *
 *	\exception std::string Errortext
 */
void GFilter_cflow4::read_flow(boost::iostreams::filtering_istream & infs, cflow_t & cf) const {
	cflow4 tmpCflow4;
	infs.read((char *) &tmpCflow4, sizeof(struct cflow4));

	streamsize num_read = infs.gcount();
	if (num_read != sizeof(struct cflow4)) {
		string errtext = "ERROR: read ";
		errtext += num_read;
		errtext += " byte instead of ";
		errtext += sizeof(struct cflow4);
		errtext += ". Possibly incomplete flow read from file.";
		throw errtext;
	}

	// Check flow data
	if (tmpCflow4.magic != CFLOW_4_MAGIC_NUMBER) {
		string errtext = "ERROR: file check failed (wrong magic number) in in CImport::read_flow4.";
		throw errtext;
	}

	cf.localIP = IPv6_addr(tmpCflow4.localIP);
	cf.localPort = tmpCflow4.localPort;
	cf.remoteIP = IPv6_addr(tmpCflow4.remoteIP);
	cf.remotePort = tmpCflow4.remotePort;
	cf.prot = tmpCflow4.prot;
	cf.flowtype = tmpCflow4.flowtype;
	cf.startMs = tmpCflow4.startMs;
	cf.durationMs = tmpCflow4.durationMs;
	cf.dOctets = tmpCflow4.dOctets;
	cf.dPkts = tmpCflow4.dPkts;
	cf.localAS = tmpCflow4.AS.local;
	cf.remoteAS = tmpCflow4.AS.remote;
	cf.tos_flags = tmpCflow4.tos_flags;
	cf.magic = CFLOW_CURRENT_MAGIC_NUMBER; // Update it to the current version
}

/**
 *	\class	GFilter_cflow6
 *	\brief	Class to import cflow6 files
 *
 *	\param	formatName	name of this format
 *	\param	humanReadablePattern	a simple name pattern for files of this type, used by e.g. the GUI
 *	\param	regexPattern	regex pattern used internal
 */
GFilter_cflow6::GFilter_cflow6(std::string formatName, std::string humanReadablePattern, std::string regexPattern) :
	GFilter_cflow(formatName, humanReadablePattern, regexPattern) {
	// nothing to do here
}

/**
 *	Decides if this file contains cflow6 flows
 *
 *	\param in_filename File which should be tested
 *
 *	\return True if this file contains cflow4 flows, false if not
 */
bool GFilter_cflow6::acceptFileForReading(string in_filename) const {
	if (GFilter::acceptFilename(in_filename)) {
		try {
			if (detect_cflow_version(in_filename) == v_cflow6)
				return true;
		} catch (string & e) {
			cerr << e << endl;
		}
	}
	return false;
}

/**
 *	Decides, if the given number of bytes is a multiple of the size of a cflow6 struct
 *
 *	\param uncompressed_size Size in bytes of the whole e.g. file
 *
 *	\return True if the given number is a multiple of sizeof(cflow6)
 */
bool GFilter_cflow6::checkCflowFileSize(uint32_t uncompressed_size) const {
	if (uncompressed_size % sizeof(cflow_t) != 0) {
		string errtext = "\nERROR: input file data size is not a multiple of a cflow4 record.\n";
		errtext += "Possibly this is not a gzipped file containing cflow4 data.\n";
		stringstream ss;
		ss << "File size is: " << uncompressed_size << ", sizeof(struct cflow) is: " << sizeof(cflow_t) << "\n";
		errtext += ss.str();
		cerr << errtext;
		return false;
	}
	return true;
}

/**
 *	Return the number of flows which can be stored in a given filesize
 *
 *	\param size Size in bytes of the whole e.g. file
 *
 *	\return Number of cflow4 version flows fit into this size
 */
unsigned int GFilter_cflow6::getNumberOfFlows(uint32_t size) const {
	return size / (sizeof(cflow_t));
}

/**
 *	Reads a single flow and stores it into a cflow_t struct
 *
 *	\param infs Inputstream to read from
 *	\param cf Cflow struct to write to
 *	\param oldmagic stores the old magic number before it got updated (assumes that all magic numbers are the same in single file)
 *
 */
void GFilter_cflow6::read_flow(boost::iostreams::filtering_istream & infs, cflow_t & cf, uint8_t & oldmagic) const {
	oldmagic = CFLOW_CURRENT_MAGIC_NUMBER;
	read_flow(infs, cf);
}

/**
 *	Reads a single flow and stores it into a cflow_t struct
 *
 *	\param infs Inputstream to read from
 *	\param cf Cflow struct to write to
 *
 *	\exception std::string Errortext
 */
void GFilter_cflow6::read_flow(boost::iostreams::filtering_istream & infs, cflow_t & cf) const {
	infs.read((char *) &cf, sizeof(cflow_t));

	streamsize num_read = infs.gcount();
	if (num_read != sizeof(cflow_t)) {
		string errtext = "ERROR: read ";
		errtext += num_read;
		errtext += " byte instead of ";
		errtext += sizeof(struct cflow4);
		errtext += ". Possibly incomplete flow read from file.";
		throw errtext;
	}

	// Check flow data
	if (cf.magic != CFLOW_CURRENT_MAGIC_NUMBER) {
		string errtext = "ERROR: file check failed (wrong magic number) in in CImport::read_flow6.";
		throw errtext;
	}
}

/**
 *	Creates a stream which compresses to a gz-file
 *
 *	\param in_filestream The resulting, uncompressed stream
 *	\param in_filename Filename of the compressed file
 *
 *	\exception std::string Errortext
 */
void GFilter_cflow6::openGzipStream(boost::iostreams::filtering_ostream & out_filestream, boost::iostreams::file_sink & out_filesink,
      const std::string & out_filename) const {
	// Add a comment to the gz file to signal cflow6 content
	boost::iostreams::gzip_params params;
	params.comment = "CFLOW: cflow6";

	// Use gzip compression
	out_filestream.push(boost::iostreams::gzip_compressor(params));

	// Open output file and link it to stream chain
	if (!out_filesink.is_open()) {
		string errtext = "ERROR: could not open file destination \"" + out_filename + "\".";
		throw errtext;
	}
	out_filestream.push(out_filesink);
}

/**
 *	Writes a single flow to the given boost::iostreams::filtering_ostream
 *
 *	\param out_filestream filtering_ostream to write ti
 *	\param cf Cflow which should get saved
 */
void GFilter_cflow6::write_flow(boost::iostreams::filtering_ostream & out_filestream, const cflow_t & cf) const {
	out_filestream.write((char *) &(cf), sizeof(cflow_t));
}
