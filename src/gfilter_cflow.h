/**
 *	\file gfilter_cflow.h
 *	\brief Filter to import and export cflow files
 */

#ifndef GFILTER_CFLOW_H_
#define GFILTER_CFLOW_H_

#include <iosfwd>
#include <string>
#include <stdint.h>
#include <boost/iostreams/filtering_streambuf.hpp>
#include <boost/iostreams/filtering_stream.hpp>
#include <boost/iostreams/filter/gzip.hpp>
#include <boost/iostreams/device/file.hpp>

#include "gfilter.h"
#include "IPv6_addr.h"
#include "cflow.h"

class GFilter_cflow: public GFilter {
public:
	GFilter_cflow(std::string formatName = "cflow", std::string humanReadablePattern = "*.gz", std::string regexPattern = ".*\\.gz$");

	// import methods
	void read_file(std::string filename, CFlowList & flowlist, bool append = false) const;
	virtual void read_file(std::string filename, CFlowList & flowlist, const IPv6_addr & local_net, const IPv6_addr & netmask, bool append) const;

	// export methods
	virtual void write_file(const std::string & out_filename, const Subflowlist flowlist, bool appendIfExisting = true) const;
	virtual void write_flow(boost::iostreams::filtering_ostream & out_filestream, const cflow_t & cf) const;

protected:
	enum cflow_version {
		none, v_cflow4, v_cflow6
	};

	// general methods
	cflow_version detect_cflow_version(std::string in_filename) const;
	virtual bool checkCflowFileSize(uint32_t size) const=0;

	// export methods
	virtual void openGzipStream(boost::iostreams::filtering_ostream & out_filestream, boost::iostreams::file_sink & out_filesink,
	      const std::string & in_filename) const;

	// import methods
	void openGunzipStream(boost::iostreams::filtering_istream & in_filestream, boost::iostreams::file_source & infs, const std::string & in_filename) const;
	uint32_t getUncompressedFileSize(std::ifstream & in_filestream) const;
	virtual unsigned int getNumberOfFlows(uint32_t size) const=0;
	virtual void read_flow(boost::iostreams::filtering_istream & infs, cflow_t & cf) const=0;
};

class GFilter_cflow4: public GFilter_cflow {
public:
	GFilter_cflow4(std::string formatName = "cflow4", std::string humanReadablePattern = "*.gz", std::string regexPattern = ".*\\.gz$");

	// import methods
	virtual bool acceptFileForReading(std::string in_filename) const;

protected:
	virtual bool checkCflowFileSize(uint32_t size) const;
	virtual unsigned int getNumberOfFlows(uint32_t size) const;
	virtual void read_flow(boost::iostreams::filtering_istream & infs, cflow_t & cf) const;
	virtual void read_flow(boost::iostreams::filtering_istream & infs, cflow_t & cf, uint8_t & oldmagic) const;
};

class GFilter_cflow6: public GFilter_cflow {
public:
	GFilter_cflow6(std::string formatName = "cflow6", std::string humanReadablePattern = "*.gz", std::string regexPattern = ".*\\.gz$");

	// import methods
	virtual bool acceptFileForReading(std::string in_filename) const;

	// export methods
	virtual bool acceptFileForWriting(std::string in_filename) const {
		return acceptFilename(in_filename);
	}
	virtual void openGzipStream(boost::iostreams::filtering_ostream & out_filestream, boost::iostreams::file_sink & out_filesink,
	      const std::string & in_filename) const;
	virtual void write_flow(boost::iostreams::filtering_ostream & out_filestream, const cflow_t & cf) const;

protected:
	virtual bool checkCflowFileSize(uint32_t size) const;
	virtual unsigned int getNumberOfFlows(uint32_t size) const;
	virtual void read_flow(boost::iostreams::filtering_istream & infs, cflow_t & cf) const;
	virtual void read_flow(boost::iostreams::filtering_istream & infs, cflow_t & cf, uint8_t & oldmagic) const;
};

#endif /* GFILTER_CFLOW_H_ */
