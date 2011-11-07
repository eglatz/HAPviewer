/**
 *	\file gfilter_nfdump_gnfdump.cpp
 *	\brief Contains needed code from nfdump tool set to import flows from nfdump files.
 *	For copyright details see below.
 */

/*
 *  Copyright (c) 2009, Peter Haag
 *  Copyright (c) 2004-2008, SWITCH - Teleinformatikdienste fuer Lehre und Forschung
 *  All rights reserved.
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions are met:
 *
 *   * Redistributions of source code must retain the above copyright notice,
 *     this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright notice,
 *     this list of conditions and the following disclaimer in the documentation
 *     and/or other materials provided with the distribution.
 *   * Neither the name of SWITCH nor the names of its contributors may be
 *     used to endorse or promote products derived from this software without
 *     specific prior written permission.
 *
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 *  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 *  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 *  ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 *  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 *  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 *  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 *  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 *  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 *  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 *  POSSIBILITY OF SUCH DAMAGE.
 *
 *  $Author: haag $
 *
 *  $Id: nfx.c 58 2010-02-26 12:26:07Z haag $
 *
 *  $LastChangedRevision: 58 $
 *
 */

// Simplifications:
// - single file processing only
// - no support for compressed nfdump files
// Assumptions:
// - has to be compiled with GCC

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>
#include <fcntl.h>
#include <time.h>

#include <unistd.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "gfilter_nfdump_gnfdump.h"

#ifndef DEVEL
#define dbg_printf(...) /* printf(__VA_ARGS__) */
#else
#define dbg_printf(...) printf(__VA_ARGS__)
#endif

// defined, with value 1, if (and only if) the compilation is for a target where long int
// and pointer both use 64-bits and int uses 32-bit
#ifdef __LP64__
typedef uint64_t pointer_addr_t;
#else
typedef uint32_t pointer_addr_t;
#endif

// *** Code from nfx.c *********************************************************

/* global vars */

#pragma GCC diagnostic ignored "-Wwrite-strings"

/*
 * see nffile.h for detailed extension description
 */
extension_descriptor_t extension_descriptor[] = {
// fill indices 0 - 3
      { COMMON_BLOCK_ID, 0, 0, 1, "Required extension: Common record" }, { EX_IPv4v6, 0, 0, 1, "Required extension: IPv4/IPv6 src/dst address" }, {
            EX_PACKET_4_8, 0, 0, 1, "Required extension: 4/8 byte input packets" }, { EX_BYTE_4_8, 0, 0, 1, "Required extension: 4/8 byte input bytes" },

      // the optional extension
      { EX_IO_SNMP_2, 4, 1, 1, "2 byte input/output interface index" }, { EX_IO_SNMP_4, 8, 1, 1, "4 byte input/output interface index" }, { EX_AS_2, 4, 2, 1,
            "2 byte src/dst AS number" }, { EX_AS_4, 8, 2, 1, "4 byte src/dst AS number" }, { EX_MULIPLE, 4, 3, 0, "dst tos, direction, src/dst mask" }, {
            EX_NEXT_HOP_v4, 4, 4, 0, "IPv4 next hop" }, { EX_NEXT_HOP_v6, 16, 4, 0, "IPv6 next hop" }, { EX_NEXT_HOP_BGP_v4, 4, 5, 0, "IPv4 BGP next IP" }, {
            EX_NEXT_HOP_BGP_v6, 16, 5, 0, "IPv6 BGP next IP" }, { EX_VLAN, 4, 6, 0, "src/dst vlan id" }, { EX_OUT_PKG_4, 4, 7, 0, "4 byte output packets" }, {
            EX_OUT_PKG_8, 8, 7, 0, "8 byte output packets" }, { EX_OUT_BYTES_4, 4, 8, 0, "4 byte output bytes" }, { EX_OUT_BYTES_8, 8, 8, 0,
            "8 byte output bytes" }, { EX_AGGR_FLOWS_4, 4, 9, 0, "4 byte aggregated flows" }, { EX_AGGR_FLOWS_8, 8, 9, 0, "8 byte aggregated flows" }, {
            EX_MAC_1, 16, 10, 0, "in src/out dst mac address" }, { EX_MAC_2, 16, 11, 0, "in dst/out src mac address" }, { EX_MPLS, 40, 12, 0, "MPLS Labels" }, {
            EX_ROUTER_IP_v4, 4, 13, 0, "IPv4 router IP addr" }, { EX_ROUTER_IP_v6, 16, 13, 0, "IPv6 router IP addr" }, { EX_ROUTER_ID, 4, 14, 0, "router ID" },

      // last entry
      { 0, 0, 0, 0, NULL } };

#pragma GCC diagnostic warning "-Wwrite-strings"

void InitExtensionMaps(extension_map_list_t *extension_map_list) {
	memset((void *) extension_map_list->slot, 0, MAX_EXTENSION_MAPS * sizeof(extension_info_t *));
	memset((void *) extension_map_list->page, 0, MAX_EXTENSION_MAPS * sizeof(extension_info_t *));

	extension_map_list->next_free = 0;
	extension_map_list->max_used = -1;

} // End of InitExtensionMaps

void FreeExtensionMaps(extension_map_list_t *extension_map_list) {
	int32_t i;

	if (extension_map_list == NULL)
		return;

	// free all maps
	for (i = 0; i <= extension_map_list->max_used; i++) {
		if (extension_map_list->slot[i]) {
			if (extension_map_list->slot[i]->map) {
				free(extension_map_list->slot[i]->map);
				extension_map_list->slot[i]->map = NULL;
			}
			free(extension_map_list->slot[i]);
			extension_map_list->slot[i] = NULL;
		}

	}

	// free all paged maps
	for (i = 0; (uint32_t) i < extension_map_list->next_free; i++) {
		if (extension_map_list->page[i]) {
			if (extension_map_list->page[i]->map) {
				free(extension_map_list->page[i]->map);
				extension_map_list->page[i]->map = NULL;
			}
			free(extension_map_list->page[i]);
			extension_map_list->page[i] = NULL;
		}
	}

	InitExtensionMaps(extension_map_list);

} // End of FreeExtensionMaps

int Insert_Extension_Map(extension_map_list_t *extension_map_list, extension_map_t *map) {
	uint32_t next_free = extension_map_list->next_free;
	uint16_t map_id;

	map_id = map->map_id == INIT_ID ? 0 : map->map_id & EXTENSION_MAP_MASK;
	map->map_id = map_id;
	dbg_printf("Insert Extension Map:\n");
#ifdef DEVEL
	PrintExtensionMap(map);
#endif
	// is this slot free
	if (extension_map_list->slot[map_id]) {
		uint32_t i, map_found;
		dbg_printf("Map %d already exists\n", map_id);
		// no - check if same map already in slot
		if (extension_map_list->slot[map_id]->map->size == map->size) {
			// existing map and new map have the same size
			dbg_printf("New map same size:\n");

			// we must compare the maps
			i = 0;
			while (extension_map_list->slot[map_id]->map->ex_id[i] && (extension_map_list->slot[map_id]->map->ex_id[i] == map->ex_id[i]))
				i++;

			// if last entry == 0 => last map entry => maps are the same
			if (extension_map_list->slot[map_id]->map->ex_id[i] == 0) {
				dbg_printf("Same map => nothing to do\n");
				// same map
				return 0;
			} dbg_printf("Different map => continue\n");
		}

		dbg_printf("Search for map in extension page\n");
		map_found = -1;
		// new map is different but has same id - search for map in page list
		for (i = 0; i < next_free; i++) {
			int j;
			j = 0;
			if (extension_map_list->page[i]->map->size == map->size) {
				while (extension_map_list->page[i]->map->ex_id[j] && (extension_map_list->page[i]->map->ex_id[j] == map->ex_id[j]))
					j++;
			}
			if (extension_map_list->page[i]->map->ex_id[j] == 0) {
				dbg_printf("Map found in page slot %i\n", i);
				map_found = i;
			}
		}
		if (map_found >= 0) {
			extension_info_t *tmp;
			dbg_printf("Move map from page slot %i to slot %i\n", map_found ,map_id);

			// exchange the two maps
			tmp = extension_map_list->slot[map_id];
			extension_map_list->slot[map_id] = extension_map_list->page[map_found];
			extension_map_list->slot[map_id]->map->map_id = map_id;

			extension_map_list->page[map_found] = tmp;
			extension_map_list->page[map_found]->map->map_id = map_found;
			return 1;

		} else {
			dbg_printf("Map not found in extension page\n");
			// map not found - move it to the extension page to a currently free slot
			if (next_free < MAX_EXTENSION_MAPS) {
				dbg_printf("Move existing map from slot %d to page slot %d\n",map_id, next_free);
				extension_map_list->page[next_free] = extension_map_list->slot[map_id];
				extension_map_list->page[next_free]->map->map_id = next_free;
				extension_map_list->slot[map_id] = NULL;
				// ready to fill new slot
			} else {
				fprintf(stderr, "Extension map list exhausted - too many extension maps ( > %d ) to process;\n", MAX_EXTENSION_MAPS);
				exit(255);
			}
		}
	}

	// add new entry to slot
	extension_map_list->slot[map_id] = (extension_info_t *) calloc(1, sizeof(extension_info_t));
	if (!extension_map_list->slot[map_id]) {
		fprintf(stderr, "calloc() error in %s line %d: %s\n", __FILE__, __LINE__, strerror(errno));
		exit(255);
	}
	extension_map_list->slot[map_id]->map = (extension_map_t *) malloc((ssize_t) map->size);
	if (!extension_map_list->slot[map_id]->map) {
		fprintf(stderr, "malloc() error in %s line %d: %s\n", __FILE__, __LINE__, strerror(errno));
		exit(255);
	}
	memcpy((void *) extension_map_list->slot[map->map_id]->map, (void *) map, map->size);

	extension_map_list->slot[map_id]->ref_count = 0;

	if (map_id > extension_map_list->max_used) {
		extension_map_list->max_used = map_id;
	}

	// Update next_free page slot, if it's used now
	while (extension_map_list->page[next_free] && (next_free < MAX_EXTENSION_MAPS))
		next_free++;
	extension_map_list->next_free = next_free;

	// if all slots are exhausted next_free is now MAX_EXTENSION_MAPS. The next time an empty slot is needed, it will properly fail.
	dbg_printf("Installed map in slot %d. Next free page slot: %d\n", map_id, next_free);

	//map changed
	return 1;

} // End of Insert_Extension_Map

void PackExtensionMapList(extension_map_list_t *extension_map_list) {
	int32_t i, free_slot;

	dbg_printf("Pack extensions maps\n");
	// compact extension map list - close gaps
	free_slot = -1;
	for (i = 0; i <= extension_map_list->max_used; i++) {
		dbg_printf("Check slot: %i, ref: %u\n", i, extension_map_list->slot[i] ? extension_map_list->slot[i]->ref_count : 0);
		if (extension_map_list->slot[i] != NULL && extension_map_list->slot[i]->ref_count == 0) {
			// Destroy slot, if no flows referenced this map
			free(extension_map_list->slot[i]->map);
			free(extension_map_list->slot[i]);
			extension_map_list->slot[i] = NULL;
			dbg_printf("Free slot: %i\n", i);
		}
		if (extension_map_list->slot[i] == NULL && free_slot == -1) {
			// remember this free slot
			dbg_printf("Remember free slot at %i\n", i);
			free_slot = i;
		} else if (free_slot != -1 && extension_map_list->slot[i] != NULL) {
			int j;
			// move this slot down to compact the list
			extension_map_list->slot[free_slot] = extension_map_list->slot[i];
			extension_map_list->slot[free_slot]->map->map_id = free_slot;
			extension_map_list->slot[i] = NULL;
			dbg_printf("Move slot %i down to %i\n", i, free_slot);

			// search for next free slot - latest slot[i] is free now
			for (j = free_slot + 1; j <= i; j++) {
				if (extension_map_list->slot[j] == NULL) {
					free_slot = j;
					dbg_printf("Next free slot found at %i\n", free_slot);
					break;
				}
			}
		} else {
			dbg_printf("Fell through\n");
		}
	}

	// get max index - set index to map
	i = 0;
	while (extension_map_list->slot[i] != NULL && i < MAX_EXTENSION_MAPS) {
		dbg_printf("Slot: %i, ref: %u\n", i, extension_map_list->slot[i]->ref_count);
		i++;
	}

	if (i == MAX_EXTENSION_MAPS) {
		// ups! - should not really happen - so we are done for now
		if (extension_map_list->next_free == 0) {
			// map slots full but no maps im page list - we are done
			return;
		} else {
			// we can't handle this event for now - too many maps - but MAX_EXTENSION_MAPS should be more than enough
			fprintf(stderr, "Critical error in %s line %d: %s\n", __FILE__, __LINE__, "Out of maps!");
			exit(255);
		}
	}

	// this points to the next free slot
	free_slot = i;

	for (i = 0; (uint32_t) i < extension_map_list->next_free; i++) {
		if (free_slot < MAX_EXTENSION_MAPS) {
			if (extension_map_list->page[i]->ref_count) {
				dbg_printf("Move page %u to slot %u\n", i, free_slot);
				extension_map_list->slot[free_slot] = extension_map_list->page[i];
				extension_map_list->slot[free_slot]->map->map_id = free_slot;
				extension_map_list->page[i] = NULL;
				free_slot++;
			} else {
				dbg_printf("Skip page %u. Zero ref count \n", i);
			}
		} else {
			// we can't handle this event for now, but should not happen anyway
			fprintf(stderr, "Critical error in %s line %d: %s\n", __FILE__, __LINE__, "Out of maps!");
			exit(255);
		}
	}

	extension_map_list->max_used = free_slot - 1;
	dbg_printf("Packed maps: %i\n", free_slot);

#ifdef DEVEL
	// Check maps
	i = 0;
	while ( extension_map_list->slot[i] != NULL && i < MAX_EXTENSION_MAPS ) {
		if ( extension_map_list->slot[i]->map->map_id != i )
		printf("*** Map ID missmatch in slot: %i, id: %u\n", i, extension_map_list->slot[i]->map->map_id);
		i++;
	}
#endif

} // End of PackExtensionMapList

// *** Code from nffile.c *********************************************************

#define BUFFSIZE 1048576

/* global vars */

char *CurrentIdent;

/* local vars */
static file_header_t FileHeader;
static stat_record_t NetflowStat;

#define ERR_SIZE 256
static char error_string[ERR_SIZE];

static void ZeroStat() {

	FileHeader.NumBlocks = 0;
	strncpy(FileHeader.ident, IdentNone, IdentLen);

	NetflowStat.first_seen = 0;
	NetflowStat.last_seen = 0;
	NetflowStat.msec_first = 0;
	NetflowStat.msec_last = 0;

	CurrentIdent = FileHeader.ident;

} // End of ZeroStat

int OpenFile(char *filename, stat_record_t **stat_record, char **err) {
	struct stat stat_buf;
	int fd, ret;

	*err = NULL;
	if (stat_record)
		*stat_record = &NetflowStat;

	if (filename == NULL) {
		// stdin
		ZeroStat();
		fd = STDIN_FILENO;
	} else {
		// regular file
		if (stat(filename, &stat_buf)) {
			snprintf(error_string, ERR_SIZE, "Can't stat '%s': %s\n", filename, strerror(errno));
			error_string[ERR_SIZE - 1] = 0;
			*err = error_string;
			ZeroStat();
			return -1;
		}

		if (!S_ISREG(stat_buf.st_mode)) {
			snprintf(error_string, ERR_SIZE, "'%s' is not a file\n", filename);
			error_string[ERR_SIZE - 1] = 0;
			*err = error_string;
			ZeroStat();
			return -1;
		}

		// printf("Statfile %s\n",filename);
		fd = open(filename, O_RDONLY);
		if (fd < 0) {
			snprintf(error_string, ERR_SIZE, "Error open file: %s\n", strerror(errno));
			error_string[ERR_SIZE - 1] = 0;
			*err = error_string;
			ZeroStat();
			return fd;
		}

	}

	ret = read(fd, (void *) &FileHeader, sizeof(FileHeader));
	if (FileHeader.magic != MAGIC) {
		snprintf(error_string, ERR_SIZE, "Open file '%s': bad magic: 0x%X\n", filename ? filename : "<stdin>", FileHeader.magic);
		error_string[ERR_SIZE - 1] = 0;
		*err = error_string;
		ZeroStat();
		close(fd);
		return -1;
	}
	if (FileHeader.version != LAYOUT_VERSION_1) {
		snprintf(error_string, ERR_SIZE, "Open file %s: bad version: %u\n", filename, FileHeader.version);
		error_string[ERR_SIZE - 1] = 0;
		*err = error_string;
		ZeroStat();
		close(fd);
		return -1;
	}
	int rval = read(fd, (void *) &NetflowStat, sizeof(NetflowStat));
	if (rval < 0)
		exit(-1);

// for debugging:
	/*
	 printf("Magic: 0x%X\n", FileHeader.magic);
	 printf("Version: %i\n", FileHeader.version);
	 printf("Flags: %i\n", FileHeader.flags);
	 printf("NumBlocks: %i\n", FileHeader.NumBlocks);
	 printf("Ident: %s\n\n", FileHeader.ident);

	 printf("Flows: %llu\n", NetflowStat.numflows);
	 printf("Flows_tcp: %llu\n", NetflowStat.numflows_tcp);
	 printf("Flows_udp: %llu\n", NetflowStat.numflows_udp);
	 printf("Flows_icmp: %llu\n", NetflowStat.numflows_icmp);
	 printf("Flows_other: %llu\n", NetflowStat.numflows_other);
	 printf("Packets: %llu\n", NetflowStat.numpackets);
	 printf("Packets_tcp: %llu\n", NetflowStat.numpackets_tcp);
	 printf("Packets_udp: %llu\n", NetflowStat.numpackets_udp);
	 printf("Packets_icmp: %llu\n", NetflowStat.numpackets_icmp);
	 printf("Packets_other: %llu\n", NetflowStat.numpackets_other);
	 printf("Bytes: %llu\n", NetflowStat.numbytes);
	 printf("Bytes_tcp: %llu\n", NetflowStat.numbytes_tcp);
	 printf("Bytes_udp: %llu\n", NetflowStat.numbytes_udp);
	 printf("Bytes_icmp: %llu\n", NetflowStat.numbytes_icmp);
	 printf("Bytes_other: %llu\n", NetflowStat.numbytes_other);
	 printf("First: %u\n", NetflowStat.first_seen);
	 printf("Last: %u\n", NetflowStat.last_seen);
	 printf("msec_first: %u\n", NetflowStat.msec_first);
	 printf("msec_last: %u\n", NetflowStat.msec_last);
	 */
	CurrentIdent = FileHeader.ident;

	return fd;

} // End of OpenFile

int ReadBlock(int rfd, data_block_header_t *block_header, void *read_buff, char **err) {
	ssize_t ret, read_bytes, buff_bytes, request_size;
	void *read_ptr, *buff;

	ret = read(rfd, block_header, sizeof(data_block_header_t));
	if (ret == 0) // EOF
		return NF_EOF;

	if (ret == -1) // ERROR
		return NF_ERROR;

	// block header read successfully
	read_bytes = ret;

	// Check for sane buffer size
	if (block_header->size > BUFFSIZE) {
		snprintf(error_string, ERR_SIZE, "Corrupt data file: Requested buffer size %u exceeds max. buffer size.\n", block_header->size);
		error_string[ERR_SIZE - 1] = 0;
		*err = error_string;
		// this is most likely a corrupt file
		return NF_CORRUPT;
	}

	buff = read_buff;

	ret = read(rfd, buff, block_header->size);
	if (ret == (ssize_t)block_header->size) {
		return read_bytes + ret;
	}

	if (ret == 0) {
		// EOF not expected here - this should never happen, file may be corrupt
		snprintf(error_string, ERR_SIZE, "Corrupt data file: Unexpected EOF while reading data block.\n");
		error_string[ERR_SIZE - 1] = 0;
		*err = error_string;
		return NF_CORRUPT;
	}

	if (ret == -1) // ERROR
		return NF_ERROR;

	// Ups! - ret is != block_header->size
	// this was a short read - most likely reading from the stdin pipe
	// loop until we have requested size

	buff_bytes = ret; // already in buffer
	request_size = block_header->size - buff_bytes; // still to go for this amount of data

	read_ptr = (void *) ((pointer_addr_t) buff + buff_bytes);
	do {

		ret = read(rfd, read_ptr, request_size);
		if (ret < 0)
			// -1: Error - not expected
			return NF_ERROR;

		if (ret == 0) {
			//  0: EOF   - not expected
			snprintf(error_string, ERR_SIZE, "Corrupt data file: Unexpected EOF. Short read of data block.\n");
			error_string[ERR_SIZE - 1] = 0;
			*err = error_string;
			return NF_CORRUPT;
		}

		buff_bytes += ret;
		request_size = block_header->size - buff_bytes;

		if (request_size > 0) {
			// still a short read - continue in read loop
			read_ptr = (void *) ((pointer_addr_t) buff + buff_bytes);
		}
	} while (request_size > 0);

	// finally - we are done for now
	return read_bytes + buff_bytes;

} // End of ReadBlock

// *** Code from nffile_inline.c *********************************************************

/*
 * Expand file record into master record for further processing
 * LP64 CPUs need special 32bit operations as it is not guarateed, that 64bit
 * values are aligned
 */
void ExpandRecord_v2(common_record_t *input_record, extension_info_t *extension_info, master_record_t *output_record) {
	extension_map_t *extension_map = extension_info->map;
	uint32_t i, *u;
	size_t size;
	void *p = (void *) input_record;

	// set map ref
	output_record->map_ref = extension_map;

	// Copy common data block
	size = COMMON_RECORD_DATA_SIZE;
	memcpy((void *) output_record, p, size);
	p = (void *) input_record->data;

	// Required extension 1 - IP addresses
	if ((input_record->flags & FLAG_IPV6_ADDR) != 0) { // IPv6
		// IPv6
		memcpy((void *) output_record->v6.srcaddr, p, 4 * sizeof(uint64_t));
		p = (void *) ((pointer_addr_t) p + 4 * sizeof(uint64_t));
	} else {
		// IPv4
		u = (uint32_t *) p;
		output_record->v6.srcaddr[0] = 0;
		output_record->v6.srcaddr[1] = 0;
		output_record->v4.srcaddr = u[0];

		output_record->v6.dstaddr[0] = 0;
		output_record->v6.dstaddr[1] = 0;
		output_record->v4.dstaddr = u[1];
		p = (void *) ((pointer_addr_t) p + 2 * sizeof(uint32_t));
	}

	// Required extension 2 - packet counter
	if ((input_record->flags & FLAG_PKG_64) != 0) {
		// 64bit packet counter
		value64_t l, *v = (value64_t *) p;
		l.val.val32[0] = v->val.val32[0];
		l.val.val32[1] = v->val.val32[1];
		output_record->dPkts = l.val.val64;
		p = (void *) ((pointer_addr_t) p + sizeof(uint64_t));
	} else {
		// 32bit packet counter
		output_record->dPkts = *((uint32_t *) p);
		p = (void *) ((pointer_addr_t) p + sizeof(uint32_t));
	}

	// Required extension 3 - byte counter
	if ((input_record->flags & FLAG_BYTES_64) != 0) {
		// 64bit byte counter
		value64_t l, *v = (value64_t *) p;
		l.val.val32[0] = v->val.val32[0];
		l.val.val32[1] = v->val.val32[1];
		output_record->dOctets = l.val.val64;
		p = (void *) ((pointer_addr_t) p + sizeof(uint64_t));
	} else {
		// 32bit bytes counter
		output_record->dOctets = *((uint32_t *) p);
		p = (void *) ((pointer_addr_t) p + sizeof(uint32_t));
	}

	// preset one single flow
	output_record->aggr_flows = 1;

	// Process optional extensions
	i = 0;
	while (extension_map->ex_id[i]) {
		switch (extension_map->ex_id[i++]) {
		// 0 - 3 should never be in an extension table so - ignore it
		case 0:
		case 1:
		case 2:
		case 3:
			break;
		case EX_IO_SNMP_2: {
			tpl_ext_4_t *tpl = (tpl_ext_4_t *) p;
			output_record->input = tpl->input;
			output_record->output = tpl->output;
			p = (void *) tpl->data;
		}
			break;
		case EX_IO_SNMP_4: {
			tpl_ext_5_t *tpl = (tpl_ext_5_t *) p;
			output_record->input = tpl->input;
			output_record->output = tpl->output;
			p = (void *) tpl->data;
		}
			break;
		case EX_AS_2: {
			tpl_ext_6_t *tpl = (tpl_ext_6_t *) p;
			output_record->srcas = tpl->src_as;
			output_record->dstas = tpl->dst_as;
			p = (void *) tpl->data;
		}
			break;
		case EX_AS_4: {
			tpl_ext_7_t *tpl = (tpl_ext_7_t *) p;
			output_record->srcas = tpl->src_as;
			output_record->dstas = tpl->dst_as;
			p = (void *) tpl->data;
		}
			break;
		case EX_MULIPLE: {
			tpl_ext_8_t *tpl = (tpl_ext_8_t *) p;
			// use a 32 bit int to copy all 4 fields
			output_record->any = tpl->any;
			p = (void *) tpl->data;
		}
			break;
		case EX_NEXT_HOP_v4: {
			tpl_ext_9_t *tpl = (tpl_ext_9_t *) p;
			output_record->ip_nexthop.v6[0] = 0;
			output_record->ip_nexthop.v6[1] = 0;
			output_record->ip_nexthop.v4 = tpl->nexthop;
			p = (void *) tpl->data;
			ClearFlag(output_record->flags, FLAG_IPV6_NH);
		}
			break;
		case EX_NEXT_HOP_v6: {
			tpl_ext_10_t *tpl = (tpl_ext_10_t *) p;
			output_record->ip_nexthop.v6[0] = tpl->nexthop[0];
			output_record->ip_nexthop.v6[1] = tpl->nexthop[1];
			p = (void *) tpl->data;
			SetFlag(output_record->flags, FLAG_IPV6_NH);
		}
			break;
		case EX_NEXT_HOP_BGP_v4: {
			tpl_ext_11_t *tpl = (tpl_ext_11_t *) p;
			output_record->bgp_nexthop.v6[0] = 0;
			output_record->bgp_nexthop.v6[1] = 0;
			output_record->bgp_nexthop.v4 = tpl->bgp_nexthop;
			ClearFlag(output_record->flags, FLAG_IPV6_NHB);
			p = (void *) tpl->data;
		}
			break;
		case EX_NEXT_HOP_BGP_v6: {
			tpl_ext_12_t *tpl = (tpl_ext_12_t *) p;
			output_record->bgp_nexthop.v6[0] = tpl->bgp_nexthop[0];
			output_record->bgp_nexthop.v6[1] = tpl->bgp_nexthop[1];
			p = (void *) tpl->data;
			SetFlag(output_record->flags, FLAG_IPV6_NHB);
		}
			break;
		case EX_VLAN: {
			tpl_ext_13_t *tpl = (tpl_ext_13_t *) p;
			output_record->src_vlan = tpl->src_vlan;
			output_record->dst_vlan = tpl->dst_vlan;
			p = (void *) tpl->data;
		}
			break;
		case EX_OUT_PKG_4: {
			tpl_ext_14_t *tpl = (tpl_ext_14_t *) p;
			output_record->out_pkts = tpl->out_pkts;
			p = (void *) tpl->data;
		}
			break;
		case EX_OUT_PKG_8: {
			tpl_ext_15_t v, *tpl = (tpl_ext_15_t *) p;
			v.v[0] = tpl->v[0];
			v.v[1] = tpl->v[1];
			output_record->out_pkts = v.out_pkts;
			p = (void *) tpl->data;
		}
			break;
		case EX_OUT_BYTES_4: {
			tpl_ext_16_t *tpl = (tpl_ext_16_t *) p;
			output_record->out_bytes = tpl->out_bytes;
			p = (void *) tpl->data;
		}
			break;
		case EX_OUT_BYTES_8: {
			tpl_ext_17_t v, *tpl = (tpl_ext_17_t *) p;
			v.v[0] = tpl->v[0];
			v.v[1] = tpl->v[1];
			output_record->out_bytes = v.out_bytes;
			p = (void *) tpl->data;
		}
			break;
		case EX_AGGR_FLOWS_4: {
			tpl_ext_18_t *tpl = (tpl_ext_18_t *) p;
			output_record->aggr_flows = tpl->aggr_flows;
			p = (void *) tpl->data;
		}
			break;
		case EX_AGGR_FLOWS_8: {
			tpl_ext_19_t v, *tpl = (tpl_ext_19_t *) p;
			v.v[0] = tpl->v[0];
			v.v[1] = tpl->v[1];
			output_record->aggr_flows = v.aggr_flows;
			p = (void *) tpl->data;
		}
			break;
		case EX_MAC_1: {
			tpl_ext_20_t v, *tpl = (tpl_ext_20_t *) p;
			v.v1[0] = tpl->v1[0];
			v.v1[1] = tpl->v1[1];
			output_record->in_src_mac = v.in_src_mac;

			v.v2[0] = tpl->v2[0];
			v.v2[1] = tpl->v2[1];
			output_record->out_dst_mac = v.out_dst_mac;
			p = (void *) tpl->data;
		}
			break;
		case EX_MAC_2: {
			tpl_ext_21_t v, *tpl = (tpl_ext_21_t *) p;
			v.v1[0] = tpl->v1[0];
			v.v1[1] = tpl->v1[1];
			output_record->in_dst_mac = v.in_dst_mac;
			v.v2[0] = tpl->v2[0];
			v.v2[1] = tpl->v2[1];
			output_record->out_src_mac = v.out_src_mac;
			p = (void *) tpl->data;
		}
			break;
		case EX_MPLS: {
			tpl_ext_22_t *tpl = (tpl_ext_22_t *) p;
			int j;
			for (j = 0; j < 10; j++) {
				output_record->mpls_label[j] = tpl->mpls_label[j];
			}
			p = (void *) tpl->data;
		}
			break;
		case EX_ROUTER_IP_v4: {
			tpl_ext_23_t *tpl = (tpl_ext_23_t *) p;
			output_record->ip_router.v6[0] = 0;
			output_record->ip_router.v6[1] = 0;
			output_record->ip_router.v4 = tpl->router_ip;
			p = (void *) tpl->data;
			ClearFlag(output_record->flags, FLAG_IPV6_EXP);
		}
			break;
		case EX_ROUTER_IP_v6: {
			tpl_ext_24_t *tpl = (tpl_ext_24_t *) p;
			output_record->ip_router.v6[0] = tpl->router_ip[0];
			output_record->ip_router.v6[1] = tpl->router_ip[1];
			p = (void *) tpl->data;
			SetFlag(output_record->flags, FLAG_IPV6_EXP);
		}
			break;
		case EX_ROUTER_ID: {
			tpl_ext_25_t *tpl = (tpl_ext_25_t *) p;
			output_record->engine_type = tpl->engine_type;
			output_record->engine_id = tpl->engine_id;
			p = (void *) tpl->data;
		}
			break;
		}
	}
} // End of ExpandRecord_v2

// *** Code from nfdump_inline.c *********************************************************

void UpdateStat(stat_record_t *stat_record, master_record_t *master_record) {

	switch (master_record->prot) {
	case IPPROTO_ICMP:
	case IPPROTO_ICMPV6:
		stat_record->numflows_icmp++;
		stat_record->numpackets_icmp += master_record->dPkts;
		stat_record->numbytes_icmp += master_record->dOctets;
		break;
	case IPPROTO_TCP:
		stat_record->numflows_tcp++;
		stat_record->numpackets_tcp += master_record->dPkts;
		stat_record->numbytes_tcp += master_record->dOctets;
		break;
	case IPPROTO_UDP:
		stat_record->numflows_udp++;
		stat_record->numpackets_udp += master_record->dPkts;
		stat_record->numbytes_udp += master_record->dOctets;
		break;
	default:
		stat_record->numflows_other++;
		stat_record->numpackets_other += master_record->dPkts;
		stat_record->numbytes_other += master_record->dOctets;
	}
	stat_record->numflows++;
	stat_record->numpackets += master_record->dPkts;
	stat_record->numbytes += master_record->dOctets;

	if (master_record->first < stat_record->first_seen) {
		stat_record->first_seen = master_record->first;
		stat_record->msec_first = master_record->msec_first;
	}
	if (master_record->first == stat_record->first_seen && master_record->msec_first < stat_record->msec_first)
		stat_record->msec_first = master_record->msec_first;

	if (master_record->last > stat_record->last_seen) {
		stat_record->last_seen = master_record->last;
		stat_record->msec_last = master_record->msec_last;
	}
	if (master_record->last == stat_record->last_seen && master_record->msec_last > stat_record->msec_last)
		stat_record->msec_last = master_record->msec_last;

} // End of UpdateStat

// *** Code from nfreader.c *********************************************************

void print_record(void *record, char *s) {
	char as[INET6_ADDRSTRLEN], ds[INET6_ADDRSTRLEN], datestr1[64], datestr2[64];
	time_t when;
	struct tm *ts;
	master_record_t *r = (master_record_t *) record;

	if ((r->flags & FLAG_IPV6_ADDR) != 0) { // IPv6
		r->v6.srcaddr[0] = htonll(r->v6.srcaddr[0]);
		r->v6.srcaddr[1] = htonll(r->v6.srcaddr[1]);
		r->v6.dstaddr[0] = htonll(r->v6.dstaddr[0]);
		r->v6.dstaddr[1] = htonll(r->v6.dstaddr[1]);
		inet_ntop(AF_INET6, r->v6.srcaddr, as, sizeof(as));
		inet_ntop(AF_INET6, r->v6.dstaddr, ds, sizeof(ds));
	} else { // IPv4
		r->v4.srcaddr = htonl(r->v4.srcaddr);
		r->v4.dstaddr = htonl(r->v4.dstaddr);
		inet_ntop(AF_INET, &r->v4.srcaddr, as, sizeof(as));
		inet_ntop(AF_INET, &r->v4.dstaddr, ds, sizeof(ds));
	}
	as[40 - 1] = 0;
	ds[40 - 1] = 0;

	when = r->first;
	ts = localtime(&when);
	strftime(datestr1, 63, "%Y-%m-%d %H:%M:%S", ts);

	when = r->last;
	ts = localtime(&when);
	strftime(datestr2, 63, "%Y-%m-%d %H:%M:%S", ts);

	snprintf(s, 1023, "\n"
			"Flow Record: \n"
			"  srcaddr     = %16s\n"
			"  dstaddr     = %16s\n"
			"  first       =       %10u [%s]\n"
			"  last        =       %10u [%s]\n"
			"  msec_first  =            %5u\n"
			"  msec_last   =            %5u\n"
			"  prot        =              %3u\n"
			"  srcport     =            %5u\n"
			"  dstport     =            %5u\n"
			"  dPkts       =       %10llu\n"
			"  dOctets     =       %10llu\n", as, ds, r->first, datestr1, r->last, datestr2, r->msec_first, r->msec_last, r->prot, r->srcport, r->dstport,
	      (unsigned long long) r->dPkts, (unsigned long long) r->dOctets);

	s[1024 - 1] = 0;

} // End of print_record

