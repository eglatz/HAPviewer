/**
 *	\file gfilter_ipfix_vx5ipfix_bi.cpp
 *
 *	\brief Example IPFIX file reader and writer code based on a template
 *	supporting uniflows and biflows on IPv4.
 *
 *	Author: Brian Trammell
 *	Changes (delta counters removed, biflow support added): Eduard Glatz
 */
#include "gfilter_ipfix_vx5ipfix_bi.h"

#pragma GCC diagnostic ignored "-Wwrite-strings"
static fbInfoElementSpec_t vx5_flow_spec[] = {
		{ "flowStartMilliseconds", 0, 0 },
		{ "flowEndMilliseconds", 0, 0 },
		{ "packetTotalCount", 0, 0 },
		{"octetTotalCount", 0, 0 },
		{ "reversePacketTotalCount", 0, 0 },
		{ "reverseOctetTotalCount", 0, 0 },
		{ "sourceIPv4Address", 0, 0 },
		{"destinationIPv4Address", 0, 0 },
		{ "sourceIPv6Address", 0, 0 },
		{ "destinationIPv6Address", 0, 0 },
		{ "sourceTransportPort", 0, 0 },
		{ "destinationTransportPort", 0, 0 },
		{ "ipNextHopIPv4Address", 0, 0 },
		{"ipNextHopIPv6Address", 0, 0 },
		{ "ingressInterface", 0, 0 },
		{ "egressInterface", 0, 0 },
		{ "ipVersion", 0, 0 },
		/* Protocol; sensor information */
		{ "protocolIdentifier", 0, 0 },
		{ "nextHeaderIPv6", 0, 0 },
		/* Flags */
		{ "tcpControlBits", 0, 0 },
		FB_IESPEC_NULL
};

static fbInfoElementSpec_t vx5_int_flow_spec[] = {
/* pad record to 64-bit boundary */
{ "paddingOctets", 4, 0 }, FB_IESPEC_NULL };
#pragma GCC diagnostic warning "-Wwrite-strings"

static fbInfoModel_t *vx5InfoModel() {
	static fbInfoModel_t *model = NULL;

	if (model)
		return model;

	model = fbInfoModelAlloc();
	return model;
}

static fbSession_t *vx5Session(int isWriter, GError **err) {
	fbInfoModel_t *model = vx5InfoModel();
	fbTemplate_t *itmpl = NULL, *xtmpl = NULL;
	fbSession_t *session = NULL;

	/* Allocate the session */
	session = fbSessionAlloc(model);

	/* FIXME this is not, technically speaking, legal */
	fbSessionSetDomain(session, 0);

	/* Create internal template */
	itmpl = fbTemplateAlloc(model);
	if (!fbTemplateAppendSpecArray(itmpl, vx5_flow_spec, 0, err)) {
		return NULL;
	}
	if (!fbTemplateAppendSpecArray(itmpl, vx5_int_flow_spec, 0, err)) {
		return NULL;
	}
	if (!fbSessionAddTemplate(session, TRUE, VX5_TID, itmpl, err)) {
		return NULL;
	}

	/* Create external template for writer */
	if (isWriter) {
		xtmpl = fbTemplateAlloc(model);
		if (!fbTemplateAppendSpecArray(xtmpl, vx5_flow_spec, 0, err)) {
			return NULL;
		}
		if (!fbSessionAddTemplate(session, FALSE, VX5_TID, xtmpl, err)) {
			return NULL;
		}
	}

	/* Done. Return the session. */
	return session;
}

fBuf_t *vx5ReaderForFP(FILE *fp, GError **err) {
	fbSession_t *session = NULL;
	fBuf_t *fbuf = NULL;
	fbCollector_t *collector = NULL;

	/* Get a session */
	if (!(session = vx5Session(0, err)))
		goto err;

	/* Allocate a collector for the file */
	collector = fbCollectorAllocFP(NULL, fp);

	/* Allocate a buffer */
	fbuf = fBufAllocForCollection(session, collector);

	/* Set the internal template */
	if (!fBufSetInternalTemplate(fbuf, VX5_TID, err))
		goto err;

	/* all done */
	return fbuf;

	err:
	/* free buffer if necessary */
	if (fbuf)
		fBufFree(fbuf);
	return NULL;
}

fBuf_t *vx5WriterForFP(FILE *fp, GError **err) {
	fbSession_t *session = NULL;
	fBuf_t *fbuf = NULL;
	fbExporter_t *exporter = NULL;

	/* Get a session */
	if (!(session = vx5Session(1, err)))
		goto err;

	/* Allocate a collector for the file */
	exporter = fbExporterAllocFP(fp);

	/* Allocate a buffer */
	fbuf = fBufAllocForExport(session, exporter);

	/* Set the internal template */
	if (!fBufSetInternalTemplate(fbuf, VX5_TID, err))
		goto err;

	/* Set the export template */
	if (!fBufSetExportTemplate(fbuf, VX5_TID, err))
		goto err;
	/* Write templates to output stream */

	/* and export them */
	if (!fbSessionExportTemplates(session, err)) {
		goto err;
	}

	/* all done */
	return fbuf;

	err:
	/* free buffer if necessary */
	if (fbuf)
		fBufFree(fbuf);
	return NULL;
}
