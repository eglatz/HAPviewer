/**
 *	\file	glistview_cflow.cpp
 *	\brief List view containing per host meta data.
 *
 *	This type of list view is used whenever graphlets are directly derived from packet or flow data.
 *	An alternate form of list view (see listview_hpg.cpp/h) is used when pre-processed graphlet data
 *	is imported.
 */

#include <arpa/inet.h>
#include <sys/types.h>
#include <fcntl.h>
#include <ctime>

#include "ghpgdata.h"
#include "HAPviewer.h"
#include "gview.h"
#include "glistview_cflow.h"
#include "gmodel.h"
#include "gutil.h"
#include "cflow.h"

#include <gtkmm/stock.h>
#include <iostream>
#include <stdlib.h>
#include <libgen.h>

const bool dbg = false;
const bool debug = false;

using namespace std;

/**
 *	Default constructor
 */
CflowModelColumns::CflowModelColumns() {
	add( m_col_flownum), add(m_col_protocol), add(m_col_IP1);
	add(m_col_port1);
	add(m_col_direction);
	add(m_col_IP2);
	add(m_col_port2);
	add(m_col_bytes);
	add(m_col_packets);
	add(m_col_start);
	add(m_col_duration);
}

/**
 *	Add a flow to the rolelist
 *
 *	\param m_refTreeModel List to append a new row
 *	\param flownum	number of this flow
 *	\param uint8_t Protocol number
 *	\param remoteIP Local IP
 *	\param remoteIP Local Port
 *	\param flowtype Flowtype
 *	\param remoteIP Remote IP
 *	\param remotePort Remote Port
 *	\param bytes Number of bytes
 *	\param packets Number of packets
 *	\param startMs Flow start time in milliseconds since the epoch
 *	\param durationMs Flow duration in milliseconds
 */
void CflowModelColumns::add_row(Glib::RefPtr<Gtk::ListStore> m_refTreeModel, unsigned int flownum, uint8_t protocol, IPv6_addr localIP, uint16_t localPort,
      uint8_t flowtype, IPv6_addr remoteIP, uint16_t remotePort, uint64_t bytes, int packets, uint64_t startMs, uint32_t durationMs) {
	Gtk::TreeModel::Row row = *(m_refTreeModel->append());
	row[m_col_flownum] = flownum;
	row[m_col_protocol] = util::ipV6ProtocolToString(protocol);
	row[m_col_IP1] = localIP.toString();
	row[m_col_port1] = localPort;
	switch (flowtype) {
		case biflow:
			row[m_col_direction] = "<==>";
			break;
		case inflow:
			row[m_col_direction] = "<---";
			break;
		case outflow:
			row[m_col_direction] = "--->";
			break;
		case (inflow | unibiflow):
			row[m_col_direction] = "<--*";
			break;
		case (outflow | unibiflow):
			row[m_col_direction] = "*-->";
			break;
		default:
			std::cerr << "ERROR: encountered invalid flow type: " << (int) flowtype << std::endl;
			break;
	}
	row[m_col_IP2] = remoteIP.toString();
	row[m_col_port2] = remotePort;
	row[m_col_bytes] = bytes;
	row[m_col_packets] = packets;

	// Start time
	time_t tt = (time_t) (startMs / 1000);
	struct tm ts;
	localtime_r(&tt, &ts);

	std::stringstream buf;
	buf << std::setw(2) << std::setfill('0') << ts.tm_hour << ":" << std::setw(2) << std::setfill('0') << ts.tm_min << ":" << std::setw(2) << std::setfill('0')
	      << ts.tm_sec << "." << std::setw(3) << std::setfill('0') << (startMs % 1000);
	row[m_col_start] = buf.str();

	buf.str("");
	buf << (durationMs / 1000) << "." << std::setprecision(3) << std::setw(3) << std::setfill('0') << (durationMs % 1000) << "s";
	row[m_col_duration] = buf.str();
}

/**
 *	Default constructor
 */
CflowlistWindow::CflowlistWindow() :
	m_Button_Hide("Hide") {
	set_title("Flowlist");
	set_border_width(5);
	// Initial text window size in pixels (can be changed by user later on)
	set_default_size(900, 300);

	add(m_VBox);

	// Only show the scrollbars when they are necessary:
	m_ScrolledWindow.set_policy(Gtk::POLICY_AUTOMATIC, Gtk::POLICY_AUTOMATIC);

	m_VBox.pack_start(m_ScrolledWindow);

	// Add buttons
	m_VBox.pack_start(m_ButtonBox, Gtk::PACK_SHRINK);

	m_ButtonBox.pack_start(m_Button_Hide, Gtk::PACK_SHRINK);
	m_ButtonBox.set_border_width(5);
	m_ButtonBox.set_spacing(5);
	m_ButtonBox.set_layout(Gtk::BUTTONBOX_END);

	// Connect signals
	m_Button_Hide.signal_clicked().connect(sigc::mem_fun(*this, &CflowlistWindow::on_button_hide));

	flowModel = new CflowModelColumns();
	m_refFlowTreeModel = Gtk::ListStore::create(*flowModel);

	// Add the TreeView, inside a ScrolledWindow, with the buttons underneath
	m_ScrolledWindow.add(m_TreeView);

	// Link model to view
	m_TreeView.set_model(m_refFlowTreeModel);

	m_TreeView.modify_font(Pango::FontDescription("courier, 13"));

	// Select model columns to display
	m_TreeView.append_column("flow", flowModel->m_col_flownum);
	m_TreeView.append_column("proto", flowModel->m_col_protocol);
	m_TreeView.append_column("localIP", flowModel->m_col_IP1); // col 2
	m_TreeView.append_column("locPort", flowModel->m_col_port1);
	m_TreeView.append_column("direction", flowModel->m_col_direction); // col4
	m_TreeView.append_column("remoteIP", flowModel->m_col_IP2); // col 5
	m_TreeView.append_column("remPort", flowModel->m_col_port2);
	m_TreeView.append_column("bytes", flowModel->m_col_bytes);
	m_TreeView.append_column("packets", flowModel->m_col_packets);
	m_TreeView.append_column("flowstart", flowModel->m_col_start); // col 9
	m_TreeView.append_column("duration", flowModel->m_col_duration);

	// Install compare function for sorting of IP dotted string addresses
	m_refFlowTreeModel->set_sort_func(1, sigc::mem_fun(*this, &CflowlistWindow::on_sort_compareProtocol));
	m_refFlowTreeModel->set_sort_func(2, sigc::mem_fun(*this, &CflowlistWindow::on_sort_compareLocalIP));
	m_refFlowTreeModel->set_sort_func(4, sigc::mem_fun(*this, &CflowlistWindow::on_sort_compareDirection));
	m_refFlowTreeModel->set_sort_func(5, sigc::mem_fun(*this, &CflowlistWindow::on_sort_compareRemoteIP));
	m_refFlowTreeModel->set_sort_func(9, sigc::mem_fun(*this, &CflowlistWindow::on_sort_compare_startTime));
	m_refFlowTreeModel->set_sort_func(10, sigc::mem_fun(*this, &CflowlistWindow::on_sort_compare_duration));

	// Make columns sortable by clicking on column header
	Gtk::TreeView::Column* pColumn = m_TreeView.get_column(0);
	if (pColumn) {
		pColumn->set_sort_column(flowModel->m_col_flownum);
		pColumn->set_sort_indicator(true);
	}

	pColumn = m_TreeView.get_column(1);
	if (pColumn) {
		pColumn->set_sort_column(flowModel->m_col_protocol);
		pColumn->set_sort_indicator(true);
	}

	pColumn = m_TreeView.get_column(2);
	if (pColumn) {
		pColumn->set_sort_column(flowModel->m_col_IP1);
		pColumn->set_sort_indicator(true);
	}

	pColumn = m_TreeView.get_column(3);
	if (pColumn) {
		pColumn->set_sort_column(flowModel->m_col_port1);
		pColumn->set_sort_indicator(true);
	}

	pColumn = m_TreeView.get_column(4);
	if (pColumn) {
		pColumn->set_sort_column(flowModel->m_col_direction);
		pColumn->set_sort_indicator(true);
	}

	pColumn = m_TreeView.get_column(5);
	if (pColumn) {
		pColumn->set_sort_column(flowModel->m_col_IP2);
		pColumn->set_sort_indicator(true);
	}

	pColumn = m_TreeView.get_column(6);
	if (pColumn) {
		pColumn->set_sort_column(flowModel->m_col_port2);
		pColumn->set_sort_indicator(true);
	}

	pColumn = m_TreeView.get_column(7);
	if (pColumn) {
		pColumn->set_sort_column(flowModel->m_col_bytes);
		pColumn->set_sort_indicator(true);
	}

	pColumn = m_TreeView.get_column(8);
	if (pColumn) {
		pColumn->set_sort_column(flowModel->m_col_packets);
		pColumn->set_sort_indicator(true);
	}

	pColumn = m_TreeView.get_column(9);
	if (pColumn) {
		pColumn->set_sort_column(flowModel->m_col_start);
		pColumn->set_sort_indicator(true);
	}


	pColumn = m_TreeView.get_column(10);
	if (pColumn) {
		pColumn->set_sort_column(flowModel->m_col_duration);
		pColumn->set_sort_indicator(true);
	}


	flow_num = -1;
	hidden = true;
	initialized = false;
}

/**
 *	Hide window
 */
void CflowlistWindow::hide() {
	hidden = true;
	Gtk::Widget::hide();
}

/**
 *	Unhide window
 */
void CflowlistWindow::unhide() {
	hidden = false;
	show_all_children();
	show();
}

/**
 *	Fill list with subitted flowlist, set graphlet# in title to graphlet_nr
 *
 *	\param subflowlist Flowlist to show in list
 *	\param graphlet_nr Number of the graphlet this flows belong to
 */
void CflowlistWindow::fill_flowlist(Subflowlist subflowlist, int graphlet_nr) {
	if (m_refFlowTreeModel) {
		m_refFlowTreeModel.reset();
		delete flowModel;
		flowModel = new CflowModelColumns();
		m_refFlowTreeModel = Gtk::ListStore::create(*flowModel);
		// Install compare function for sorting of IPv4 dotted string addresses
		m_refFlowTreeModel->set_sort_func(1, sigc::mem_fun(*this, &CflowlistWindow::on_sort_compareProtocol));
		m_refFlowTreeModel->set_sort_func(2, sigc::mem_fun(*this, &CflowlistWindow::on_sort_compareLocalIP));
		m_refFlowTreeModel->set_sort_func(4, sigc::mem_fun(*this, &CflowlistWindow::on_sort_compareDirection));
		m_refFlowTreeModel->set_sort_func(5, sigc::mem_fun(*this, &CflowlistWindow::on_sort_compareRemoteIP));
		m_refFlowTreeModel->set_sort_func(9, sigc::mem_fun(*this, &CflowlistWindow::on_sort_compare_startTime));
		m_refFlowTreeModel->set_sort_func(10, sigc::mem_fun(*this, &CflowlistWindow::on_sort_compare_duration));

		m_TreeView.unset_model();
		m_TreeView.set_model(m_refFlowTreeModel);
	}

	flow_num = 1;

	string title("Flowlist graphlet #");
	stringstream ss;
	ss << graphlet_nr;
	title += ss.str();
	title += " (";
	stringstream ss2;
	ss2 << subflowlist.size();
	title += ss2.str();
	title += " flows)";
	set_title(title);

	for (unsigned int i = 0; i < subflowlist.size(); i++) {
		flowModel->add_row(m_refFlowTreeModel, flow_num, subflowlist[i].prot, subflowlist[i].localIP, subflowlist[i].localPort, subflowlist[i].flowtype,
		      subflowlist[i].remoteIP, subflowlist[i].remotePort, subflowlist[i].dOctets, subflowlist[i].dPkts, subflowlist[i].startMs, subflowlist[i].durationMs);
		flow_num++;
	}
	initialized = true;
}

void CflowlistWindow::fill_flowlist(const CFlowList & flowlist, int graphlet_nr) {
	Subflowlist subflowlist(flowlist.begin(), flowlist.end());
	fill_flowlist(subflowlist, graphlet_nr);
}

void CflowlistWindow::on_button_hide() {
	CflowlistWindow::hide();
	hidden = true;
}


/**
 *	Clear flow list contents and set a re-load for next graphlet.
 */
void CflowlistWindow::reset() {
	initialized = false;
	cout << "INFO: reset flowTreeModel\n";
	if (m_refFlowTreeModel) {
		m_refFlowTreeModel.reset();
		delete flowModel;
		flowModel = new CflowModelColumns();
		m_refFlowTreeModel = Gtk::ListStore::create(*flowModel);
		// Install compare function for sorting of IP dotted string addresses
		m_refFlowTreeModel->set_sort_func(1, sigc::mem_fun(*this, &CflowlistWindow::on_sort_compareProtocol));
		m_refFlowTreeModel->set_sort_func(2, sigc::mem_fun(*this, &CflowlistWindow::on_sort_compareLocalIP));
		m_refFlowTreeModel->set_sort_func(4, sigc::mem_fun(*this, &CflowlistWindow::on_sort_compareDirection));
		m_refFlowTreeModel->set_sort_func(5, sigc::mem_fun(*this, &CflowlistWindow::on_sort_compareRemoteIP));
		m_refFlowTreeModel->set_sort_func(9, sigc::mem_fun(*this, &CflowlistWindow::on_sort_compare_startTime));
		m_refFlowTreeModel->set_sort_func(10, sigc::mem_fun(*this, &CflowlistWindow::on_sort_compare_duration));

		m_TreeView.unset_model();
		m_TreeView.set_model(m_refFlowTreeModel);
		CflowlistWindow::hide();
	}
}



/**
 *	Compare IP addresses in dotted string form (IP addresses are taken from selected lines of list).
 *	This function is required to make IP address column of list view sortable.
 *
 *	\param	a_	Iterator for row a
 *	\param	b_	Iterator for row b
 *
 *	\return	Returns -1 if a compares before b, 0 if they compare equal, 1 if a compares after b. 
 */
int CflowlistWindow::on_sort_compareLocalIP(const Gtk::TreeModel::iterator& a_, const Gtk::TreeModel::iterator& b_) {
	const Gtk::TreeModel::Row row_a = *a_;
	const Gtk::TreeModel::Row row_b = *b_;

	try {
		IPv6_addr localIPa(row_a[flowModel->m_col_IP1]);
		IPv6_addr localIPb(row_b[flowModel->m_col_IP1]);
		if (localIPa < localIPb)
			return -1;
		else if (localIPa > localIPb)
			return 1;
	} catch (string & e) {
		cerr << e << endl;
	}
	return 0;
}

/**
 *	Compare IP addresses in dotted string form (IP addresses are taken from selected lines of list).
 *	This function is required to make IP address column of list view sortable.
 *
 *	\param	a_	Iterator for row a
 *	\param	b_	Iterator for row b
 *
 *	\return	Returns -1 if a compares before b, 0 if they compare equal, 1 if a compares after b.
 */
int CflowlistWindow::on_sort_compareRemoteIP(const Gtk::TreeModel::iterator& a_, const Gtk::TreeModel::iterator& b_) {
	const Gtk::TreeModel::Row row_a = *a_;
	const Gtk::TreeModel::Row row_b = *b_;

	try {
		IPv6_addr remoteIPa(row_a[flowModel->m_col_IP2]);
		IPv6_addr remoteIPb(row_b[flowModel->m_col_IP2]);
		if (remoteIPa < remoteIPb)
			return -1;
		else if (remoteIPa > remoteIPb)
			return 1;
	} catch (string & e) {
		cerr << e << endl;
	}
	return 0;
}

/**
 *	Compare protocol string
 *	This function is required to make the protocol column of list view sortable.
 *
 *	\param	a_	Iterator for row a
 *	\param	b_	Iterator for row b
 *
 *	\return	Returns -1 if a compares before b, 0 if they compare equal, 1 if a compares after b.
 */
int CflowlistWindow::on_sort_compareProtocol(const Gtk::TreeModel::iterator& a_, const Gtk::TreeModel::iterator& b_) {
	const Gtk::TreeModel::Row row_a = *a_;
	const Gtk::TreeModel::Row row_b = *b_;

	string protoA = row_a[flowModel->m_col_protocol];
	string protoB = row_b[flowModel->m_col_protocol];

	return protoA.compare(protoB);
}


/**
 *	Compare direction of flows
 *	This function is required to make the direction column of list view sortable.
 *
 *	\param	a_	Iterator for row a
 *	\param	b_	Iterator for row b
 *
 *	\return	Returns -1 if a compares before b, 0 if they compare equal, 1 if a compares after b.
 */
int CflowlistWindow::on_sort_compareDirection(const Gtk::TreeModel::iterator& a_, const Gtk::TreeModel::iterator& b_) {
	const Gtk::TreeModel::Row row_a = *a_;
	const Gtk::TreeModel::Row row_b = *b_;

	string directionA = row_a[flowModel->m_col_direction];
	string directionB = row_b[flowModel->m_col_direction];

	return directionA.compare(directionB);
}

/**
 *	Compare start times in string form.
 *	This function is required to make startTime column of list view sortable.
 *
 *	\param	a_	Iterator for row a
 *	\param	b_	Iterator for row b
 *
 *	\return	Returns -1 if a compares before b, 0 if they compare equal, 1 if a compares after b.
 */
int CflowlistWindow::on_sort_compare_startTime(const Gtk::TreeModel::iterator& a_, const Gtk::TreeModel::iterator& b_) {
	const Gtk::TreeModel::Row row_a = *a_;
	const Gtk::TreeModel::Row row_b = *b_;

	string start_a = row_a[flowModel->m_col_start];
	string start_b = row_b[flowModel->m_col_start];

	static struct tm tm_a, tm_b;
	static time_t ta, tb;

	string a = start_a.substr(0, start_a.size() - 4);
	if (strptime(a.c_str(), "%H:%M:%S", &tm_a) == NULL) {
		cerr << "\nERROR in strptime(): invalid date/time string = " << a << "\n\n";
		exit(1);
	}
	tm_a.tm_isdst = -1; /* Not set by strptime(); tells mktime()
	 to determine whether daylight saving time
	 is in effect */
	ta = mktime(&tm_a);
	if (ta == -1) {
		printf("\nERROR: mktime() failed.!\n\n");
		exit(1);
	}

	string b = start_b.substr(0, start_b.size() - 4);
	if (strptime(b.c_str(), "%H:%M:%S", &tm_b) == NULL) {
		cerr << "\nERROR in strptime(): invalid date/time string = " << b << "\n\n";
		exit(1);
	}
	tm_b.tm_isdst = -1; /* Not set by strptime(); tells mktime()
	 to determine whether daylight saving time
	 is in effect */
	tb = mktime(&tm_b);
	if (tb == -1) {
		printf("\nERROR: mktime() failed.!\n\n");
		exit(1);
	}

	// Add unix secons and ms
	stringstream ssa;
	ssa << start_a.substr(start_a.size() - 3);
	unsigned int ms_a;
	ssa >> ms_a;
	unsigned long uta = 1000 * (unsigned int) ta + ms_a;

	stringstream ssb;
	ssb << start_b.substr(start_b.size() - 3);
	unsigned int ms_b;
	ssb >> ms_b;
	unsigned long utb = 1000 * (unsigned int) tb + ms_b;

	if (uta > utb)
		return 1;
	else
		return -1;
}


/**
 *	Compare duration times in string form.
 *	This function is required to make duration column of list view sortable.
 *
 *	\param	a_	Iterator for row a
 *	\param	b_	Iterator for row b
 *
 *	\return	Returns -1 if a compares before b, 0 if they compare equal, 1 if a compares after b.
 */
int CflowlistWindow::on_sort_compare_duration(const Gtk::TreeModel::iterator& a_, const Gtk::TreeModel::iterator& b_) {
	double a = 0.0;
	double b = 0.0;

	const Gtk::TreeModel::Row row_a = *a_;
	const Gtk::TreeModel::Row row_b = *b_;

	stringstream ss_a(row_a[flowModel->m_col_duration]);
	stringstream ss_b(row_b[flowModel->m_col_duration]);
	ss_a >> a;
	ss_b >> b;
	if(a < b)
		return -1;
	if(a > b)
		return 1;
	return 0;
}
//*** ChostListView ***************************************************************

/**
 *	Default constructor
 */
ChostListView::ChostListView() :
	last_cimport(NULL), m_Button_Clear("Clear"), m_Button_ShowSelection("Show"), m_Button_previous(Gtk::Stock::GO_BACK), m_Button_next(Gtk::Stock::GO_FORWARD),
	      m_Button_first(Gtk::Stock::GOTO_FIRST), m_Button_last(Gtk::Stock::GOTO_LAST), m_Button_flowlist("Flowlist") {
	initialized = false;
}

/**
 *	Gets the remote flow list
 *
 *	\return CFlowList Remote flow list
 */
const CFlowList & ChostListView::get_rflows() {
	return rflows;
}

/**
 *	Create and show list view as a tree view for metadata list.
 *
 *	Create tree view, associate it with scroll bars and create button row at the bottom of list.
 *	Then link data model to view and make columns sortable.
 *
 *	\param model Data to display
 *	\param m_refTreeModel Model of data
 */
void ChostListView::initialize(ChostModelColumns * model, Glib::RefPtr<Gtk::ListStore> m_refTreeModel, const prefs_t & newprefs) {
	pmodel = model;
	hostData = NULL;
	this->m_refTreeModel = m_refTreeModel;
	prefs = newprefs;
	if (initialized) {
		// View is already constructed: just update list contents
		reinitialize(model, m_refTreeModel);
	} else {

		// Add the TreeView, inside a ScrolledWindow, with the buttons underneath
		m_ScrolledWindow.add(m_TreeView);
		// Only show the scrollbars when they are necessary
		m_ScrolledWindow.set_policy(Gtk::POLICY_AUTOMATIC, Gtk::POLICY_AUTOMATIC);

		pack_start(m_ScrolledWindow);
		pack_start(m_ButtonBox, Gtk::PACK_SHRINK);

		m_ButtonBox.pack_start(m_Button_first, Gtk::PACK_SHRINK);
		m_ButtonBox.pack_start(m_Button_previous, Gtk::PACK_SHRINK);
		m_ButtonBox.pack_start(m_Button_next, Gtk::PACK_SHRINK);
		m_ButtonBox.pack_start(m_Button_last, Gtk::PACK_SHRINK);
		m_ButtonBox.pack_start(m_Button_ShowSelection, Gtk::PACK_SHRINK);
		m_ButtonBox.pack_start(m_Button_Clear, Gtk::PACK_SHRINK);
		m_ButtonBox.pack_start(m_Button_flowlist, Gtk::PACK_SHRINK);

		m_ButtonBox.set_border_width(5);
		m_ButtonBox.set_layout(Gtk::BUTTONBOX_START);
		m_Button_Clear.signal_clicked().connect(sigc::mem_fun(*this, &ChostListView::on_button_clear));
		m_Button_ShowSelection.signal_clicked().connect(sigc::mem_fun(*this, &ChostListView::on_button_showselection));
		// Navigation
		m_Button_first.signal_clicked().connect(sigc::mem_fun(*this, &ChostListView::on_button_first));
		m_Button_previous.signal_clicked().connect(sigc::mem_fun(*this, &ChostListView::on_button_previous));
		m_Button_next.signal_clicked().connect(sigc::mem_fun(*this, &ChostListView::on_button_next));
		m_Button_last.signal_clicked().connect(sigc::mem_fun(*this, &ChostListView::on_button_last));
		m_Button_flowlist.signal_clicked().connect(sigc::mem_fun(*this, &ChostListView::on_button_flowlist));

		// Link model to view
		m_TreeView.set_model(m_refTreeModel);

		// Select model columns to display
		m_TreeView.append_column("IP", pmodel->m_col_IP);
		m_TreeView.append_column("graphlet", pmodel->m_col_graphlet);
		m_TreeView.append_column("flows", pmodel->m_col_flows);
		m_TreeView.append_column("uniflows", pmodel->m_col_uniflows);
		m_TreeView.append_column("protocols", pmodel->m_col_protos);
		m_TreeView.append_column("packets", pmodel->m_col_packets);
		m_TreeView.append_column("totalBytes", pmodel->m_col_bytes);

		// Install compare function for sorting of IP string addresses
		m_refTreeModel->set_sort_func(0, sigc::mem_fun(*this, &ChostListView::on_sort_compareIP));

		// Make columns sortable by clicking on column header
		Gtk::TreeView::Column* pColumn = m_TreeView.get_column(0);
		if (pColumn) {
			pColumn->set_sort_column(pmodel->m_col_IP);
			pColumn->set_sort_indicator(true);
		}

		pColumn = m_TreeView.get_column(1);
		if (pColumn) {
			pColumn->set_sort_column(pmodel->m_col_graphlet);
			pColumn->set_sort_indicator(true);
		}

		pColumn = m_TreeView.get_column(2);
		if (pColumn) {
			pColumn->set_sort_column(pmodel->m_col_flows);
			pColumn->set_sort_indicator(true);
		}

		pColumn = m_TreeView.get_column(3);
		if (pColumn) {
			pColumn->set_sort_column(pmodel->m_col_uniflows);
			pColumn->set_sort_indicator(true);
		}

		pColumn = m_TreeView.get_column(4);
		if (pColumn) {
			pColumn->set_sort_column(pmodel->m_col_protos);
			pColumn->set_sort_indicator(true);
		}

		pColumn = m_TreeView.get_column(5);
		if (pColumn) {
			pColumn->set_sort_column(pmodel->m_col_packets);
			pColumn->set_sort_indicator(true);
		}

		pColumn = m_TreeView.get_column(6);
		if (pColumn) {
			pColumn->set_sort_column(pmodel->m_col_bytes);
			pColumn->set_sort_indicator(true);
		}

		if (dbg)
			cout << "View successfully constructed.\n";

		rflows.clear();
		initialized = true;
	}
}

/**
 *	Re-initialize list view.
 *	To be used to associate list view with new data in case list view already exists and new data arrived.
 *
 *	\param model Data to display
 *	\param m_refTreeModel Model of data
 */
void ChostListView::reinitialize(ChostModelColumns * model, Glib::RefPtr<Gtk::ListStore> m_refTreeModel) {
	this->m_refTreeModel = m_refTreeModel;
	pmodel = model;
	rflows.clear();

	// Remove old model and link new model to view
	m_TreeView.unset_model();
	m_TreeView.set_model(m_refTreeModel);
	flowlist_view.reset();
}

/**
 *	Associate new data with list view.
 *
 *	\param data Imported data
 */
void ChostListView::set_data(CImport * data) {
	hostData = data;
}

/**
 *	Select first row of list so that it can be immediately displayed.
 */
void ChostListView::select_first_row() {
	const Gtk::TreeNodeChildren & list = m_refTreeModel->children();
	Gtk::ListStore::iterator iter = list.begin();

	Glib::RefPtr<Gtk::TreeSelection> refTreeSelection = m_TreeView.get_selection();
	refTreeSelection->select(iter);

	Gtk::ListStore::Row row = *iter;

	Gtk::TreeModel::Path path = m_refTreeModel->get_path(iter);
	m_TreeView.scroll_to_row(path);
}

/**
 *	Compare IP addresses in dotted string form (IP addresses are taken from selected lines of list).
 *	This function is required to make IP address column of list view sortable.
 *
 *	\param	a_	Iterator for row a
 *	\param	b_	Iterator for row b
 *
 *	\return	Returns -1 if a compares before b, 0 if they compare equal, 1 if a compares after b. 
 */
int ChostListView::on_sort_compareIP(const Gtk::TreeModel::iterator& a_, const Gtk::TreeModel::iterator& b_) {
	const Gtk::TreeModel::Row row_a = *a_;
	const Gtk::TreeModel::Row row_b = *b_;

	try {
		IPv6_addr IPa(row_a[pmodel->m_col_IP]);
		IPv6_addr IPb(row_b[pmodel->m_col_IP]);
		if (IPa < IPb)
			return -1;
		else if (IPa > IPb)
			return 1;
	} catch (string & e) {
		cerr << e << endl;
	}
	return 0;
}

/**
 *	Clear list view: undo association of list view with data, and clear view.
 */
void ChostListView::on_button_clear() {
	hide();
	flowlist_view.hide();
	signal_list_cleared();
}

/**
 *	Go to first line of list view and display its graphlet.
 */
void ChostListView::on_button_first() {
	const Gtk::TreeNodeChildren & list = m_refTreeModel->children();
	Gtk::ListStore::iterator iter = list.begin();

	Glib::RefPtr<Gtk::TreeSelection> refTreeSelection = m_TreeView.get_selection();
	refTreeSelection->select(iter);

	Gtk::ListStore::Row row = *iter;

	// get ptr to affected flowlist entry
	int flIndex = row[pmodel->m_col_flIdx];
	int flow_count = row[pmodel->m_col_flows];
	if (dbg) {
		cout << "First row has flowlist index = " << flIndex << " and comprises " << flow_count << " flows.\n";
	}

	Gtk::TreeModel::Path path = m_refTreeModel->get_path(iter);
	m_TreeView.scroll_to_row(path);

	hostData->setBegin(flIndex);
	hostData->setEnd(flIndex + flow_count);

	flowlist_view.fill_flowlist(hostData->getActiveFlowlist(), row[pmodel->m_col_graphlet]);
	show_graphlet_from_list(*hostData, row[pmodel->m_col_graphlet], false);
}

/**
 *	Go to previous line of list view and display its graphlet.	
 *	No action is taken if current line is first line of list.	
 */
void ChostListView::on_button_previous() {
	Glib::RefPtr<Gtk::TreeSelection> refTreeSelection = m_TreeView.get_selection();
	Gtk::ListStore::iterator iter = refTreeSelection->get_selected();

	const Gtk::TreeNodeChildren & list = m_refTreeModel->children();
	Gtk::ListStore::iterator iter0 = list.begin();

	if (iter && iter != iter0) { // If anything is selected and we are not at first row
		iter--;
		int flIndex = 0, flow_count = 0, graphlet_nr = 0;
		if (iter) { // If still valid
			refTreeSelection->select(iter);
			Gtk::ListStore::Row row = *iter;
			// get ptr to affected flowlist entry
			flIndex = row[pmodel->m_col_flIdx];
			flow_count = row[pmodel->m_col_flows];
			graphlet_nr = row[pmodel->m_col_graphlet];
			if (dbg) {
				cout << "Previous row has flowlist index = " << flIndex << " and comprises " << flow_count << " flows.\n";
			}
		} else {
			if (dbg) {
				cout << "No backward action: already at end of list.\n";
			}
			return;
		}

		Gtk::TreeModel::Path path = m_refTreeModel->get_path(iter);
		m_TreeView.scroll_to_row(path);

		hostData->setBegin(flIndex);
		hostData->setEnd(flIndex + flow_count);

		flowlist_view.fill_flowlist(hostData->getActiveFlowlist(), graphlet_nr);
		show_graphlet_from_list(*hostData, graphlet_nr, false);

	} else {
		cout << "No row is selected or desired row does not exist.\n";
	}

}

/**
 *	Go to next line of list view and display its graphlet.
 *	No action is taken if current line is last line of list.
 */
void ChostListView::on_button_next() {
	Glib::RefPtr<Gtk::TreeSelection> refTreeSelection = m_TreeView.get_selection();
	Gtk::ListStore::iterator iter = refTreeSelection->get_selected();
	if (iter) { // If anything is selected
		iter++;
		int flIndex = 0, flow_count = 0, graphlet_nr = 0;
		if (iter) { // If still valid
			refTreeSelection->select(iter);
			Gtk::ListStore::Row row = *iter;
			// get ptr to affected flowlist entry
			flIndex = row[pmodel->m_col_flIdx];
			flow_count = row[pmodel->m_col_flows];
			graphlet_nr = row[pmodel->m_col_graphlet];
			if (dbg) {
				cout << "Next row has flowlist index = " << flIndex << " and comprises " << flow_count << " flows.\n";
			}
		} else {
			if (dbg) {
				cout << "No forward action: already at end of list.\n";
			}
			return;
		}

		Gtk::TreeModel::Path path = m_refTreeModel->get_path(iter);
		m_TreeView.scroll_to_row(path);

		hostData->setBegin(flIndex);
		hostData->setEnd(flIndex + flow_count);

		flowlist_view.fill_flowlist(hostData->getActiveFlowlist(), graphlet_nr);
		show_graphlet_from_list(*hostData, graphlet_nr, false);

	} else {
		cout << "No row is selected.\n";
	}
}

/**
 *	Go to last line of list view and display its graphlet.	
 */
void ChostListView::on_button_last() {
	const Gtk::TreeNodeChildren & list = m_refTreeModel->children();
	Gtk::ListStore::iterator iter = list.end();
	iter--;

	Glib::RefPtr<Gtk::TreeSelection> refTreeSelection = m_TreeView.get_selection();
	refTreeSelection->select(iter);

	Gtk::ListStore::Row row = *iter;

	// get ptr to affected flowlist entry
	int flIndex = row[pmodel->m_col_flIdx];
	int flow_count = row[pmodel->m_col_flows];
	if (dbg) {
		cout << "Last row has flowlist index = " << flIndex << " and comprises " << flow_count << " flows.\n";
	}

	Gtk::TreeModel::Path path = m_refTreeModel->get_path(iter);
	m_TreeView.scroll_to_row(path);

	flowlist_view.fill_flowlist(hostData->getActiveFlowlist(), row[pmodel->m_col_graphlet]);
	show_graphlet_from_list(*hostData, row[pmodel->m_col_graphlet], false);
}

/**
 *	Go to line of list view which contains given graphlet number and display its graphlet.
 *
 *	The model of the list view is searched for given graphlet number. When found then the
 *	group of flows assolciated with this graphlet is located in the flowlist. Finally,
 *	this flow group is displayed.
 *
 *	\param graphlet Graphlet number
 */
void ChostListView::on_button_goto_graphlet(int graphlet) {
	if (dbg)
		cout << "INFO: goto graphlet " << graphlet << endl;

	// We have to search the whole list for given graphlet number
	const Gtk::TreeNodeChildren & list = m_refTreeModel->children();
	Gtk::ListStore::iterator iter = list.begin();

	for (iter = list.begin(); iter != list.end(); iter++) {
		Gtk::ListStore::Row row = *iter;
		if (row[pmodel->m_col_graphlet] == (unsigned int) graphlet)
			break; // Hit
	}

	if (iter == list.end()) { // Miss
		if (dbg)
			cout << "Requested graphlet not found: no action.\n";
		return;
	}

	if (!iter) {
		cerr << "ERROR: goto graphlet " << graphlet << " failed.\n";
		return;
	}

	Glib::RefPtr<Gtk::TreeSelection> refTreeSelection = m_TreeView.get_selection();
	refTreeSelection->select(iter);

	// Get ptr to affected flowlist entry
	Gtk::ListStore::Row row = *iter;
	int flIndex = row[pmodel->m_col_flIdx];
	int flow_count = row[pmodel->m_col_flows];
	if (dbg)
		cout << "Chosen row has flowlist index = " << flIndex << " and comprises " << flow_count << " flows.\n";

	Gtk::TreeModel::Path path = m_refTreeModel->get_path(iter);
	m_TreeView.scroll_to_row(path);

	flowlist_view.fill_flowlist(hostData->getActiveFlowlist(), row[pmodel->m_col_graphlet]);
	show_graphlet_from_list(*hostData, row[pmodel->m_col_graphlet], false);

}

/**
 *	Display graphlet of currently selected line of list view.
 */
void ChostListView::on_button_showselection() {
	Glib::RefPtr<Gtk::TreeSelection> refTreeSelection = m_TreeView.get_selection();
	Gtk::ListStore::iterator iter = refTreeSelection->get_selected();
	if (iter) { // If anything is selected
		Gtk::ListStore::Row row = *iter;
		// get ptr to affected flowlist entry
		int flIndex = row[pmodel->m_col_flIdx];
		int flow_count = row[pmodel->m_col_flows];
		int graphlet_nr = row[pmodel->m_col_graphlet];
		if (dbg)
			cout << "Last row has flowlist index = " << flIndex << " and comprises " << flow_count << " flows.\n";

		hostData->setBegin(flIndex);
		hostData->setEnd(flIndex + flow_count);

		flowlist_view.fill_flowlist(hostData->getActiveFlowlist(), row[pmodel->m_col_graphlet]);
		show_graphlet_from_list(*hostData, graphlet_nr, false);
	} else {
		cout << "No row is selected.\n";
	}
}

/**
 *	Show window conatining list of flows associated with currently selected graphlet.
 */
void ChostListView::on_button_flowlist() {
	cout << "Button flowlist clicked.\n";

	Glib::RefPtr<Gtk::TreeSelection> refTreeSelection = m_TreeView.get_selection();
	Gtk::ListStore::iterator iter = refTreeSelection->get_selected();
	if (iter) { // If anything is selected
		Gtk::ListStore::Row row = *iter;
		// get ptr to affected flowlist entry
		int flIndex = row[pmodel->m_col_flIdx];
		int flow_count = row[pmodel->m_col_flows];
		if (dbg) {
			cout << "Current row has flowlist index = " << flIndex << " and comprises " << flow_count << " flows.\n";
		}

		flowlist_view.unhide();
		flowlist_view.fill_flowlist(hostData->get_flow(flIndex, flow_count), row[pmodel->m_col_graphlet]);

	} else {
		cout << "No row is selected.\n";
	}
}

/**
 *	Write flowlist associated with currently selected row to a binary file.
 *
 *	\param filename	Name of output file that will take gzipped binary flow data (in cflow_t-format)
 */
void ChostListView::write_cflows(string & filename) {
	Glib::RefPtr<Gtk::TreeSelection> refTreeSelection = m_TreeView.get_selection();
	Gtk::ListStore::iterator iter = refTreeSelection->get_selected();
	if (iter) { // If anything is selected
		Gtk::ListStore::Row row = *iter;
		// get ptr to affected flowlist entry
		int flIndex = row[pmodel->m_col_flIdx];
		int flow_count = row[pmodel->m_col_flows];
		if (dbg) {
			cout << "Current row has flowlist index = " << flIndex << " and comprises " << flow_count << " flows.\n";
		}

		if(CImport::acceptForExport(filename)) {
			hostData->write_file(filename, hostData->get_flow(flIndex, flow_count), true);
		}
	} else {
		cout << "No row is selected.\n";
	}
}

/**
 *	Search list for a given IP address. The search covers local and remote IP addresses.
 *	Supports an extra dialog that asks user for IP address of desired graphlet.
 *
 *	\param sIP IPv6_addr representation of IP address
 */
void ChostListView::on_button_goto_IP(IPv6_addr remote_IP) {
	cout << "Search IP address is: " << remote_IP << endl;
	const Gtk::TreeNodeChildren & list = m_refTreeModel->children();
	Gtk::ListStore::iterator iter = list.begin();

	// Search for localIP first
	for (iter = list.begin(); iter != list.end(); iter++) {
		Gtk::ListStore::Row row = *iter;
		string s = row[pmodel->m_col_IP];
		if (IPv6_addr(s) == remote_IP)
			break; // Hit
	}

	if (iter == list.end()) { // When not found then look up remote IP's
		// We have to use the flowlist as remoteIPs are not contained in metadata
		rflows.clear();
		rflows = hostData->get_outside_graphlet_flows(remote_IP);
		if (rflows.size() > 0) {
			CImport tmpImp(rflows, prefs);
			show_graphlet_from_list(tmpImp, -1, true);
			return;
		}

	} else {
		// Searched IP is local
		if (iter == list.end()) { // Requested graphlet is behind list end (encountered list end)
			if (dbg)
				cout << "Requested IP address not found: no action.\n";
			return;
		}

		if (!iter) {
			cerr << "ERROR: goto line " << remote_IP << " failed.\n";
			return;
		}

		Glib::RefPtr<Gtk::TreeSelection> refTreeSelection = m_TreeView.get_selection();
		refTreeSelection->select(iter);

		Gtk::ListStore::Row row = *iter;
		// get ptr to affected flowlist entry
		int flIndex = row[pmodel->m_col_flIdx];
		int flow_count = row[pmodel->m_col_flows];
		if (dbg)
			cout << "Chosen row has flowlist index = " << flIndex << " and comprises " << flow_count << " flows.\n";

		Gtk::TreeModel::Path path = m_refTreeModel->get_path(iter);
		m_TreeView.scroll_to_row(path);

		flowlist_view.fill_flowlist(hostData->getActiveFlowlist(), row[pmodel->m_col_graphlet]);
		show_graphlet_from_list(*hostData, row[pmodel->m_col_graphlet], false);
	}
}

/**
 *	Display graphlet derived from a group of flows given.
 *	Enables graphlet visualization from flow data.
 *
 *	\param flowlist List of flows associated with requested graphlet/host
 *	\param graphlet_nr Number of graphlet (will be displayed in graphlet window title bar) 
 *	\param release_flows Set true if flowlist shall be freed after use
 *	\param remote_view TRUE when a second window shall be used for a remote IP
 */
void ChostListView::show_graphlet_from_list(CImport & cimport, int graphlet_nr, bool remote_view, bool deleteFilters) {
	if (!remote_view) {
		last_cimport = &cimport;
		last_graphlet_nr = graphlet_nr;
		last_remove_view = remote_view;
	}

	if (deleteFilters)
		cimport.clear_desummarized_roles();

	// 0. Create a hpg temp file from flowlist of one particular host
	try {
		cimport.cflow2hpg();
	} catch (string & e) {
		signal_failure(e);
		return;
	}

	// 1. Create hpgTempData from temporary hpg data file
	// (hpg data for this host starts right at the beginning of the file)
	ChpgData hpgTempData(cimport.get_hpg_filename());
	try {
		hpgTempData.read_hpg_file();
	} catch (string & e) {
		signal_failure(e);
		return;
	}

	// 2. Transform associated graphlet data into dot format
	string filename = default_dot_filename;
	try {
		hpgTempData.hpg2dot(0, filename);
		if (dbg) {
			cout << "HPG data transformed into DOT format and saved in " << filename << ".\n\n";
		}
	} catch (string & errtext) {
		string errtext = "No flows to display for this host.\n";
		cerr << errtext;
		signal_failure(errtext);
		return;
	}

	// 3. Transform dot format into gif format and display gif file
	char s[20];
	sprintf(s, "graphlet# %d", graphlet_nr);
	title = s;

	// Check if we have a very large graphlet
	int edges = hpgTempData.get_edges();
	if (edges > VIEW_EDGE_INITIAL_THRESHOLD) {
		// Yes: user must confirm display
		signal_large_graphics_to_display(filename, title, edges, remote_view);
	} else {
		// No: display graphics
		signal_graphics_to_display(filename, title, remote_view);
	}
}

/**
 *	Display graphlet derived from a group of flows given.
 *	Enables graphlet visualization from flow data.
 *	Uses the same values as the latest call to (CImport, int, bool, bool)
 *
 *	\pre last_cimport has to be != NULL
 */
void ChostListView::show_graphlet_from_list() {
	assert(last_cimport != NULL);
	show_graphlet_from_list(*last_cimport, last_graphlet_nr, last_remove_view, false);
}

/**
 *	Clear the flowlist table.
 */
void ChostListView::clear_flowlist() {
	flowlist_view.reset();
}

