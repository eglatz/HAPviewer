/**
 *	\file	glistview_hpg.cpp
 *	\brief List view containing graphlet (hpg) meta data.
 *
 *	This type of list view is used whenever when pre-processed graphlet data is imported. 
 *	Shown metedata is graph-oriented by providing e.g. count of edges.
 *	An alternate form of list view (see listview1.cpp/h) is used when graphlets are directly 
 *	derived from packet or flow data.
 */

#include "HAPviewer.h"
#include "gview.h"
#include "gmodel.h"
#include "ghpgdata.h"
#include "glistview_hpg.h"

#include <gtkmm/stock.h>
#include <iostream>
#include <stdlib.h>
#include <libgen.h>

const bool dbg = false;

using namespace std;

/**
 * Constructor: default constructor
 */
ChpgListView::ChpgListView() :
	m_Button_Clear("Clear"), m_Button_ShowSelection("Show"), m_Button_previous(Gtk::Stock::GO_BACK), m_Button_next(Gtk::Stock::GO_FORWARD),
	      m_Button_first(Gtk::Stock::GOTO_FIRST), m_Button_last(Gtk::Stock::GOTO_LAST) {
	initialized = false;
}

/**
 * Constructor
 */
ChpgListView::~ChpgListView() {

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
void ChpgListView::initialize(ChpgModelColumns * model, Glib::RefPtr<Gtk::ListStore> m_refTreeModel) {
	pmodel = model;
	hpgData = NULL;
	this->m_refTreeModel = m_refTreeModel;

	if (initialized) {

		// View is alreayd constructed: just update list
		reinitialize(model, m_refTreeModel);

	} else {

		// Add the TreeView, inside a ScrolledWindow, with the button underneath
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

		m_ButtonBox.set_border_width(5);
		m_ButtonBox.set_layout(Gtk::BUTTONBOX_START);
		m_Button_Clear.signal_clicked().connect(sigc::mem_fun(*this, &ChpgListView::on_button_clear));
		m_Button_ShowSelection.signal_clicked().connect(sigc::mem_fun(*this, &ChpgListView::on_button_showselection));
		// Navigation
		m_Button_first.signal_clicked().connect(sigc::mem_fun(*this, &ChpgListView::on_button_first));
		m_Button_previous.signal_clicked().connect(sigc::mem_fun(*this, &ChpgListView::on_button_previous));
		m_Button_next.signal_clicked().connect(sigc::mem_fun(*this, &ChpgListView::on_button_next));
		m_Button_last.signal_clicked().connect(sigc::mem_fun(*this, &ChpgListView::on_button_last));

		// Link model to view
		m_TreeView.set_model(m_refTreeModel);

		// Select model columns to display
		m_TreeView.append_column("graphlet", pmodel->m_col_graphlet);
		m_TreeView.append_column("edges", pmodel->m_col_edges);
		m_TreeView.append_column("protocols", pmodel->m_col_protos);
		m_TreeView.append_column("remoteIPs", pmodel->m_col_dstIPs);
		m_TreeView.append_column("localPorts", pmodel->m_col_srcPorts);
		m_TreeView.append_column("remotePorts", pmodel->m_col_dstPorts);
		m_TreeView.append_column("totalBytes", pmodel->m_col_bytes);
#define	NUM_COL	7

		// Make columns sortable by clicking on column header
		Gtk::TreeView::Column* pColumn = m_TreeView.get_column(0);
		if (pColumn) {
			pColumn->set_sort_column(pmodel->m_col_graphlet);
			pColumn->set_sort_indicator(true);
		}
		pColumn = m_TreeView.get_column(1);
		if (pColumn) {
			pColumn->set_sort_column(pmodel->m_col_edges);
			pColumn->set_sort_indicator(true);
		}

		pColumn = m_TreeView.get_column(2);
		if (pColumn) {
			pColumn->set_sort_column(pmodel->m_col_protos);
			pColumn->set_sort_indicator(true);
		}

		pColumn = m_TreeView.get_column(3);
		if (pColumn) {
			pColumn->set_sort_column(pmodel->m_col_dstIPs);
			pColumn->set_sort_indicator(true);
		}

		pColumn = m_TreeView.get_column(4);
		if (pColumn) {
			pColumn->set_sort_column(pmodel->m_col_srcPorts);
			pColumn->set_sort_indicator(true);
		}

		pColumn = m_TreeView.get_column(5);
		if (pColumn) {
			pColumn->set_sort_column(pmodel->m_col_dstPorts);
			pColumn->set_sort_indicator(true);
		}

		pColumn = m_TreeView.get_column(6);
		if (pColumn) {
			pColumn->set_sort_column(pmodel->m_col_bytes);
			pColumn->set_sort_indicator(true);
		}

		if (dbg) {
			cout << "View successfully constructed.\n";
		}
		initialized = true;
	}
}

/**
 *	Re-initialize list view.
 *	To be used to associate list view with new data in case it already exists.
 *
 *
 *	\param model Data to display
 *	\param m_refTreeModel Model of data
 */
void ChpgListView::reinitialize(ChpgModelColumns * model, Glib::RefPtr<Gtk::ListStore> m_refTreeModel) {
	this->m_refTreeModel = m_refTreeModel;
	pmodel = model;
	// Remove old model and link new model to view
	m_TreeView.unset_model();
	m_TreeView.set_model(m_refTreeModel);
}

/**
 *	Assosciate new data with list view.
 *
 *	\param data Imported data
 */
void ChpgListView::set_data(ChpgData * data) {
	hpgData = data;
}

/**
 *	Clear list view: undo association of list view with data, and clear view.
 */
void ChpgListView::on_button_clear() {
	hide();
	signal_list_cleared();
}

/**
 *	Go to first line of list view and display its graphlet.
 */
void ChpgListView::on_button_first() {
	const Gtk::TreeNodeChildren & list = m_refTreeModel->children();
	Gtk::ListStore::iterator iter = list.begin();

	Glib::RefPtr<Gtk::TreeSelection> refTreeSelection = m_TreeView.get_selection();
	refTreeSelection->select(iter);

	Gtk::ListStore::Row row = *iter;
	int graphlet_nr = row[pmodel->m_col_graphlet];
	int edges = row[pmodel->m_col_edges];
	if (dbg) {
		cout << "First row has graphlet # = " << graphlet_nr << endl;
	}

	Gtk::TreeModel::Path path = m_refTreeModel->get_path(iter);
	m_TreeView.scroll_to_row(path);

	show_graphlet_from_list(graphlet_nr, edges);
}

/**
 *	Go to previous line of list view and display its graphlet.	
 *	No action is taken if current line is first line of list.	
 */
void ChpgListView::on_button_previous() {
	Glib::RefPtr<Gtk::TreeSelection> refTreeSelection = m_TreeView.get_selection();
	Gtk::ListStore::iterator iter = refTreeSelection->get_selected();

	const Gtk::TreeNodeChildren & list = m_refTreeModel->children();
	Gtk::ListStore::iterator iter0 = list.begin();

	if (iter && iter != iter0) { // If anything is selected and we are not at first row
		iter--;
		int graphlet_nr = 0, edges = 0;
		if (iter) { // If still valid
			refTreeSelection->select(iter);
			Gtk::ListStore::Row row = *iter;
			graphlet_nr = row[pmodel->m_col_graphlet];
			edges = row[pmodel->m_col_edges];
			if (dbg) {
				cout << "Next selected row has graphlet # = " << graphlet_nr << endl;
			}
		} else {
			if (dbg) {
				cout << "No backward action: already at end of list.\n";
			}
			return;
		}

		Gtk::TreeModel::Path path = m_refTreeModel->get_path(iter);
		m_TreeView.scroll_to_row(path);

		show_graphlet_from_list(graphlet_nr, edges);

	} else {
		cout << "No row is selected or desired row does not exist.\n";
	}

}

/**
 *	Go to next line of list view and display its graphlet.
 *	No action is taken if current line is last line of list.
 */
void ChpgListView::on_button_next() {
	Glib::RefPtr<Gtk::TreeSelection> refTreeSelection = m_TreeView.get_selection();
	Gtk::ListStore::iterator iter = refTreeSelection->get_selected();
	if (iter) { // If anything is selected
		iter++;
		int graphlet_nr = 0, edges = 0;
		if (iter) { // If still valid
			refTreeSelection->select(iter);
			Gtk::ListStore::Row row = *iter;
			graphlet_nr = row[pmodel->m_col_graphlet];
			edges = row[pmodel->m_col_edges];
			if (dbg) {
				cout << "Next selected row has graphlet # = " << graphlet_nr << endl;
			}
		} else {
			if (dbg) {
				cout << "No forward action: already at end of list.\n";
			}
			return;
		}

		Gtk::TreeModel::Path path = m_refTreeModel->get_path(iter);
		m_TreeView.scroll_to_row(path);

		show_graphlet_from_list(graphlet_nr, edges);

	} else {
		cout << "No row is selected.\n";
	}
}

/**
 *	Go to last line of list view and display its graphlet.	
 */
void ChpgListView::on_button_last() {
	const Gtk::TreeNodeChildren & list = m_refTreeModel->children();
	Gtk::ListStore::iterator iter = list.end();
	iter--;

	Glib::RefPtr<Gtk::TreeSelection> refTreeSelection = m_TreeView.get_selection();
	refTreeSelection->select(iter);

	Gtk::ListStore::Row row = *iter;
	int graphlet_nr = row[pmodel->m_col_graphlet];
	int edges = row[pmodel->m_col_edges];
	if (dbg) {
		cout << "Last row has graphlet # = " << graphlet_nr << endl;
	}

	Gtk::TreeModel::Path path = m_refTreeModel->get_path(iter);
	m_TreeView.scroll_to_row(path);

	show_graphlet_from_list(graphlet_nr, edges);
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
void ChpgListView::on_button_goto_graphlet(int graphlet) {
	if (dbg)
		cout << "INFO: goto graphlet " << graphlet << endl;

	const Gtk::TreeNodeChildren & list = m_refTreeModel->children();
	Gtk::ListStore::iterator iter = list.begin();

	for (iter = list.begin(); iter != list.end(); iter++) {
		Gtk::ListStore::Row row = *iter;
		if (row[pmodel->m_col_graphlet] == (unsigned int) graphlet)
			break; // Hit
	}

	if (iter == list.end()) { // Requested graphlet is behind list end: got list end
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

	Gtk::ListStore::Row row = *iter;
	int graphlet_nr = row[pmodel->m_col_graphlet];
	int edges = row[pmodel->m_col_edges];
	if (dbg) {
		cout << "Selected row has graphlet # = " << graphlet_nr << endl;
	}

	Gtk::TreeModel::Path path = m_refTreeModel->get_path(iter);
	m_TreeView.scroll_to_row(path);

	show_graphlet_from_list(graphlet_nr, edges);
}

/**
 *	Display graphlet of currently selected line of list view.
 */
void ChpgListView::on_button_showselection() {
	Glib::RefPtr<Gtk::TreeSelection> refTreeSelection = m_TreeView.get_selection();
	Gtk::ListStore::iterator iter = refTreeSelection->get_selected();
	if (iter) { // If anything is selected
		Gtk::ListStore::Row row = *iter;
		int graphlet_nr = row[pmodel->m_col_graphlet];
		int edges = row[pmodel->m_col_edges];
		if (dbg) {
			cout << "Selected row has graphlet # = " << graphlet_nr << endl;
		}

		show_graphlet_from_list(graphlet_nr, edges);

	} else {
		cout << "No row is selected.\n";
	}
}

/**
 *	Display graphlet with given number and count of edges.
 *
 *	\param graphlet_nr Number of graphlet to display
 *	\param edges Count of egdes of graphlet (used to warn user before very large graphlets)
 *
 *	\exception std::string Errormessage
 */
void ChpgListView::show_graphlet_from_list(int graphlet_nr, int edges) {
	// 1. Get index for this graphlet_nr
	int index = 0;
	if (hpgData == NULL) {
		string errtext = "data not set in listview.\n";
		cerr << "ERROR: " << errtext;
		throw errtext;
	} else {
		index = hpgData->get_index(graphlet_nr);
		if (dbg) {
			cout << "Index into data[] for " << graphlet_nr << " is: " << index << endl;
		}
	}

	// 2. Transform associated graphlet data into dot format
	string filename = default_dot_filename;
	;
	try {
		hpgData->hpg2dot(index, filename);
		if (dbg) {
			cout << "HPG data transformed into DOT format and saved in " << filename << ".\n";
		}
	} catch (string & errtext) {
		// Propagate exception as signal
		signal_error(errtext);
	}

	// 3. Transform dot format into gif format and display gif file
	char s[20];
	sprintf(s, "graphlet# %d", graphlet_nr);
	title = s;

	if (edges > VIEW_EDGE_INITIAL_THRESHOLD) { // Check if we have a very large graphlet
		// Yes: user must confirm display
		signal_large_graphics_to_display(filename, title, edges, false);
	} else {
		// No: display graphics
		signal_graphics_to_display(filename, title, false); // Callback to transform/display function
	}
}

