#ifndef GLISTVIEW_CFLOW_H
#define GLISTVIEW_CFLOW_H

/**
 *	\file glistview_cflow.h
 *	\brief List view containing per host meta data.
 *
 *	This type of list view is used whenever graphlets are directly derived from packet or flow data.
 *	An alternate form of list view (see listview_hpg.cpp/h) is used when pre-processed graphlet data
 *	is imported.
 */

#include <gtkmm.h>
#include <ctime>
#include <sys/socket.h>
#include <sstream>
#include <iomanip>
#include <string>

#include "gmodel.h"
#include "gview.h"
#include "gimport.h"
#include "gutil.h"
#include "cflow.h"

// ******************************************************************************************

/**
 *	\class CflowModelColumns
 *	\brief Model containing flow data.
 */
class CflowModelColumns: public Gtk::TreeModel::ColumnRecord {
	public:
		CflowModelColumns();

		void add_row(Glib::RefPtr<Gtk::ListStore> m_refTreeModel, unsigned int flownum, uint8_t protocol, IPv6_addr IP1, uint16_t port1, uint8_t flowtype,
		      IPv6_addr IP2, uint16_t port2, uint64_t bytes, int packets, uint64_t startMs, uint32_t durationMs);

		// Define names and types of columns
		Gtk::TreeModelColumn<unsigned int> m_col_flownum;
		Gtk::TreeModelColumn<std::string> m_col_protocol;
		Gtk::TreeModelColumn<std::string> m_col_IP1;
		Gtk::TreeModelColumn<unsigned int> m_col_port1;
		Gtk::TreeModelColumn<std::string> m_col_direction;
		Gtk::TreeModelColumn<std::string> m_col_IP2;
		Gtk::TreeModelColumn<unsigned int> m_col_port2;
		Gtk::TreeModelColumn<uint64_t> m_col_bytes;
		Gtk::TreeModelColumn<unsigned int> m_col_packets;
		Gtk::TreeModelColumn<std::string> m_col_start;
		Gtk::TreeModelColumn<std::string> m_col_duration;
};

//*** CflowlistWindow ***************************************************************

class CflowlistWindow: public Gtk::Window {
	public:
		CflowlistWindow();

		void hide();
		void unhide();
		void fill_flowlist(Subflowlist subflowlist, int graphlet_nr);
		void fill_flowlist(const CFlowList & flowlist, int graphlet_nr);
		//void write_cflows(std::string & filename, Subflowlist subflowlist);
		void reset();

	protected:
		// Signal handlers:
		void on_button_hide();
		virtual int on_sort_compareProtocol(const Gtk::TreeModel::iterator& a_, const Gtk::TreeModel::iterator& b_);
		virtual int on_sort_compareDirection(const Gtk::TreeModel::iterator& a_, const Gtk::TreeModel::iterator& b_);
		virtual int on_sort_compareLocalIP(const Gtk::TreeModel::iterator& a_, const Gtk::TreeModel::iterator& b_);
		virtual int on_sort_compareRemoteIP(const Gtk::TreeModel::iterator& a_, const Gtk::TreeModel::iterator& b_);
		virtual int on_sort_compare_startTime(const Gtk::TreeModel::iterator& a_, const Gtk::TreeModel::iterator& b_);
		virtual int on_sort_compare_duration(const Gtk::TreeModel::iterator& a_, const Gtk::TreeModel::iterator& b_);

		Gtk::VBox m_VBox; ///< Contains child widgets:

		Gtk::ScrolledWindow m_ScrolledWindow; ///< Window with scrollbars

		Gtk::TreeView m_TreeView; ///< Table to show the graphlets
		Glib::RefPtr<Gtk::ListStore> m_refFlowTreeModel; ///< Holds the data for m_TreeView
		CflowModelColumns * flowModel;	///< Holds the data for m_TreeView

		Gtk::HButtonBox m_ButtonBox;	///< Contains the hide button
		Gtk::Button m_Button_Hide;		///< Button to hide the flowlist

		int flow_num;	///< Number of flows
		bool hidden;	///< True if window is hidden
		bool initialized;	///< True if the flowlist is initalized
};

//*** ChostListView ***************************************************************

// Edge count threshold for warning before oversized graphlets
#define	VIEW_EDGE_INITIAL_THRESHOLD	1000

/**
 *	\class ChpgListView
 *	\brief List view for graphlet metadata.
 *
 *	This type of list view is used whenever graphlets are directly derived from packet or flow data.
 *	An alternate form of list view (see listview1.cpp/h) is used when pre-processed graphlet data
 *	is imported.
 *
 */
class ChostListView: public Gtk::VBox {
	public:
		ChostListView();

		void initialize(ChostModelColumns * model, Glib::RefPtr<Gtk::ListStore> m_refTreeModel, const prefs_t & prefs);
		void reinitialize(ChostModelColumns * pmodel, Glib::RefPtr<Gtk::ListStore> m_refTreeModel);
		void set_data(CImport * data);
		void select_first_row();
		void write_cflows(std::string & filename);
		void clear_flowlist();

		sigc::signal<void, std::string, std::string, bool> signal_graphics_to_display;
		sigc::signal<void> signal_list_cleared;
		sigc::signal<void, std::string, std::string, int, bool> signal_large_graphics_to_display;
		sigc::signal<void, std::string> signal_error;
		sigc::signal<void, std::string> signal_failure;

	public:
		// Signal handlers
		virtual void on_button_first();
		virtual void on_button_last();
		virtual void on_button_goto_graphlet(int graphlet);
		virtual void on_button_goto_IP(IPv6_addr sIP);
		virtual void on_button_flowlist();

		const CFlowList & get_rflows();

		void show_graphlet_from_list(CImport & cimport, int graphlet_nr, bool remote_view, bool deleteFilters = true);
		void show_graphlet_from_list();

	private:
		// those elements are used to allow show_graphlet_from_list() to be called without to provide updated elements
		CImport * last_cimport;	///< latest cimport used
		int last_graphlet_nr;	///< latest graphlet_nr used
		bool last_remove_view;	///< remove_view flag used
		int last_start;			///< latest start index used
		int last_count;			///< latest count number used

	protected:
		// Signal handlers
		virtual void on_button_clear();
		virtual void on_button_showselection();
		virtual void on_button_previous();
		virtual void on_button_next();

		virtual int on_sort_compareIP(const Gtk::TreeModel::iterator& a_, const Gtk::TreeModel::iterator& b_);

		Gtk::ScrolledWindow m_ScrolledWindow;
		Gtk::TreeView m_TreeView;

		Gtk::HButtonBox m_ButtonBox;
		// Hide list
		Gtk::Button m_Button_Clear;			///< reset
		// Act on row selection
		Gtk::Button m_Button_ShowSelection;	///< Show currentyl selected row/flow
		// Navigation
		Gtk::Button m_Button_previous;	///< Show previous graphlet
		Gtk::Button m_Button_next;			///< Show next graphlet
		Gtk::Button m_Button_first;		///< Show first graphlet
		Gtk::Button m_Button_last;			///< Show last graphlet

		Gtk::Button m_Button_flowlist;	///< Show flowlist

		CflowlistWindow flowlist_view;	///< Pop-up window to inspect the flowlist


		bool initialized; ///< True if fill_flowlist() has been called

		Glib::RefPtr<Gtk::ListStore> m_refTreeModel;
		ChostModelColumns * pmodel; ///< Model containing metadata about graphlets
		CImport * hostData; ///< Handles import and transformation to dot
		CFlowList rflows; ///< Flow initialized by remote host look-up
		prefs_t prefs; ///< Stores the settings

		std::string title; ///< Window title
};

#endif /* GLISTVIEW_CFLOW_H */
