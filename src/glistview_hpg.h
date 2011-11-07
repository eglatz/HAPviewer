#ifndef GLISTVIEW_HPG_H
#define GLISTVIEW_HPG_H
/**
 *	\file glistview_hpg.h
 *	\brief List view containing graphlet data.

 *	This type of list view is used whenever when pre-processed graphlet data is imported. 
 *	Shown metedata is graph-oriented by providing e.g. count of edges.
 *	An alternate form of list view (see glistview_cflow.cpp/h) is used when graphlets are directly
 *	derived from packet or flow data.
 */

#include <gtkmm.h>
#include <string>

#include "gmodel.h"
#include "ghpgdata.h"
#include "gview.h"

#define	VIEW_EDGE_INITIAL_THRESHOLD	1000

/**
 *	\class ChpgListView
 *	\brief List view for graphlet metadata
 *
 *	This type of list view is used whenever when pre-processed graphlet data is imported. 
 *	An alternate form of list view (see listview2.cpp/h) is used when graphlets are directly 
 *	derived from packet or flow data.
 *
 */
class ChpgListView: public Gtk::VBox {
	public:
		ChpgListView();
		virtual ~ChpgListView();

		void initialize(ChpgModelColumns * model, Glib::RefPtr<Gtk::ListStore> m_refTreeModel);
		void reinitialize(ChpgModelColumns * pmodel, Glib::RefPtr<Gtk::ListStore> m_refTreeModel);
		void set_data(ChpgData * data);

		sigc::signal<void, std::string, std::string, bool> signal_graphics_to_display; ///> Signal to transform/display function
		sigc::signal<void> signal_list_cleared; ///> Signal to clear list
		sigc::signal<void, std::string, std::string, int, bool> signal_large_graphics_to_display; ///< Ask user if he really wants to see the huge graphlet
		sigc::signal<void, std::string> signal_error; ///< Show an error

	public:
		virtual void on_button_first();
		virtual void on_button_last();
		virtual void on_button_goto_graphlet(int graphlet);

	protected:
		void show_graphlet_from_list(int graphlet_nr, int edges);

		// Signal handlers
		virtual void on_button_clear();
		virtual void on_button_showselection();
		virtual void on_button_previous();
		virtual void on_button_next();

		Gtk::ScrolledWindow m_ScrolledWindow;
		Gtk::TreeView m_TreeView;

		Gtk::HButtonBox m_ButtonBox;
		// Hide list
		Gtk::Button m_Button_Clear;
		// Act on row selection
		Gtk::Button m_Button_ShowSelection;
		// Navigation
		Gtk::Button m_Button_previous;
		Gtk::Button m_Button_next;
		Gtk::Button m_Button_first;
		Gtk::Button m_Button_last;

		bool initialized; ///< True if the flowlist is initalized

		Glib::RefPtr<Gtk::ListStore> m_refTreeModel;
		ChpgModelColumns * pmodel; ///< Model containing metadata about graphlets
		ChpgData * hpgData; ///< Keeps any hpg (host profile graphlet) data read

		std::string title; ///< Window title
};

#endif /* GLISTVIEW_HPG_H */
