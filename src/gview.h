#ifndef GVIEW_H
#define GVIEW_H

/**
 *	\file gview.h
 *	\brief Main view of application
 */

#include <gtkmm.h>
#include <string>

#include "gmodel.h"
#include "ghpgdata.h"
#include "glistview_cflow.h"
#include "glistview_hpg.h"
#include "gimport.h"
#include "global.h"
#include "IPv6_addr.h"

//*** CGotoGraphlet ***************************************************************

/**
 *	\class CGotoGraphlet
 *	\brief Implements a modal pop-up dialog to enter a graphlet number.
 */
class CGotoGraphlet: public Gtk::Window {
	public:
		CGotoGraphlet();
		void unhide();
		virtual void on_button_goto_graphlet();
		sigc::signal<void, int> signal_goto_graphlet;

	protected:
		Gtk::Entry m_Entry;
		Gtk::VBox m_Vbox;
		Gtk::Button m_Button_GotoGraphlet;
};

/*** CGotoIP *****************************************************************/

/**
 *	\class CGotoIP
 *	\brief Implements a modal pop-up dialog to enter an IP address.
 */
class CGotoIP: public Gtk::Window {
	public:
		CGotoIP();
		void unhide();
		virtual void on_button_goto_IP();
		sigc::signal<void, IPv6_addr> signal_goto_IP;

	protected:
		Gtk::Entry m_Entry;
		Gtk::VBox m_Vbox;
		Gtk::Button m_Button_GotoIP;
		// Remember last entered IP address
		IPv6_addr goto_IP;
};

/*** CGetNetwork *****************************************************************/

/**
 *	\class CGetNetwork
 *	\brief Implements a modal pop-up dialog to enter network address and 
 *	network address prefix value. This information is needed to determine the 
 *	local group of IP addresses in pcap data as pcap files do not store the 
 *	network address and netmask/address prefix of the capture interface.
 */
class CGetNetwork: public Gtk::Window {
	public:

		CGetNetwork();
		void unhide();
		virtual void on_button_get_network();
		sigc::signal<void, IPv6_addr, IPv6_addr> signal_get_network;

	protected:

		Gtk::Label m_Label1;
		Gtk::Entry m_Entry_IP;
		Gtk::HBox m_Hbox_IP;

		Gtk::Label m_Label2;
		Gtk::Entry m_Entry_prefix;
		Gtk::HBox m_Hbox_prefix;

		Gtk::VBox m_Vbox;
		Gtk::Button m_Button_GetNetwork;

		// Network address/prefix for pcap import
		IPv6_addr local_net;
		Glib::ustring netmask_text;

};

//*** CPreferences ************************************************************

class CPreferences: public Gtk::Window {
	public:
		CPreferences();
		void unhide();
		void on_button_sum_biflows_clicked();
		void on_button_sum_uniflows_clicked();
		void on_button_filter_biflows_clicked();
		void on_button_filter_uniflows_clicked();
		void on_button_filter_inflows_clicked();
		void on_button_filter_outflows_clicked();
		void on_button_filter_TCP_clicked();
		void on_button_filter_UDP_clicked();
		void on_button_filter_ICMP_clicked();
		void on_button_filter_OTHER_clicked();
		void on_button_warn_oversized_graphlet_clicked();
		void on_button_pref_ok();
		prefs_t get_prefs();
		sigc::signal<void, prefs_t> signal_preferences;

	protected:
		prefs_t prefs;

		Gtk::CheckButton m_button_sum_biflows;
		Gtk::CheckButton m_button_sum_uniflows;

		Gtk::SeparatorMenuItem m_separator, m_separator2, m_separator3;

		Gtk::CheckButton m_button_filter_biflows;
		Gtk::CheckButton m_button_filter_uniflows;
		Gtk::CheckButton m_button_filter_unprod_inflows;
		Gtk::CheckButton m_button_filter_unprod_outflows;

		Gtk::CheckButton m_button_filter_TCP;
		Gtk::CheckButton m_button_filter_UDP;
		Gtk::CheckButton m_button_filter_ICMP;
		Gtk::CheckButton m_button_filter_OTHER;

		Gtk::CheckButton m_button_warn_oversized_graphlet;

		Gtk::Button m_Button_ok;
		Gtk::VBox m_Vbox;
};

//*** CView *******************************************************************

/**
 *	\class CView
 *	\brief Main view of application.
 *
 */
class CView: public Gtk::Window {
	public:
		CView(char *argv[]);
		virtual ~CView();

	protected:
		// Application title
#define BASETITLE "HAPviewer"
		std::string maintitle;

		// Signal handlers
		// ***************
		virtual void on_menu_file_open();
		virtual void on_menu_file_save();
		virtual void on_menu_file_test();
		virtual void on_menu_file_close();
		virtual void on_menu_file_quit();
		virtual void on_menu_first();
		virtual void on_menu_last();
		virtual void on_menu_gotoGraphlet();
		virtual void on_menu_gotoIP();
		virtual void on_menu_help();
		virtual void on_menu_information();
		virtual void on_menu_others();
		virtual void on_menu_summarize_clt();
		virtual void on_menu_summarize_multclt();
		virtual void on_menu_summarize_srv();
		virtual void on_menu_summarize_p2p();
		virtual void on_menu_preferences();

		virtual void on_button_refresh();
		virtual void on_button_flowlist();

		// Auxiliary view handlers
		// ***********************
		void handle_hpgMetadataview(std::string filename);
		void handle_hostMetadataview();
		bool handle_binary_import(std::string in_filename, std::string & out_filename);
		void handle_graphicsview(std::string filename, std::string title, bool remote_view);
		void handle_large_graphicsview(std::string filename, std::string title, unsigned int edges, bool remote_view);
		void handle_list_cleared();
		void show_progressbar(double fraction);
		void update_progressbar(double fraction);
		void hide_progressbar();
		void handle_error(std::string filename);
		void handle_failure(std::string filename);
		void handle_preferences(const prefs_t & newprefs);

		// Other handlers
		void handle_goto_graphlet(int graphlet);
		void handle_goto_IP(IPv6_addr IP);
		void handle_new_rolnum(uint32_t rolnum);
		void handle_get_network(IPv6_addr IP, IPv6_addr netmask);

		// Child widgets
		// *************
		Gtk::VBox m_Box;
		Glib::RefPtr<Gtk::UIManager> m_refUIManager;
		Glib::RefPtr<Gtk::ActionGroup> m_refActionGroup;
		Glib::RefPtr<Gtk::RadioAction> m_refChoiceOne, m_refChoiceTwo;

		// Status bar
		Gtk::Statusbar m_StatusBar;

		// Progress bar
		Gtk::ProgressBar m_ProgressBar;
		Gtk::HSeparator m_Separator;
		Gtk::VBox m_BorderBox;

		// Dialog widgets
		// **************
		// Pop-up windows for go to graphlet/IP and get network addr./prefix
		CGotoGraphlet m_Goto_graphlet;
		CGotoIP m_Goto_IP;
		CGetNetwork m_get_network;
		CPreferences m_preferences;

		// Network address/prefix for pcap import
		// **************************************
		IPv6_addr local_net;
		IPv6_addr netmask;

		// Metadata list views & data
		// **************************
		// The HPG list view is used when data source is a *.hpg file,
		// and the host list view is used when data source is a *.gz/*-pcap file.

		std::string import_filename; ///< Name of file to import data from

		// HPG list
		ChpgModelColumns * hpgModel; ///< HPG model to visualize
		Glib::RefPtr<Gtk::ListStore> m_refHpgTreeModel; ///< HPG list view (refptr)
		ChpgListView hpgListview; ///< HPG list view (object)
		ChpgData * hpgData; ///< Data for HPG model

		// HOST list
		ChostModelColumns * hostModel; ///< HOST list model to visualize
		Glib::RefPtr<Gtk::ListStore> m_refHostTreeModel; ///< HOST list view (refptr)
		ChostListView hostListview; ///< HOST list view (object)
		CImport * flowImport; ///< Ref to data for HOST list model

		// Preferences
		// ***********
		struct prefs_t prefs; ///< Stores the preferences
		unsigned int edges_threshold;

		// Graphlet data and windows
		// *************************
		// ..1: for oversized (scrolled); ..2: otherwise
		CGraphicsArea * graphicsArea, *graphicsArea2; ///< Drawing area for graphics data
		Gtk::Window imgwin, imgwin2; ///< Used for an extra window to show graphics
		Gtk::ScrolledWindow m_ScrolledWindow, m_ScrolledWindow2; ///< For oversized pictures
		int xpos, ypos; ///< To remember the graphlet window position
		int max_x, max_y; ///< Maximum size of graphlet window (i.e. imgwin)

		// Add a button bar to remote host graphlet window
		Gtk::VBox m_VBox1, m_VBox2;
		Gtk::HButtonBox m_ButtonBox1, m_ButtonBox2;
		Gtk::HSeparator m_Separator1, m_Separator2;
		// Refresh
		Gtk::Button m_Button_Refresh1, m_Button_Refresh2;
		// Show flowlist
		Gtk::Button m_Button_Flowlist1, m_Button_Flowlist2;
		bool rinitialized;

		// Pop-up window (for remote host view)
		CflowlistWindow flowlist_view;

};

#endif /* GVIEW_H */
