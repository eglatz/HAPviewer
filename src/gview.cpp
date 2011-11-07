/**
 *	\file	gview.cpp
 *	\brief Main view of application.
 */

#include "HAPviewer.h"
#include "gview.h"
#include "glistview_hpg.h"
#include "gmodel.h"
#include "ghpgdata.h"
#include "IPv6_addr.h"

#include <gtkmm/stock.h>
#include <glibmm/thread.h>
#include <giomm.h>

#include <boost/bind.hpp>

#include <iostream>
#include <stdlib.h>
#include <libgen.h>

#ifdef NDEBUG
const bool dbg=true;
const bool dbg2=false;
#else
const bool dbg = true;
const bool dbg2 = false;
#endif

using namespace std;

//*** CGotoGraphlet ***************************************************************

/**
 * Default Constructor
 */
CGotoGraphlet::CGotoGraphlet() :
	m_Button_GotoGraphlet("Go") {
	set_title("Goto graphlet number:");
	set_border_width(10);

	m_Entry.set_text("0");
	m_Vbox.pack_start(m_Entry, Gtk::PACK_SHRINK);

	m_Button_GotoGraphlet.signal_clicked().connect(sigc::mem_fun(*this, &CGotoGraphlet::on_button_goto_graphlet));
	m_Vbox.pack_start(m_Button_GotoGraphlet, Gtk::PACK_SHRINK);

	add(m_Vbox);
}
/**
 *	Show this window
 */
void CGotoGraphlet::unhide() {
	m_Entry.set_text("0");
	show_all_children();
	set_keep_above(true);
	set_modal(true);
	show();
}

/**
 *	Display the supplied graphlet
 */
void CGotoGraphlet::on_button_goto_graphlet() {
	Glib::ustring text = m_Entry.get_text();
	hide();
	cout << "Entered goto text: " << text << endl;
	int graphlet = boost::lexical_cast<int>(text);

	signal_goto_graphlet(graphlet);
}

//*** CGotoIP *****************************************************************
/**
 * Default Constructor
 */
CGotoIP::CGotoIP() :
	m_Button_GotoIP("Go IP") {
	set_title("Goto IP address:");
	set_border_width(10);

	m_Entry.set_text("");
	m_Vbox.pack_start(m_Entry, Gtk::PACK_SHRINK);

	m_Button_GotoIP.signal_clicked().connect(sigc::mem_fun(*this, &CGotoIP::on_button_goto_IP));
	m_Vbox.pack_start(m_Button_GotoIP, Gtk::PACK_SHRINK);

	add(m_Vbox);
}

/**
 *	Show this window
 */
void CGotoIP::unhide() {
	m_Entry.set_text(goto_IP.toString());
	show_all_children();
	set_keep_above(true);
	set_modal(true);
	show();
}

/**
 *	Display the graphlet for the supplied IP
 */
void CGotoIP::on_button_goto_IP() {
	bool good_ip = false;
	try {
		goto_IP = IPv6_addr(m_Entry.get_text());
		good_ip = true;
	} catch (string & e) {
		cerr << e << endl;
	}
	hide();
	if (good_ip) {
		cout << "Entered goto text: " << goto_IP << endl;
		signal_goto_IP(goto_IP);
	}
}

//*** CGetNetwork *****************************************************************
/**
 * Default Constructor
 */
CGetNetwork::CGetNetwork() :
	m_Button_GetNetwork("Get network") {
	set_title("Get local network:");
	set_border_width(10);

	m_Label1.set_text("Network address: ");
	m_Hbox_IP.pack_start(m_Label1, Gtk::PACK_SHRINK);
	m_Entry_IP.set_text("");
	m_Hbox_IP.pack_start(m_Entry_IP, Gtk::PACK_SHRINK);

	m_Label2.set_text("Address prefix value: ");
	m_Hbox_prefix.pack_start(m_Label2, Gtk::PACK_SHRINK);
	m_Entry_prefix.set_text("8");
	m_Entry_prefix.set_max_length(3);
	m_Entry_prefix.set_width_chars(3);
	m_Hbox_prefix.pack_start(m_Entry_prefix, Gtk::PACK_SHRINK);

	m_Button_GetNetwork.signal_clicked().connect(sigc::mem_fun(*this, &CGetNetwork::on_button_get_network));
	m_Vbox.add(m_Hbox_IP);

	m_Vbox.add(m_Hbox_prefix);
	m_Vbox.pack_start(m_Button_GetNetwork, Gtk::PACK_EXPAND_PADDING);

	add(m_Vbox);

	if (dbg) {
		local_net = IPv6_addr("::");
		netmask_text = "128";
	} else {
		local_net = IPv6_addr();
		netmask_text = "8";
	}
}

/**
 *	Show this window
 */
void CGetNetwork::unhide() {
	m_Entry_IP.set_text(local_net.toString());
	m_Entry_prefix.set_text(netmask_text);
	show_all_children();
	set_keep_above(true);
	set_modal(true);
	show();

}

/**
 *	Get an IP and the netmask
 */
void CGetNetwork::on_button_get_network() {
	IPv6_addr netmask_tmp;
	try {
		local_net = (string) m_Entry_IP.get_text();
		netmask_text = m_Entry_prefix.get_text();
		uint32_t prefix = boost::lexical_cast<uint32_t>(netmask_text);
		// Add 96 bits if user enters an IPv4 address and the according hostmask
		if (prefix <= 32 && local_net.isIPv4()) {
			prefix += 96;
		}
		netmask_tmp = IPv6_addr::getNetmask(prefix);
	} catch (...) {
		cerr << "Invalid input" << endl;
		return;
	}
	hide();

	signal_get_network(local_net, netmask_tmp);
}

//*** CPreferences ************************************************************
/**
 * Default Constructor
 */
CPreferences::CPreferences() :
	m_button_sum_biflows("summarize biflows"), m_button_sum_uniflows("summarize uniflows"), m_button_filter_biflows("filter biflows"),
	      m_button_filter_uniflows("filter uniflows"), m_button_filter_unprod_inflows("filter unproductive inflows"),
	      m_button_filter_unprod_outflows("filter unproductive outflows"), m_button_filter_TCP("filter TCP flows"), m_button_filter_UDP("filter UDP flows"),
	      m_button_filter_ICMP("filter ICMP flows"), m_button_filter_OTHER("filter OTHER flows"),
	      m_button_warn_oversized_graphlet("warn before oversized graphlets"), m_Button_ok("Okay") {
	set_title("Preferences");
	set_border_width(10);

	prefs.summarize_clt_roles = true;
	prefs.summarize_multclt_roles = true;
	prefs.summarize_srv_roles = true;
	prefs.summarize_p2p_roles = true;

	prefs.summarize_biflows = true;
	m_button_sum_biflows.set_active(true);

	prefs.summarize_uniflows = true;
	m_button_sum_uniflows.set_active(true);

	prefs.filter_biflows = false;
	prefs.filter_uniflows = false;
	prefs.filter_unprod_inflows = false;
	prefs.filter_unprod_outflows = false;
	prefs.filter_TCP = false;
	prefs.filter_UDP = false;
	prefs.filter_ICMP = false;
	prefs.filter_OTHER = false;

	prefs.warn_oversized_graphlet = true;
	m_button_warn_oversized_graphlet.set_active(true);

	m_button_sum_biflows.signal_clicked().connect(sigc::mem_fun(*this, &CPreferences::on_button_sum_biflows_clicked));
	m_Vbox.pack_start(m_button_sum_biflows, Gtk::PACK_SHRINK);

	m_button_sum_uniflows.signal_clicked().connect(sigc::mem_fun(*this, &CPreferences::on_button_sum_uniflows_clicked));
	m_Vbox.pack_start(m_button_sum_uniflows, Gtk::PACK_SHRINK);

	m_Vbox.add(m_separator);

	m_button_filter_biflows.signal_clicked().connect(sigc::mem_fun(*this, &CPreferences::on_button_filter_biflows_clicked));
	m_Vbox.pack_start(m_button_filter_biflows, Gtk::PACK_SHRINK);

	m_button_filter_uniflows.signal_clicked().connect(sigc::mem_fun(*this, &CPreferences::on_button_filter_uniflows_clicked));
	m_Vbox.pack_start(m_button_filter_uniflows, Gtk::PACK_SHRINK);

	m_button_filter_unprod_inflows.signal_clicked().connect(sigc::mem_fun(*this, &CPreferences::on_button_filter_inflows_clicked));
	m_Vbox.pack_start(m_button_filter_unprod_inflows, Gtk::PACK_SHRINK);

	m_button_filter_unprod_outflows.signal_clicked().connect(sigc::mem_fun(*this, &CPreferences::on_button_filter_outflows_clicked));
	m_Vbox.pack_start(m_button_filter_unprod_outflows, Gtk::PACK_SHRINK);

	m_Vbox.add(m_separator2);

	m_button_filter_TCP.signal_clicked().connect(sigc::mem_fun(*this, &CPreferences::on_button_filter_TCP_clicked));
	m_Vbox.pack_start(m_button_filter_TCP, Gtk::PACK_SHRINK);

	m_button_filter_UDP.signal_clicked().connect(sigc::mem_fun(*this, &CPreferences::on_button_filter_UDP_clicked));
	m_Vbox.pack_start(m_button_filter_UDP, Gtk::PACK_SHRINK);

	m_button_filter_ICMP.signal_clicked().connect(sigc::mem_fun(*this, &CPreferences::on_button_filter_ICMP_clicked));
	m_Vbox.pack_start(m_button_filter_ICMP, Gtk::PACK_SHRINK);

	m_button_filter_OTHER.signal_clicked().connect(sigc::mem_fun(*this, &CPreferences::on_button_filter_OTHER_clicked));
	m_Vbox.pack_start(m_button_filter_OTHER, Gtk::PACK_SHRINK);

	m_Vbox.add(m_separator3);

	m_button_warn_oversized_graphlet.signal_clicked().connect(sigc::mem_fun(*this, &CPreferences::on_button_warn_oversized_graphlet_clicked));
	m_Vbox.pack_start(m_button_warn_oversized_graphlet, Gtk::PACK_SHRINK);

	m_Button_ok.signal_clicked().connect(sigc::mem_fun(*this, &CPreferences::on_button_pref_ok));
	m_Vbox.add(m_Button_ok);

	add(m_Vbox);
}

/**
 *	Show this window
 */
void CPreferences::unhide() {
	show_all_children();
	set_keep_above(true);
	set_modal(true);
	show();
}
/**
 *	Get used preferences
 *
 *	\return prefs_t Return preferences
 */
prefs_t CPreferences::get_prefs() {
	return prefs;
}

/**
 * For debugging purposes: Print current state to console
 */
void CPreferences::on_button_sum_biflows_clicked() {
	if (dbg2)
		cout << "Check box clicked. state=" << (m_button_sum_biflows.get_active() ? "true" : "false") << endl;
}

/**
 * For debugging purposes: Print current state to console
 */
void CPreferences::on_button_sum_uniflows_clicked() {
	if (dbg2)
		cout << "Check box clicked. state=" << (m_button_sum_uniflows.get_active() ? "true" : "false") << endl;
}

/**
 * For debugging purposes: Print current state to console
 */
void CPreferences::on_button_filter_biflows_clicked() {
	if (dbg2)
		cout << "Check box clicked. state=" << (m_button_filter_biflows.get_active() ? "true" : "false") << endl;
}

/**
 * For debugging purposes: Print current state to console
 */
void CPreferences::on_button_filter_uniflows_clicked() {
	if (dbg2)
		cout << "Check box clicked. state=" << (m_button_filter_uniflows.get_active() ? "true" : "false") << endl;
}

/**
 * For debugging purposes: Print current state to console
 */
void CPreferences::on_button_filter_inflows_clicked() {
	if (dbg2)
		cout << "Check box clicked. state=" << (m_button_filter_unprod_inflows.get_active() ? "true" : "false") << endl;
}

void CPreferences::on_button_filter_outflows_clicked() {
	if (dbg2)
		cout << "Check box clicked. state=" << (m_button_filter_unprod_outflows.get_active() ? "true" : "false") << endl;
}

/**
 * For debugging purposes: Print current state to console
 */
void CPreferences::on_button_filter_TCP_clicked() {
	if (dbg2)
		cout << "Check box clicked. state=" << (m_button_filter_TCP.get_active() ? "true" : "false") << endl;
}

/**
 * For debugging purposes: Print current state to console
 */
void CPreferences::on_button_filter_UDP_clicked() {
	if (dbg2)
		cout << "Check box clicked. state=" << (m_button_filter_UDP.get_active() ? "true" : "false") << endl;
}

/**
 * For debugging purposes: Print current state to console
 */
void CPreferences::on_button_filter_ICMP_clicked() {
	if (dbg2)
		cout << "Check box clicked. state=" << (m_button_filter_ICMP.get_active() ? "true" : "false") << endl;
}

/**
 * For debugging purposes: Print current state to console
 */
void CPreferences::on_button_filter_OTHER_clicked() {
	if (dbg2)
		cout << "Check box clicked. state=" << (m_button_filter_OTHER.get_active() ? "true" : "false") << endl;
}

/**
 * For debugging purposes: Print current state to console
 */
void CPreferences::on_button_warn_oversized_graphlet_clicked() {
	if (dbg2)
		cout << "Check box clicked. state=" << (m_button_warn_oversized_graphlet.get_active() ? "true" : "false") << endl;
}

/**
 * Updates the preferences to the actually selected one from the GUI
 */
void CPreferences::on_button_pref_ok() {
	hide();
	if (dbg2)
		cout << "Button pref ok pressed.\n";
	prefs_t prefs;
	prefs.summarize_biflows = m_button_sum_biflows.get_active();
	prefs.summarize_uniflows = m_button_sum_uniflows.get_active();
	prefs.filter_biflows = m_button_filter_biflows.get_active();
	prefs.filter_uniflows = m_button_filter_uniflows.get_active();
	prefs.filter_unprod_inflows = m_button_filter_unprod_inflows.get_active();
	prefs.filter_unprod_outflows = m_button_filter_unprod_outflows.get_active();
	prefs.filter_TCP = m_button_filter_TCP.get_active();
	prefs.filter_UDP = m_button_filter_UDP.get_active();
	prefs.filter_ICMP = m_button_filter_ICMP.get_active();
	prefs.filter_OTHER = m_button_filter_OTHER.get_active();
	prefs.warn_oversized_graphlet = m_button_warn_oversized_graphlet.get_active();

	signal_preferences(prefs);
}

//*** CView *******************************************************************
/**
 * Constructor: Default constructor
 *
 * @param argv Not used.
 */
CView::CView(char *argv[]) :
	m_Button_Refresh1("Refresh"), m_Button_Refresh2("Refresh"), m_Button_Flowlist1("Flowlist"), m_Button_Flowlist2("Flowlist") {
	graphicsArea = NULL; // Start without drawing area
	graphicsArea2 = NULL; // Start without drawing area
	rinitialized = false;
	hpgData = NULL;
	flowImport = NULL;
	hpgModel = NULL;
	hostModel = NULL;
	xpos = ypos = 0;
	edges_threshold = VIEW_EDGE_INITIAL_THRESHOLD;

	prefs = m_preferences.get_prefs();

	Glib::RefPtr<Gdk::Screen> screen = Gdk::Screen::get_default();
	int screen_width = screen->get_width();
	max_x = screen_width - XMARGIN;
	int screen_height = screen->get_height();
	max_y = screen_height - YMARGIN;
	if (dbg)
		cout << "Screen width = " << screen_width << ", height = " << screen_height << endl;

	// Set main window title
	maintitle = BASETITLE;
	set_title(maintitle);

	// Fetch icon for title bar decoration from file
	//
	// TODO: for now we get the icon from user's default gtk rc file directory until we know
	// a better way how to install the icon file in a standard procedure without needing root privileges.
	char * home = getenv("HOME");
	cout << "User's home directory is: " << home << endl;
	string icon_filename(home);
	icon_filename += "/.gtkrc-2.0/icon1.png";
	Glib::RefPtr<Gdk::Pixbuf> icon_image;
	try {
		icon_image = Gdk::Pixbuf::create_from_file(icon_filename.c_str());
	} catch (const Gdk::PixbufError& ex) {
		string errtext = "could not load icon image from file " + icon_filename;
		cerr << "ERROR: " << errtext << endl;
		cerr << "Going to use default icon.\n";
	} catch (...) {
		string errtext = "could not open file " + icon_filename;
		cerr << "ERROR: " << errtext << endl;
		cerr << "Going to use default icon.\n";
	}
	set_icon(icon_image);

	// Initial main window size in pixels (can be changed by user later on)
	set_default_size(800, 400);

	add(m_Box); // Add a vertical box to main window.
	// m_Box will be initialized with a menu bar at the top and  a status bar at the bottom.
	// In the middle part of the box a metadata list view will be added whenever data is imported

	// Create actions for menus and toolbars:
	m_refActionGroup = Gtk::ActionGroup::create();

	// File menu
	// *********
	m_refActionGroup->add(Gtk::Action::create("FileMenu", "_File"));

	m_refActionGroup->add(Gtk::Action::create("FileOpen", Gtk::Stock::OPEN), sigc::mem_fun(*this, &CView::on_menu_file_open));

	m_refActionGroup->add(Gtk::Action::create("FileSave", Gtk::Stock::SAVE_AS), sigc::mem_fun(*this, &CView::on_menu_file_save));

		m_refActionGroup->add(Gtk::Action::create("TestList", Gtk::Stock::NEW),
	   	sigc::mem_fun(*this, &CView::on_menu_file_test));

	m_refActionGroup->add(Gtk::Action::create("FileClose", Gtk::Stock::CLOSE), sigc::mem_fun(*this, &CView::on_menu_file_close));

	m_refActionGroup->add(Gtk::Action::create("FileQuit", Gtk::Stock::QUIT), sigc::mem_fun(*this, &CView::on_menu_file_quit));

	// View menu
	// *********
	m_refActionGroup->add(Gtk::Action::create("ViewMenu", "_View"));

	m_refActionGroup->add(Gtk::Action::create("ViewFirst", Gtk::Stock::GOTO_FIRST, "Go to first graphlet"), sigc::mem_fun(*this, &CView::on_menu_first));

	m_refActionGroup->add(Gtk::Action::create("ViewLast", Gtk::Stock::GOTO_LAST, "Go to last graphlet"), sigc::mem_fun(*this, &CView::on_menu_last));

	m_refActionGroup->add(Gtk::Action::create("ViewGotoGraphlet", Gtk::Stock::JUMP_TO, "Go to graphlet"), sigc::mem_fun(*this, &CView::on_menu_gotoGraphlet));

	m_refActionGroup->add(Gtk::Action::create("ViewGotoIP", Gtk::Stock::JUMP_TO, "Go to IP address"), sigc::mem_fun(*this, &CView::on_menu_gotoIP));

	// Configure menu
	// **************
	m_refActionGroup->add(Gtk::Action::create("ConfigureMenu", "_Configure"));

	Glib::RefPtr<Gtk::ToggleAction> m_summarize_clients = Gtk::ToggleAction::create("SummarizeClt", "Summarize client roles", "summarize client roles");
	if (prefs.summarize_clt_roles)
		m_summarize_clients->set_active(true);
	m_refActionGroup->add(m_summarize_clients, sigc::mem_fun(*this, &CView::on_menu_summarize_clt));

	Glib::RefPtr<Gtk::ToggleAction> m_summarize_multclients = Gtk::ToggleAction::create("SummarizeMultClt", "Summarize multi-client roles",
	      "summarize multi-client roles");
	if (prefs.summarize_multclt_roles)
		m_summarize_multclients->set_active(true);
	m_refActionGroup->add(m_summarize_multclients, sigc::mem_fun(*this, &CView::on_menu_summarize_multclt));

	Glib::RefPtr<Gtk::ToggleAction> m_summarize_servers = Gtk::ToggleAction::create("SummarizeSrv", "Summarize server roles", "summarize server roles");
	if (prefs.summarize_srv_roles)
		m_summarize_servers->set_active(true);
	m_refActionGroup->add(m_summarize_servers, sigc::mem_fun(*this, &CView::on_menu_summarize_srv));

	Glib::RefPtr<Gtk::ToggleAction> m_summarize_p2p = Gtk::ToggleAction::create("SummarizeP2P", "Summarize P2P roles", "summarize P2P roles");
	if (prefs.summarize_p2p_roles)
		m_summarize_p2p->set_active(true);
	m_refActionGroup->add(m_summarize_p2p, sigc::mem_fun(*this, &CView::on_menu_summarize_p2p));

	m_refActionGroup->add(Gtk::Action::create("Preferences", Gtk::Stock::PREFERENCES), sigc::mem_fun(*this, &CView::on_menu_preferences));

	// Help menu
	// *********
	m_refActionGroup->add(Gtk::Action::create("HelpMenu", "Help"));

	m_refActionGroup->add(Gtk::Action::create("HelpContents", Gtk::Stock::HELP), sigc::mem_fun(*this, &CView::on_menu_help));
	m_refActionGroup->add(Gtk::Action::create("HelpAbout", Gtk::Stock::INFO), sigc::mem_fun(*this, &CView::on_menu_information));

	m_refUIManager = Gtk::UIManager::create();
	m_refUIManager->insert_action_group(m_refActionGroup);

	add_accel_group(m_refUIManager->get_accel_group());

	// Layout the actions in a menubar and toolbar
	Glib::ustring ui_info = "<ui>"
		"  <menubar name='MenuBar'>"
		"    <menu action='FileMenu'>"
		"      <menuitem action='FileOpen'/>"
		"      <menuitem action='FileSave'/>"
		//        "      <menuitem action='TestList'/>"		// displayed as "New" as "new" icon is used
		   "      <menuitem action='FileClose'/>"
		   "      <separator/>"
		   "      <menuitem action='FileQuit'/>"
		   "    </menu>"
		   "    <menu action='ViewMenu'>"
		   "      <menuitem action='ViewFirst'/>"
		   "      <menuitem action='ViewGotoGraphlet'/>"
		   "      <menuitem action='ViewGotoIP'/>"
		   "      <menuitem action='ViewLast'/>"
		   "    </menu>"
		   "    <menu action='ConfigureMenu'>"
		   "      <menuitem action='SummarizeClt'/>"
		   "      <menuitem action='SummarizeMultClt'/>"
		   "      <menuitem action='SummarizeSrv'/>"
		   "      <menuitem action='SummarizeP2P'/>"
		   "      <menuitem action='Preferences'/>"
		   "    </menu>"
		   "    <menu action='HelpMenu'>"
		   "      <menuitem action='HelpContents'/>"
		   "      <menuitem action='HelpAbout'/>"
		   "    </menu>"
		   "  </menubar>"
		   "</ui>";

#ifdef GLIBMM_EXCEPTIONS_ENABLED

	try {
		m_refUIManager->add_ui_from_string(ui_info);
	} catch (const Glib::Error& ex) {
		cerr << "building menus failed: " << ex.what();
	}

#else

	std::auto_ptr<Glib::Error> ex;
	m_refUIManager->add_ui_from_string(ui_info, ex);
	if (ex.get()) {
		cerr << "building menus failed: " << ex->what();

	}

#endif /* GLIBMM_EXCEPTIONS_ENABLED */
	// Get the menubar and toolbar widgets, and add them to a container widget:
	Gtk::Widget* pMenubar = m_refUIManager->get_widget("/MenuBar");
	if (pMenubar) {
		m_Box.pack_start(*pMenubar, Gtk::PACK_SHRINK);
	}

	// Pop-up dialogs: assign action functions
	m_Goto_graphlet.signal_goto_graphlet.connect(sigc::mem_fun(*this, &CView::handle_goto_graphlet));
	m_Goto_IP.signal_goto_IP.connect(sigc::mem_fun(*this, &CView::handle_goto_IP));
	m_get_network.signal_get_network.connect(sigc::mem_fun(*this, &CView::handle_get_network));
	m_preferences.signal_preferences.connect(sigc::mem_fun(*this, &CView::handle_preferences));

	m_StatusBar.push("Ready");

	m_ProgressBar.set_fraction(0.0);

	m_BorderBox.pack_start(m_Separator, Gtk::PACK_SHRINK);
	m_BorderBox.pack_start(m_ProgressBar, Gtk::PACK_SHRINK);
	m_StatusBar.pack_end(m_BorderBox, Gtk::PACK_SHRINK);

	m_Box.pack_end(m_StatusBar, Gtk::PACK_SHRINK);
	show_all_children();

	Gdk::Window::process_all_updates();
}

/**
 * Destructor
 */
CView::~CView() {
}

/**
 * Handle file open
 */
void CView::on_menu_file_open() {
	if (dbg2) {
		cout << "File|Open action was selected." << std::endl;
	}

	Gtk::FileChooserDialog dialog("Please choose a file", Gtk::FILE_CHOOSER_ACTION_OPEN);
	dialog.set_transient_for(*this);

	// Add response buttons to the dialog:
	dialog.add_button(Gtk::Stock::CANCEL, Gtk::RESPONSE_CANCEL);
	dialog.add_button(Gtk::Stock::OPEN, Gtk::RESPONSE_OK);

	// Add filters, so that only certain file types can be selected

	Gtk::FileFilter filter_any;
	filter_any.set_name("Any files");
	filter_any.add_pattern("*");
	dialog.add_filter(filter_any);

	Gtk::FileFilter filter_hpg;
	filter_hpg.set_name("HPG files");
	filter_hpg.add_pattern("*.hpg");
	dialog.add_filter(filter_hpg);

	Gtk::FileFilter filter_dot;
	filter_dot.set_name("DOT files");
	filter_dot.add_pattern("*.dot");
	dialog.add_filter(filter_dot);
//
//	Gtk::FileFilter filter_gif;
//	filter_gif.set_name("GIF files");
//	filter_gif.add_pattern("*.gif");
//	dialog.add_filter(filter_gif);

	vector<std::string> formatNames = CImport::getAllFormatNames();
	vector<std::string> patternNames = CImport::getAllHumanReadablePatterns();

	for(unsigned int i = 0; i < formatNames.size() && i < patternNames.size(); i++) {
		Gtk::FileFilter filter;
		filter.set_name(formatNames[i]);
		filter.add_pattern(patternNames[i]);
		dialog.add_filter(filter);
	}

	// To suppress display of hidden files we have to
	// 1) use file filter setting "[^.]*"
	// 2) de-activate the dialog property "show hidden"
	dialog.set_show_hidden(false); // Do not show hidden files

	// For MIME-file types: see MIME type catalog: see http://www.mimetype.org/

	// Show the dialog and wait for a user response:
	int result = dialog.run();

	// Handle the response:
	switch (result) {
		case (Gtk::RESPONSE_OK): {
			// cout << "Open clicked." << std::endl;
			import_filename = dialog.get_filename();
			dialog.hide_all();
			cout << "File selected: " << import_filename << std::endl;

			// Action depends on file type:
			// - display graphics data if a *.dot or *.gif file is given
			// - show metadata about loaded graphlets if a *.hpg file is given

			// Check if file name ends in ".hpg" (binary host profile graphlet data file)
			size_t hpg_pos = import_filename.rfind(".hpg");
			if (hpg_pos != string::npos) {
				//
				// hpg (host profile graphlet) file
				// ********************************
				// Check if found string is really at end of filename
				if (hpg_pos != (import_filename.size() - 4)) {
					cout << "Filename contains \"*.hpg\", but not at its end.\n";
				} else {
					handle_hpgMetadataview(import_filename);
					show_all_children();
				}
			} else if (CImport::getFormatName(import_filename) == "cflow4" || CImport::getFormatName(import_filename) == "cflow6") {
				//
				// gz (g'zipped binary cflow_t) file
				// *******************************
				// Check if found string is really at end of filename
				string hpg_filename = "temp.hpg";
				bool ok;

				cout << "Starting separate thread to read *.gz file.\n";

				//Disabled due to a unknown, surprisingly hard to track down bug. Need someone who can compile C++ code is his head to resolve it.
				//boost::thread import_thread(boost::bind(&CView::handle_binary_import, this, import_filename, hpg_filename));
				try {
					handle_binary_import(import_filename, hpg_filename);
				} catch (string & error) {
					return;
				}
				// Give GUI a chance to refresh
				// while (Gtk::Main::events_pending()) Gtk::Main::iteration(false);
				//				while (Gtk::Main::events_pending())
				//					Gtk::Main::iteration(); // As suggested by gtkmm reference page
				//				import_thread.join();

				// ok = handle_binary_import(import_filename, hpg_filename, CImport::isCflow);
				ok = false; // Force always the flowlist-oriented metadata handling & listing
				if (ok) {
					handle_hpgMetadataview(hpg_filename);
					show_all_children();
				} else {
					handle_hostMetadataview();
					show_all_children();
				}
			} else if (CImport::acceptForImport(import_filename)) {
				// Show get network address/prefix dialog to request user for input
				m_get_network.unhide();
			} else if (import_filename.rfind(".dot") == (import_filename.size() - 4)){
				// *.dot file
				// *******************
				handle_graphicsview(import_filename, import_filename, false);
			} else {
				handle_failure("Sorry, but there is no support for this format");
			}
			break;
		}
		case (Gtk::RESPONSE_CANCEL): {
			cout << "Cancel clicked." << std::endl;
			break;
		}
		default: {
			cout << "Unexpected button clicked." << std::endl;
			break;
		}
	}
}

/**
 * Handle file save
 *
 * \exception std::string Errormessage
 */
void CView::on_menu_file_save() {
	if (dbg2)
		cout << "File save selected.\n";

	Gtk::FileChooserDialog dialog("Please choose a name for graph/flow data file to save", Gtk::FILE_CHOOSER_ACTION_SAVE);
	dialog.set_transient_for(*this);

	// Add response buttons to the dialog:
	dialog.add_button(Gtk::Stock::CANCEL, Gtk::RESPONSE_CANCEL);
	dialog.add_button(Gtk::Stock::SAVE_AS, Gtk::RESPONSE_OK);

	// Show the dialog and wait for a user response:
	int result = dialog.run();

	// Handle the response:
	size_t pos = 0;
	string filename2;
	switch (result) {
		case (Gtk::RESPONSE_OK): {
			filename2 = dialog.get_filename();
			dialog.hide_all();
			cout << "File selected: " << filename2 << std::endl;

			// Action depends on file type (identified through file name extension enetred by user):
			// - save DOT file of graphlet if a *.dot file name is given
			// - save GIF file of graphlet if a *.gif file name is given
			// - save flow list of graphlet to cflow_t binary file if a *.gz file name is given

			// Check if file name ends in ".gif"
			pos = filename2.rfind(".gif");
			if (pos != string::npos) {
				// Check if found string is really at end of filename
				if (pos != (filename2.size() - 4)) {
					cout << "Filename contains \"*.gif\", but not at its end.\n";
				} else {
					// Copy default gif file generated to specified filename
					string filename1 = default_dot_filename;
					try {
						string type("gif");
						util::renderDot(filename1, filename2, type);
					}
					catch(string & e) {
						throw e;
					}
					break;
				}
			}

			// Check if file name ends in ".dot"
			pos = filename2.rfind(".dot");
			if (pos != string::npos) {
				// Check if found string is really at end of filename
				if (pos != (filename2.size() - 4)) {
					cout << "Filename contains \"*.dot\", but not at its end.\n";
				} else {
					// Copy default dot file generated to specified filename
					string filename1 = default_dot_filename;
					try {
						Glib::RefPtr<Gio::File> file1 = Gio::File::create_for_path(filename1);
						if (!file1)
							std::cerr << "Gio::File::create_for_path() returned an empty RefPtr." << std::endl;

						Glib::RefPtr<Gio::File> file2 = Gio::File::create_for_path(filename2);
						if (!file2)
							std::cerr << "Gio::File::create_for_path() returned an empty RefPtr." << std::endl;

						if (file1->copy(file2, Gio::FILE_COPY_OVERWRITE))
							cout << "File saved successfully.\n";
						else
							cerr << "ERROR: file save failed.\n";
					} catch (const Glib::Exception& ex) {
						cerr << "Exception caught: " << ex.what() << endl;
						throw;
					}
				}
				break;
			}

			pos = filename2.rfind(".hpg");
			if (pos != string::npos) {
				// Check if found string is really at end of filename
				if (pos != (filename2.size() - 4)) {
					cout << "Filename contains \"*.hpg\", but not at its end.\n";
				} else {
					// Copy default hpg file generated to specified filename
					string filename1 = default_hpg_filename;
					try {
						Glib::RefPtr<Gio::File> file1 = Gio::File::create_for_path(filename1);
						if (!file1)
							std::cerr << "Gio::File::create_for_path() returned an empty RefPtr." << std::endl;

						Glib::RefPtr<Gio::File> file2 = Gio::File::create_for_path(filename2);
						if (!file2)
							std::cerr << "Gio::File::create_for_path() returned an empty RefPtr." << std::endl;

						if (file1->copy(file2, Gio::FILE_COPY_OVERWRITE))
							cout << "File saved successfully.\n";
						else
							cerr << "ERROR: file save failed.\n";
					} catch (const Glib::Exception& ex) {
						cerr << "Exception caught: " << ex.what() << endl;
						throw;
					}
				}
				break;
			}

			// Check if file name ends in ".gz"
			pos = filename2.rfind(".gz");
			if (pos != string::npos) {
				// Check if found string is really at end of filename
				if (pos != (filename2.size() - 3)) {
					cout << "Filename contains \"*.gz\", but not at its end.\n";
				} else {
					// Save flow list to binary file
					hostListview.write_cflows(filename2);
				}
				break;
			}
			// No valid file name extension was found: display error message
			Gtk::MessageDialog dialog(*this, "ERROR:");
			string errtext = " no valid file name (like \"*.gif\" or \"*.dot\") was entered. File not saved.";
			dialog.set_secondary_text(errtext);
			dialog.run();
			break;
		}
		case (Gtk::RESPONSE_CANCEL): {
			if (dbg2)
				cout << "Cancel clicked." << std::endl;
			break;
		}
		default: {
			if (dbg2)
				cout << "Unexpected button clicked." << std::endl;
			break;
		}
	}

}

/**
 * Handle file test
 */
void CView::on_menu_file_test() {
	cout << "Test list was selected." << std::endl;

	// Show test list

	// Create the hpgModel
	if (m_refHpgTreeModel) {
		// List view already exists: re-create hpgModel
		//		cout << "m_refHpgTreeModel is *NOT* NULL\n";
		m_refHpgTreeModel.clear();
		if (hpgModel)
			delete hpgModel;
		hpgModel = new ChpgModelColumns();
		m_refHpgTreeModel = Gtk::ListStore::create(*hpgModel);
		hpgListview.reinitialize(hpgModel, m_refHpgTreeModel);

	} else {
		//		cout << "m_refHpgTreeModel is NULL\n";

		hpgModel = new ChpgModelColumns();
		m_refHpgTreeModel = Gtk::ListStore::create(*hpgModel);

		// Create and show view
		hpgListview.initialize(hpgModel, m_refHpgTreeModel);

		m_Box.add(hpgListview);
	}

	if (m_refHpgTreeModel) {
		// Fill hpgModel with some test data
		hpgModel->add_row(m_refHpgTreeModel, 1, 0, 13, 2, 4, 3, 5, 100);
		hpgModel->add_row(m_refHpgTreeModel, 2, 23, 10, 2, 6, 3, 5, 200);
		hpgModel->add_row(m_refHpgTreeModel, 3, 47, 19, 3, 4, 3, 5, 300);
		hpgModel->add_row(m_refHpgTreeModel, 4, 67, 13, 1, 5, 6, 10, 400);
	} else {
		cerr << "ERROR: m_refHpgTreeModel is NULL.\n";
		cerr << "ERROR in construction of hpgModel.\n";
	}

	Glib::ustring gtitle = "HAPviewer: ";
	gtitle = gtitle + " test data";
	set_title(gtitle);
	show();

	show_all_children();

}

/**
 * Handle close menu
 */
void CView::on_menu_file_close() {
	handle_list_cleared(); // Remove any loaded file data and it's displayed metadata list
}

/**
 * Handle quit
 */
void CView::on_menu_file_quit() {
	hide(); // Closes the main window to leave the Gtk::Main::run() event loop.
}

/**
 * Handle help
 */
void CView::on_menu_help() {
	Gtk::MessageDialog dialog(*this, "Getting Help");
	string text = "A short introduction and some guidelines on usage can be found on the project's home page:\n\n";
	text += "http://hapviewer.sourceforge.net\n";
	dialog.set_secondary_text(text);
	dialog.run();
}

/**
 * Handle information
 */
void CView::on_menu_information() {
	Gtk::MessageDialog dialog(*this, "HAPviewer v2.0");
	string text = "HAPviewer is a host application profile graphlet viewer.\n";
	text += "Such profiles can be created from pcap, nfdump, ipfix or cflow network traffic data files.\n";
	text += "\nCopyright (c) 2009-2011, Eduard Glatz (eglatz@tik.ee.ethz.ch).\n\n";
	text += "Distributed under the Gnu Public License version 2 or the modified BSD license.";
	dialog.set_secondary_text(text);
	dialog.run();
}

/**
 * Debugging function.
 */
void CView::on_menu_others() {
	if (dbg2)
		cout << "A menu item was selected." << std::endl;
}
/**
 * Toggles betwen the summarizing and not summarizing
 */
void CView::on_menu_summarize_clt() {
	prefs.summarize_clt_roles = prefs.summarize_clt_roles ? false : true;
	if (dbg)
		cout << "Set summarize_client_roles to: " << (prefs.summarize_clt_roles ? "true" : "false") << endl;
}

/**
 * Toggles betwen the summarizing and not summarizing
 */
void CView::on_menu_summarize_multclt() {
	prefs.summarize_multclt_roles = prefs.summarize_multclt_roles ? false : true;
	if (dbg)
		cout << "Set summarize_multclient_roles to: " << (prefs.summarize_multclt_roles ? "true" : "false") << endl;
}

/**
 * Toggles betwen the summarizing and not summarizing
 */
void CView::on_menu_summarize_srv() {
	prefs.summarize_srv_roles = prefs.summarize_srv_roles ? false : true;
	if (dbg)
		cout << "Set summarize_server_roles to: " << (prefs.summarize_srv_roles ? "true" : "false") << endl;
}

/**
 * Toggles betwen the summarizing and not summarizing
 */
void CView::on_menu_summarize_p2p() {
	prefs.summarize_p2p_roles = prefs.summarize_p2p_roles ? false : true;
	if (dbg)
		cout << "Set summarize_p2p_roles to: " << (prefs.summarize_p2p_roles ? "true" : "false") << endl;
}

/**
 * Toggles betwen the summarizing and not summarizing
 */
void CView::on_menu_preferences() {
	if (dbg2)
		cout << "A menu item was selected." << std::endl;
	m_preferences.unhide();
}

/**
 * Shows the first graphlet
 */
void CView::on_menu_first() {
	if (m_refHpgTreeModel) {
		hpgListview.on_button_first();
	} else if (m_refHostTreeModel) {
		hostListview.on_button_first();
	} else {
		cerr << "ERROR: cannot go to graphlet as no data is loaded.\n";
	}
}

/**
 * Shows the last graphlet
 */
void CView::on_menu_last() {
	if (m_refHpgTreeModel) {
		hpgListview.on_button_last();
	} else if (m_refHostTreeModel) {
		hostListview.on_button_last();
	} else {
		cerr << "ERROR: cannot go to graphlet as no data is loaded.\n";
	}
}

/**
 * Asks user for a specific graphlet and shows this one
 */
void CView::on_menu_gotoGraphlet() {
	// Show goto graphlet dialog
	m_Goto_graphlet.unhide();
}

/**
 * Asks user for a specific IP and show the graphlet to it
 */
void CView::on_menu_gotoIP() {
	// Show goto IP dialog
	m_Goto_IP.unhide();
}

/**
 * Refresh the rflows
 */
void CView::on_button_refresh() {
	CFlowList rflows = hostListview.get_rflows();
	if (rflows.size() > 0) {
		static CImport tmpImp(rflows, prefs);
		hostListview.show_graphlet_from_list(tmpImp, -1, true);
	} else {
		cerr << "ERROR in CView::in_button_refresh(): unexpectedly rflows = 0 encountered.\n";
	}
}

/**
 * Prepares and Show the flowlist
 */
void CView::on_button_flowlist() {
	CFlowList rflows = hostListview.get_rflows();
	if (rflows.size() > 0) {
		flowlist_view.fill_flowlist(rflows, -1);
		flowlist_view.unhide();
	} else {
		cerr << "ERROR in CView::on_button_flowlist(): no flows found to display.\n";
	}
}

/**
 * Show a specific graphlet
 */
void CView::handle_goto_graphlet(int graphlet) {
	if (m_refHpgTreeModel) {
		hpgListview.on_button_goto_graphlet(graphlet);
	} else if (m_refHostTreeModel) {
		hostListview.on_button_goto_graphlet(graphlet);
	} else {
		cerr << "ERROR: cannot go to graphlet as no data is loaded.\n";
	}
}

/**
 * Show a specific IP
 */
void CView::handle_goto_IP(IPv6_addr IP) {
	if (m_refHostTreeModel) {
		hostListview.on_button_goto_IP(IP);
	} else if (m_refHpgTreeModel) {
		cerr << "ERROR: cannot go to IP as loaded file type does not support IP addresses in metadata.\n";
	} else {
		cerr << "ERROR: cannot go to IP as no data is loaded.\n";
	}
}

/**
 * Add a new rolenumber to the set of the not-to-be summarized nodes
 *
 * @param rolnum Rolenumber not to summarize
 */
void CView::handle_new_rolnum(uint32_t rolnum) {
	if (m_refHostTreeModel) {
		desummarizedRoles role_set;
		role_set.insert(rolnum);
		flowImport->add_desummarized_roles(role_set);
		desummarizedRoles role_set2 = flowImport->get_desummarized_roles();
		hostListview.show_graphlet_from_list();
	} else if (m_refHpgTreeModel) {
		cerr << "ERROR: cannot desummarize as loaded file type does not support IP addresses in metadata.\n";
	} else {
		cerr << "ERROR: cannot desummarize as no data is loaded.\n";
	}
}

/**
 * Imports from a file to a CFlowList, using the submitted IP and netmask
 *
 * @param IP IP
 * @param netmask Netmask
 */
void CView::handle_get_network(IPv6_addr IP, IPv6_addr netmask) {
	if (dbg2)
		cout << "Handler for get network triggered:\n";

	this->netmask = netmask;
	handle_list_cleared();

	local_net = IP;
	cout << "Netmask is: " << hex << netmask << dec << endl;
	cout << "Network address was: " << local_net << endl;
	local_net = local_net & netmask;
	cout << "Network address is: " << local_net << endl;

	// Now we are ready to import data from file
	string hpg_filename = "temp.hpg"; // FIXME: store this on a central point
	bool ok;
	try{
		ok = handle_binary_import(import_filename, hpg_filename);
		ok = false; // Force always flowlist-oriented metadata view
		if (ok) {
			handle_hpgMetadataview(hpg_filename);
			show_all_children();
		} else {
			handle_hostMetadataview();
			show_all_children();
		}
	}
	catch(string & e) {
		handle_failure(e);
	}
}

/**
 *	Handles a clear request of user.
 *
 *	Action taken includes:
 *	- remove any display graphlet window
 *	- remove file name from main windows title bar
 *	- remove status info from status bar
 *	- hide list view
 *	- remove tree and data models of list
 */
void CView::handle_list_cleared() {
	maintitle = BASETITLE;
	set_title(maintitle);
	m_StatusBar.pop();

	if (graphicsArea != NULL) { // Remove obsolete graphics window if any exists
		imgwin.hide(); // Hide in case window is still visible
		imgwin.get_position(xpos, ypos); // Remember current window position
		imgwin.remove();
		delete graphicsArea;
		graphicsArea = NULL;
	}
	if (graphicsArea2 != NULL) { // Remove obsolete graphics window if any exists
		imgwin2.hide(); // Hide in case window is still visible
		imgwin2.remove();
		delete graphicsArea2;
		graphicsArea2 = NULL;
	}

	if (m_refHpgTreeModel) { // List view already exists: remove view from m_Box, delete it and the associated model
		m_Box.remove(hpgListview);
		m_refHpgTreeModel.reset();
		if (hpgModel) {
			delete hpgModel;
			hpgModel = NULL;
		}
	}

	if (m_refHostTreeModel) { // List view already exists: remove view from m_Box, delete it and the associated model
		m_Box.remove(hostListview);
		m_refHostTreeModel.reset();
		delete hostModel;
		hostModel = NULL;
		hostListview.clear_flowlist();
	}
}

/**
 * Displays an errortext to the user and ends HAPviewer
 *
 * @param errtext Error message
 */
void CView::handle_error(std::string errtext) {
	Gtk::MessageDialog dialog(*this, "ERROR:");
	dialog.set_title("ERROR");
	dialog.set_secondary_text(errtext);
	dialog.run();
	exit(1);
}

/**
 * Displays an errortext to the user
 *
 * @param errtext  * Displays an errortext to the user and ends HAPviewer
 */
void CView::handle_failure(std::string errtext) {
	Gtk::MessageDialog dialog(*this, "INFO:");
	dialog.set_title("INFO");
	dialog.set_secondary_text(errtext);
	dialog.run();
}

/**
 * Update preferences with the given ones
 *
 * @param newprefs Reference to the preferences which should get copied
 */
void CView::handle_preferences(const prefs_t & newprefs) {
	// Copy only the fields covered by preferences dialog
	prefs.summarize_biflows = newprefs.summarize_biflows;
	prefs.summarize_uniflows = newprefs.summarize_uniflows;
	prefs.filter_biflows = newprefs.filter_biflows;
	prefs.filter_uniflows = newprefs.filter_uniflows;
	prefs.filter_unprod_inflows = newprefs.filter_unprod_inflows;
	prefs.filter_unprod_outflows = newprefs.filter_unprod_outflows;
	prefs.filter_TCP = newprefs.filter_TCP;
	prefs.filter_UDP = newprefs.filter_UDP;
	prefs.filter_ICMP = newprefs.filter_ICMP;
	prefs.filter_OTHER = newprefs.filter_OTHER;
	prefs.warn_oversized_graphlet = newprefs.warn_oversized_graphlet;
	if (dbg)
		cout << "Preferences set.\n";
}

/**
 *	Handle graphics visualization when graph is very large.
 *
 *	\param	filename Name of graphics file to visualize
 *	\param	title	Title to put on visualization window
 *	\param	edges	Count of edges to display
 *	\param	remote_view Set to TRUE if graphlet is provided for remoteIP instead of localIP
 */
void CView::handle_large_graphicsview(std::string filename, std::string title, unsigned int edges, bool remote_view) {
	if (prefs.warn_oversized_graphlet && (edges > edges_threshold)) {
		Gtk::MessageDialog dialog(*this, "WARNING:", false, Gtk::MESSAGE_QUESTION, Gtk::BUTTONS_OK_CANCEL);
		stringstream ss;
		ss << "large graph (edge count = " << edges << "). Display anyway?";
		dialog.set_secondary_text(ss.str());
		dialog.set_title("Warning");
		int result = dialog.run();

		switch (result) {
			case (Gtk::RESPONSE_OK): {
				edges_threshold = edges;
				handle_graphicsview(filename, title, remote_view);
				break;
			}
			case (Gtk::RESPONSE_CANCEL): {
				std::cout << "Cancel clicked." << std::endl;
				break;
			}
			default: {
				std::cout << "Unexpected button clicked." << std::endl;
				break;
			}
		}
	} else {
		handle_graphicsview(filename, title, remote_view);
	}
}

/**
 *	Show graphics data in its own window and decorate it with given title.
 *
 *	\param	filename Name of graphics file to visualize
 *	\param	title	Title to be used to create a window title text
 *	\param	remote_view Set to TRUE if graphlet is provided for remoteIP instead of localIP
 */
void CView::handle_graphicsview(std::string filename, std::string title, bool remote_view) {
	if (!remote_view) {
		if (graphicsArea != NULL) { // Remove obsolete graphics window if any exists
			imgwin.hide(); // Hide in case window is still visible
			//		imgwin.get_position(xpos, ypos); // Remember current window position
			//		cout << "x = " << xpos << ", y = " << ypos << endl; 	//Debug
			imgwin.remove();
			delete graphicsArea;
			graphicsArea = NULL;
		}
		bool ok = false;
		try {
			graphicsArea = new CGraphicsArea(filename);
			ok = true;
		} catch (string & errtext) {
			// Upon failed open on filename given
			handle_failure(errtext);
		}
		if (ok) {
			// We have graphics data to display: show it in its own window
			int width = graphicsArea->get_width();
			int height = graphicsArea->get_height();

			//--------------------------------
			graphicsArea->signal_newLocalIP.connect(sigc::mem_fun(*this, &CView::handle_goto_IP));
			graphicsArea->signal_newRolnum.connect(sigc::mem_fun(*this, &CView::handle_new_rolnum));
			//--------------------------------
			if (graphicsArea->is_oversize()) { // FIXME
				if (dbg)
					cout << "Using scrollbars due to oversized picture.\n";
				// Only show the scrollbars when they are necessary
				m_ScrolledWindow.set_policy(Gtk::POLICY_AUTOMATIC, Gtk::POLICY_AUTOMATIC);
				m_ScrolledWindow.add(*graphicsArea);

				height = (height > max_y) ? max_y : height;
				width = (width > max_x) ? max_x : width;

				imgwin.add(m_ScrolledWindow);
				graphicsArea->set_size_request(graphicsArea->get_width(), graphicsArea->get_height());
				if (dbg) {
					cout << "graphicsArea->set_size_request(" << graphicsArea->get_width() << ", " << graphicsArea->get_height() << ")\n";
				}

				// FIXME: use proper scrollbar width/height (from where to get it?)
				// (questioning the scrollbar widgets always yields a value of 1)
				imgwin.set_size_request(width + 23, height + 25);

				if (dbg)
					cout << "imgwin.set_size_request(" << width << ", " << height << ")\n";

				imgwin.set_resizable(false);
			} else {
				imgwin.add(*graphicsArea);
				imgwin.set_size_request(width, height);
				imgwin.set_resizable(false);
				graphicsArea->set_size_request(graphicsArea->get_width(), graphicsArea->get_height());
				//graphicsArea->set_size_request(1024, 768); // FIXME
			}

			imgwin.set_gravity(Gdk::GRAVITY_NORTH_WEST); // Use left-upper corner as position reference
			//		imgwin.set_type_hint(Gdk::WINDOW_TYPE_HINT_TOOLBAR);
			Glib::ustring gtitle = "HAPviewer: " + title;
			imgwin.set_title(gtitle);
			imgwin.show();

			//		imgwin.move(xpos, ypos); // Use same position as last time graphlet window was displayed
			// Reposition after show(); otherwise window mgr might ignore it
			imgwin.show_all_children();
		}
	} else { // remote_view = true
		if (graphicsArea2 != NULL) { // Remove obsolete graphics window if any exists
			imgwin2.hide(); // Hide in case window is still visible
			imgwin2.remove();
			m_ScrolledWindow2.remove();
			delete graphicsArea2;
			graphicsArea2 = NULL;
		}
		bool ok = true;
		try {
			graphicsArea2 = new CGraphicsArea(filename);
		} catch (string & errtext) {
			// Upon failed open on filename given
			ok = false;
			Gtk::MessageDialog dialog(*this, "ERROR:");
			dialog.set_secondary_text(errtext);
			dialog.run();
		}
		if (ok) {
			// We have graphics data to display: show it in its own window
			int width = graphicsArea2->get_width();
			int height = graphicsArea2->get_height();

			//--------------------------------
			graphicsArea->signal_newLocalIP.connect(sigc::mem_fun(*this, &CView::handle_goto_IP));
			//--------------------------------

			if (graphicsArea2->is_oversize()) { // FIXME
				if (dbg)
					cout << "Using scrollbars due to oversized picture.\n";

				imgwin2.add(m_VBox1);
				m_ScrolledWindow2.add(*graphicsArea2);
				height = (height > max_y) ? max_y - 50 : height;
				width = (width > max_x) ? max_x : width;
				imgwin2.set_size_request(width + 23, height);

			} else {

				imgwin2.add(m_VBox2);
				m_VBox2.pack_start(*graphicsArea2, Gtk::PACK_SHRINK);
				height = (height > max_y) ? max_y : height;
				width = (width > max_x) ? max_x : width;
				imgwin2.set_size_request(width, height + 40);
			}

			if (!rinitialized) {
				//	imgwin2.add(m_VBox);
				// Only show the scrollbars when they are necessary
				m_ScrolledWindow2.set_policy(Gtk::POLICY_AUTOMATIC, Gtk::POLICY_AUTOMATIC);
				m_VBox1.pack_start(m_ScrolledWindow2);

				// Add buttons
				m_VBox1.pack_end(m_Separator1, Gtk::PACK_SHRINK);
				m_VBox1.pack_end(m_ButtonBox1, Gtk::PACK_SHRINK);

				m_Button_Refresh1.signal_clicked().connect(sigc::mem_fun(*this, &CView::on_button_refresh));
				m_ButtonBox1.pack_start(m_Button_Refresh1, Gtk::PACK_SHRINK);
				m_Button_Flowlist1.signal_clicked().connect(sigc::mem_fun(*this, &CView::on_button_flowlist));
				m_ButtonBox1.pack_start(m_Button_Flowlist1, Gtk::PACK_SHRINK);

				m_ButtonBox1.set_border_width(5);
				m_ButtonBox1.set_spacing(5);

				m_ButtonBox1.set_layout(Gtk::BUTTONBOX_END);

				//

				m_VBox2.pack_end(m_Separator2, Gtk::PACK_SHRINK);
				m_VBox2.pack_end(m_ButtonBox2, Gtk::PACK_SHRINK);

				m_Button_Refresh2.signal_clicked().connect(sigc::mem_fun(*this, &CView::on_button_refresh));
				m_ButtonBox2.pack_start(m_Button_Refresh2, Gtk::PACK_SHRINK);
				m_Button_Flowlist2.signal_clicked().connect(sigc::mem_fun(*this, &CView::on_button_flowlist));
				m_ButtonBox2.pack_start(m_Button_Flowlist2, Gtk::PACK_SHRINK);

				m_ButtonBox2.set_border_width(5);
				m_ButtonBox2.set_spacing(5);

				m_ButtonBox2.set_layout(Gtk::BUTTONBOX_END);

				rinitialized = true;
			}

			graphicsArea2->set_size_request(graphicsArea2->get_width(), graphicsArea2->get_height());
			if (dbg) {
				cout << "graphicsArea2->set_size_request(" << graphicsArea2->get_width() << ", " << graphicsArea2->get_height() << ")\n";
			}

			// FIXME: use proper scrollbar width/height (from where to get it?)
			// (questioning the scrollbar widgets always yields a value of 1)
			//				imgwin2.set_size_request(width+23, height+25);

			if (dbg) {
				cout << "imgwin2.set_size_request(" << width << ", " << height << ")\n";
			}

			imgwin2.set_resizable(false);

			imgwin2.set_gravity(Gdk::GRAVITY_NORTH_WEST); // Use left-upper corner as position reference
			Glib::ustring gtitle = "HAPviewer (remote host view): " + title;
			imgwin2.set_title(gtitle);
			imgwin2.show();

			imgwin2.show_all_children();
		}
	}
}

/**
 *	Read a host profile graphlet (hpg) file and set-up list view of its contents.
 *
 *	Host profile graphlet data is read to memory. Then metadata is prepared that is
 *	filled into the list view presented on the GUI.
 *
 *	The metadata provides the following information per graphlet:
 *	- graphlet # : graphlet number (basically a local host numbering)
 *	- edges : count of edges contained in graphlet
 *	- protos : count of protocols used
 *	- remoteIPs : count of remote hosts contacted
 *	- localPorts : count of local ports
 *	- remotePorts : count of remote ports
 *
 *	Metadata information helps the user to select "interesting" graphlets to view.
 *	This is further supported by the column sorting facility of the hpgListView.
 *
 *	\param filename Name of hpg file to process
 */
void CView::handle_hpgMetadataview(std::string filename) {
	// Dismiss old hpg model (if any)
	if (hpgData != NULL) {
		delete hpgData;
		hpgData = NULL;
	}

	if (m_refHostTreeModel) { // List view already exists: remove view from m_Box, delete it and the associated model
		m_Box.remove(hostListview);
		m_refHostTreeModel.reset();
		delete hostModel;
		hostModel = NULL;
	}

	// Read hpg data into memory and extract metadata
	bool ok = true;
	try {
		hpgData = new ChpgData(filename);
	} catch (string & errtext) {
		// Upon failed open on filename given
		ok = false;
		Gtk::MessageDialog dialog(*this, "ERROR:");
		dialog.set_secondary_text(errtext);
		dialog.run();
	}
	if (ok) {
		try {
			hpgData->read_hpg_file();
		} catch (string & errtext) {
			// Upon failed open on filename given
			ok = false;
			Gtk::MessageDialog dialog(*this, "ERROR:");
			dialog.set_secondary_text(errtext);
			dialog.run();
		}
	}

	// Set-up view of metadata
	if (ok) {
		char s[100];
		char * base = basename((char *) filename.c_str());
		sprintf(s, "%s: %s", BASETITLE, base);
		maintitle = s;
		set_title(maintitle);

		// Create the hpgModel

		if (m_refHpgTreeModel) { // List view already exists: remove view from m_Box, delete it and the associated model
			m_Box.remove(hpgListview);
			m_refHpgTreeModel.reset();
			if (hpgModel)
				delete hpgModel;
		}

		hpgModel = new ChpgModelColumns();
		if (dbg)
			cout << "Creating hpgModel.\n";
		m_refHpgTreeModel = Gtk::ListStore::create(*hpgModel);
		if (dbg)
			cout << "Model created. Initializing hpgModel.\n";
		// Create and show view
		hpgListview.initialize(hpgModel, m_refHpgTreeModel);
		if (dbg)
			cout << "Model initialized.\n";
		hpgListview.set_data(hpgData);
		hpgListview.signal_graphics_to_display.connect(sigc::mem_fun(*this, &CView::handle_graphicsview));
		hpgListview.signal_large_graphics_to_display.connect(sigc::mem_fun(*this, &CView::handle_large_graphicsview));
		hpgListview.signal_list_cleared.connect(sigc::mem_fun(*this, &CView::handle_list_cleared));
		hpgListview.signal_error.connect(sigc::mem_fun(*this, &CView::handle_error));
		m_Box.add(hpgListview);

		if (m_refHpgTreeModel) {
			// Fetch metadata from hpg data read into memory

			if (dbg)
				cout << "Preparing hpg metadata...\n";

			hpgData->signal_show_progressbar.connect(sigc::mem_fun(*this, &CView::show_progressbar));
			hpgData->signal_set_progress.connect(sigc::mem_fun(*this, &CView::update_progressbar));
			hpgData->signal_hide_progressbar.connect(sigc::mem_fun(*this, &CView::hide_progressbar));

			//			m_StatusBar.push("Loading:  0 % done");

			// Parallelize: use a separate thread to process meta data
			Glib::Thread * const worker = Glib::Thread::create(sigc::mem_fun(*hpgData, &ChpgData::get_hpgMetadata), true);
			//			Glib::Thread * const worker = Glib::Thread::create(sigc::mem_fun(*hpgData, &ChpgData::get_hpgMetadata), 0, true, true, Glib::THREAD_PRIORITY_LOW);
			// And wait for its termination
			worker->join();

			// Do not parallelize: run inside of this thread
			//			hpgData->get_hpgMetadata();

			if (dbg)
				cout << "Metadata prepared. Adding hpgMetadata to hpgModel.\n";

			ChpgMetadata * pg = hpgData->get_first_graphlet();

			while (pg != NULL) {
				hpgModel->add_row(m_refHpgTreeModel, pg->graphlet_nr, pg->index, pg->edge_count, pg->prot_count, pg->dstIP_cnt, pg->srcPort_cnt, pg->dstPort_cnt,
				      pg->bytesForAllFlows);
				pg = hpgData->get_next_graphlet();
			}

			if (dbg)
				cout << "Model complete.\n";

		} else {
			cerr << "ERROR: m_refHpgTreeModel is NULL.\n";
			cerr << "ERROR in construction of hpgModel.\n";
		}
	}
}

/**
 *	Prepare host metadata for very large numbers of hosts.
 *
 *	The host metadata (in contrast to hpg metadata) is directly derived from the
 *	flowlist and supports hpg data generation on-the-fly for selected hosts only.
 *	This approach eliminates the need to create a huge hpg file of all hosts.
 *
 *	The metadata is filled into the list view presented on the GUI.
 *
 *	The metadata provides the following information per host (row):
 *	- IP : IPv4 address of host
 *	- flows : count of flows exchanged with this host
 *	- protos : count of protocols used
 *	- packets : count of packets exchanged with this host
 *	- totalBytes : count of bytes exchanged with this host
 *
 *	Metadata information helps the user to select "interesting" graphlets to view.
 *	This is further supported by the column sorting facility of the hostListView.
 *
 */
void CView::handle_hostMetadataview() {
	// Remove hpg view and model (if any)
	if (m_refHpgTreeModel) { // List view already exists: remove view from m_Box, delete it and the associated model
		m_Box.remove(hpgListview);
		m_refHpgTreeModel.reset();

		if (hpgModel) {
			delete hpgModel;
			hpgModel = NULL;
		}

		if (hpgData) {
			delete hpgData;
			hpgData = NULL;
		}
	}

	// Set-up view of metadata (can be done directly through "flowImport")
	if (flowImport != NULL) {
		maintitle = BASETITLE;
		maintitle = maintitle + ": " + flowImport->get_in_filename();

		set_title(maintitle);

		// Create the hostModel

		if (m_refHostTreeModel) { // List view already exists: remove view from m_Box, delete it and the associated model
			m_Box.remove(hostListview);
			m_refHostTreeModel.reset();
			delete hostModel;
		}

		hostModel = new ChostModelColumns();
		if (dbg)
			cout << "Creating hostModel.\n";
		m_refHostTreeModel = Gtk::ListStore::create(*hostModel);
		if (dbg)
			cout << "Model created. Initializing hostModel.\n";

		// Create and show view
		hostListview.initialize(hostModel, m_refHostTreeModel, prefs);
		if (dbg)
			cout << "Model initialized.\n";
		hostListview.set_data(flowImport);
		hostListview.signal_graphics_to_display.connect(sigc::mem_fun(*this, &CView::handle_graphicsview));
		hostListview.signal_large_graphics_to_display.connect(sigc::mem_fun(*this, &CView::handle_large_graphicsview));
		hostListview.signal_list_cleared.connect(sigc::mem_fun(*this, &CView::handle_list_cleared));
		hostListview.signal_error.connect(sigc::mem_fun(*this, &CView::handle_error));
		hostListview.signal_failure.connect(sigc::mem_fun(*this, &CView::handle_failure));
		m_Box.add(hostListview);

		if (m_refHostTreeModel) {
			// Fetch metadata from host data read into memory

			if (dbg)
				cout << "Preparing host metadata.\n";

			flowImport->signal_show_progressbar.connect(sigc::mem_fun(*this, &CView::show_progressbar));
			flowImport->signal_set_progress.connect(sigc::mem_fun(*this, &CView::update_progressbar));
			flowImport->signal_hide_progressbar.connect(sigc::mem_fun(*this, &CView::hide_progressbar));

			//			m_StatusBar.push("Loading:  0 % done");

			// Parallelize: use a separate thread to process meta data
			//			Glib::Thread * const worker = Glib::Thread::create(sigc::mem_fun(*flowImport, &CImport::get_hostMetadata), true);
			flowImport->get_hostMetadata();
			// And wait for its termination
			//worker->join();

			// Do not parallelize: run inside of this thread
			//			flowImport->get_hostMetadata();

			if (dbg)
				cout << "Metadata prepared. Adding hostMetadata to hostModel.\n";

			try { // FIXME: Maybe we should not use try/catch for regular use
				ChostMetadata pg = flowImport->get_first_host_metadata();

				int row_cnt = 0;
				while (true) {
					row_cnt++;
					// Show progress on console
					if ((row_cnt % 10000) == 0) {
						cout << ".";
						cout.flush();
					}

					hostModel->add_row(m_refHostTreeModel, pg.IP, pg.graphlet_number, pg.index, pg.flow_count, pg.uniflow_count, pg.prot_count, pg.packet_count,
					      pg.bytesForAllFlows);

					pg = flowImport->get_next_host_metadata();
				}
			} catch (...) {
				if (dbg)
					cout << "\nModel complete.\nPreselecting first row.\n";
			}
			hostListview.select_first_row();

		} else {
			cerr << "ERROR: m_refHostTreeModel is NULL.\n";
			cerr << "ERROR in construction of hostModel.\n";
		}
	}

}

/**
 *	Import binary flow or packet data stored using cflow_t or pcap format.
 *	Packet data is assembled to flows by merging packets exhibiting identical
 *	5-tuples {srcIP, dstIP, srcPort, dstPort, protocol}.
 *
 *	\param in_filename Name of traffic data input file to process
 *	\param out_filename Name assigned to output file (*.hpg)
 *
 *	\return True when hpg file created, false otherwise (for very large input files)
 *
 *	\exception std::string Errortext
 */
bool CView::handle_binary_import(std::string in_filename, string & out_filename) {
	handle_list_cleared();

	// Read hpg data into memory and extract metadata
	if (flowImport != NULL) {
		delete flowImport;
		flowImport = NULL;
	}

	if (flowImport->acceptForImport(in_filename)) {
		flowImport = new CImport(in_filename, out_filename, prefs);
		try {
			flowImport->read_file(local_net, netmask);
		} catch (string & errtext) {
			// Upon failed open on filename given
			throw errtext;
		}
		return true;
	} else {
		string errtext = "unknown file type (hint: supported are ";
		errtext += CImport::getFormatNamesAsString();
		errtext += ")\n";
		throw errtext;
	}
	return false;
}

/**
 * Shows the progressbar
 *
 * @param fraction Progress (0.0 to 1.0)
 */
void CView::show_progressbar(double fraction) {
	m_ProgressBar.set_fraction(fraction);
	//	if (dbg) Gdk::Window::set_debug_updates(true);	// Show invalidation for debugging

	Glib::RefPtr<Gdk::Window> probarwin = m_ProgressBar.get_window();
	Gdk::Rectangle r1(0, 0, m_ProgressBar.get_allocation().get_width(), m_ProgressBar.get_allocation().get_height());
	probarwin->invalidate_rect(r1, true);

	Gdk::Window::process_all_updates();

	if (dbg)
		cout << "Showing progress bar.\n";
}


/**
 * Handles the progressbar update
 *
 * @param fraction Progress (0.0 to 1.0)
 */
void CView::update_progressbar(double fraction) {
	if (dbg)
		cout << "Progress bar updated to " << fraction << "\n";
	m_ProgressBar.set_fraction(fraction);

	m_StatusBar.pop();
	char text[128];
	sprintf(text, "Loading: %2d %% done", (int) (fraction * 100.0));
	//	m_StatusBar.push(text);

	Glib::RefPtr<Gdk::Window> probarwin = m_ProgressBar.get_window();
	Gdk::Rectangle r1(0, 0, m_ProgressBar.get_allocation().get_width(), m_ProgressBar.get_allocation().get_height());
	probarwin->invalidate_rect(r1, true);

	Gdk::Window::process_all_updates();
}

/**
 * Hides the progressbar
 */
void CView::hide_progressbar() {
	m_StatusBar.pop();

	m_ProgressBar.set_fraction(0.0); // Reset to length 0 - anything else does not work properly
	//	m_StatusBar.push("File loaded");

	Glib::RefPtr<Gdk::Window> statusbarwin = m_StatusBar.get_window();
	Gdk::Rectangle r0(0, 0, m_StatusBar.get_allocation().get_width(), m_StatusBar.get_allocation().get_height());
	statusbarwin->invalidate_rect(r0, true);

	Gdk::Window::process_all_updates();
	if (dbg)
		Gdk::Window::set_debug_updates(false);
}

