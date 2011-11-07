#ifndef GMODEL_H
#define GMODEL_H

/**
 *	\file gmodel.h
 *	\brief Metadata list view definitions (2) and graphics data class.
 *	
 *	The two list view classes define the way metadata is displayed to the user
 *	as a list of graphlets described by one line each.
 *	The graphics data class implements the DOT to GIF transformation and its
 *	visualization.
 */

#include <gtkmm.h>
#include <stdlib.h>
#include <string>

#include "gutil.h"
#include "HAPGraphlet.h"

//Include the BGL/Graphviz stuff from boost
#include <boost/graph/graphviz.hpp>
#include <boost/graph/iteration_macros.hpp>

// Constants used for limiting of graphics size and scaling of graphics window
//#define MAX_WIDTH	 1000
//#define MAX_HEIGHT 700

#define XMARGIN 50
#define YMARGIN 120

#define OVERSIZE_THRESHOLD 1.5

// ******************************************************************************************

/**
 *	\class ChpgModelColumns
 *	\brief Model containing metadata about graphlets (for list view).
 *
 */
class ChpgModelColumns: public Gtk::TreeModel::ColumnRecord {
	public:

		ChpgModelColumns();

		void add_row(Glib::RefPtr<Gtk::ListStore> m_refTreeModel, unsigned int graphlet, unsigned int hpgidx, unsigned int edges, unsigned int protos,
		      unsigned int dstIPs, unsigned int srcPorts, unsigned int dstPorts, uint64_t bytes);

		// Define names and types of columns
		Gtk::TreeModelColumn<unsigned int> m_col_graphlet;
		Gtk::TreeModelColumn<unsigned int> m_col_hpgidx;
		Gtk::TreeModelColumn<unsigned int> m_col_edges;
		Gtk::TreeModelColumn<unsigned int> m_col_protos;
		Gtk::TreeModelColumn<unsigned int> m_col_dstIPs;
		Gtk::TreeModelColumn<unsigned int> m_col_srcPorts;
		Gtk::TreeModelColumn<unsigned int> m_col_dstPorts;
		Gtk::TreeModelColumn<uint64_t> m_col_bytes;
};

// ******************************************************************************************

/**
 *	\class ChostModelColumns
 *	\brief Model containing metadata about graphlets (for list view).
 *
 */
class ChostModelColumns: public Gtk::TreeModel::ColumnRecord {
	public:

		ChostModelColumns();

		void add_row(Glib::RefPtr<Gtk::ListStore> m_refTreeModel, IPv6_addr IP, unsigned int graphlet, unsigned int flIdx, unsigned int flows,
		      unsigned int uniflows, unsigned int protos, unsigned int packets, uint64_t bytes);

		// Define names and types of columns
		Gtk::TreeModelColumn<std::string> m_col_IP;
		Gtk::TreeModelColumn<unsigned int> m_col_graphlet;
		Gtk::TreeModelColumn<unsigned int> m_col_flIdx;
		Gtk::TreeModelColumn<unsigned int> m_col_flows;
		Gtk::TreeModelColumn<unsigned int> m_col_uniflows;
		Gtk::TreeModelColumn<unsigned int> m_col_protos;
		Gtk::TreeModelColumn<unsigned int> m_col_packets;
		Gtk::TreeModelColumn<uint64_t> m_col_bytes;
};

// ******************************************************************************************

/**
 *	\class CGraphicsArea
 *	\brief Model of graphics data to visualize (for visualization of DOT files).
 *	Implements transformation of DOT descriptions into XDOT and draws on this object.
 *
 */
class CGraphicsArea: public Gtk::DrawingArea {
	public:
		CGraphicsArea(std::string filename);
		int get_width();
		int get_height();
		bool is_oversize(void);
		void drawGraphlet();

		// Signal to send when user clicks a remote IP
		sigc::signal<void, IPv6_addr> signal_newLocalIP; ///< this will become the new local IP (for the remote IP view)
		sigc::signal<void, uint32_t> signal_newRolnum; ///< this rolenum will no longer be summarized

	protected:
		//Override default signal handlers:
		virtual bool on_expose_event(GdkEventExpose* event);
		virtual bool on_button_release_event(GdkEventButton* event);

		Glib::RefPtr<Gdk::Window> window; ///< Pointer to the window we are inside of
		const static int offset_vertical = 2; ///< Vertical offset
		const static int offset_horizontal = 2;///< Horizontal offset
		int desktop_screensize_x; ///< Horizontal screensize of this computer
		int desktop_screensize_y; ///< Vertical screensize of this computer

		Cairo::RefPtr<Cairo::Context> context; ///< Cairo context we draw on

		HAPGraphlet graphlet; ///< Contains all the information about our graph

		// Helper functions to draw the graphlet
		void draw_polygon(const std::vector<HAPGraphlet::pos<int> > & points, HAPGraphlet::color_t color, HAPGraphlet::style_t style, int linewidth = 1);
		void draw_circle(double x, double y, double r, int linewidth = 1);
		void draw_ellipse(const std::vector<HAPGraphlet::pos<int> > & points, HAPGraphlet::color_t color, HAPGraphlet::style_t style, int linewidth = 1);
		void draw_text(double x, double y, double width, HAPGraphlet::textpos_t tpos, double fontsize, const std::string & text, const std::string & font);
		void draw_bspline(std::vector<HAPGraphlet::pos<int> > points, HAPGraphlet::color_t, int linewidth = 1);
		void set_color(double red, double green, double blue);
		void set_color(HAPGraphlet::color_t color);
		void set_background(HAPGraphlet::color_t);
		void set_background(double red, double green, double blue);
};

#endif /* GMODEL_H */
