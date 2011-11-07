/**
 *	\file gmodel.cpp
 *	\brief Graphics data class.
 *	The graphics data class implements the DOT to GIF transformation and its
 *	visualization.
 */

#include <gtkmm/drawingarea.h>
#include <gtkmm/messagedialog.h>
#include <cairomm/cairomm.h>

#include <iostream>
#include <string>
#include <limits>
#include <math.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#ifdef TRUE
	#undef TRUE
	#undef FALSE
#endif

#include <gvc.h>

//Include the BGL/Graphviz stuff from boost
#include <boost/graph/graphviz.hpp>

#include "HAPviewer.h"
#include "gmodel.h"

const bool dbg = false;

using namespace std;
using namespace boost;

/**
 *	Constructor: default constructor
 */
ChpgModelColumns::ChpgModelColumns() {
	add(m_col_graphlet);
	add(m_col_hpgidx);
	add(m_col_edges);
	add(m_col_protos);
	add(m_col_dstIPs);
	add(m_col_srcPorts);
	add(m_col_dstPorts);
	add(m_col_bytes);
}

/**
 *	Add a flow to the rolelist
 *
 *	\param m_refTreeModel	List to append a new row
 *	\param graphlet	Graphlet number
 *	\param hpgidx	HPG ID (never used?)
 *	\param edges Number of edges
 *	\param protos Number of involved protocols
 *	\param dstIPs Number of remote IPs
 *	\param srcPorts Number of local Ports
 *	\param dstPorts Number of remote Ports
 *	\param bytes Number of total bytes
 */
void ChpgModelColumns::add_row(Glib::RefPtr<Gtk::ListStore> m_refTreeModel, unsigned int graphlet, unsigned int hpgidx, unsigned int edges,
      unsigned int protos, unsigned int dstIPs, unsigned int srcPorts, unsigned int dstPorts, uint64_t bytes) {
	Gtk::TreeModel::Row row = *(m_refTreeModel->append());
	row[m_col_graphlet] = graphlet;
	row[m_col_hpgidx] = hpgidx;
	row[m_col_edges] = edges;
	row[m_col_protos] = protos;
	row[m_col_dstIPs] = dstIPs;
	row[m_col_srcPorts] = srcPorts;
	row[m_col_dstPorts] = dstPorts;
	row[m_col_bytes] = bytes;
}
/**
 *	Constructor: default constructor
 */
ChostModelColumns::ChostModelColumns() {
	add(m_col_IP);
	add(m_col_graphlet);
	add(m_col_flIdx);
	add(m_col_flows);
	add(m_col_uniflows);
	add(m_col_protos);
	add(m_col_packets);
	add(m_col_bytes);
}

/**
 *	Add a flow to the rolelist
 *
 *	\param m_refTreeModel	List to append a new row
 *	\param IP IP address
 *	\param graphlet	Graphlet number
 *	\param flIdx	Index into flowlist
 *	\param flows Number of flows
 *	\param uniflows Number of uniflows
 *	\param protos Number of involved protocols
 *	\param packets Number of packets
 *	\param bytes Number of total bytes
 */
void ChostModelColumns::add_row(Glib::RefPtr<Gtk::ListStore> m_refTreeModel, IPv6_addr IP, unsigned int graphlet, unsigned int flIdx, unsigned int flows,
      unsigned int uniflows, unsigned int protos, unsigned int packets, uint64_t bytes) {
	Gtk::TreeModel::Row row = *(m_refTreeModel->append());
	row[m_col_graphlet] = graphlet;
	row[m_col_IP] = IP.toString();
	row[m_col_flIdx] = flIdx;
	row[m_col_flows] = flows;
	row[m_col_uniflows] = uniflows;
	row[m_col_protos] = protos;
	row[m_col_packets] = packets;
	row[m_col_bytes] = bytes;
}

/**
 *	Constructor acting upon given file name:
 *
 *	"*.dot" : transform into gif and display
 *	"*.gif", "*.png": just display
 *	"*.hpg" : show metadata in table form inside of main window
 *
 *	\param dotFilename Name of input file
 */
CGraphicsArea::CGraphicsArea(std::string dotFilename) :
	graphlet(dotFilename) {
	Glib::RefPtr<Gdk::Screen> screen = Gdk::Screen::get_default();
	int screen_width = screen->get_width();
	desktop_screensize_x = screen_width - XMARGIN;
	int screen_height = screen->get_height();
	desktop_screensize_y = screen_height - YMARGIN;
}

/**
 *	Display graphics data upon event.
 *
 *	\param event Triggering event (currently not used)
 */
bool CGraphicsArea::on_expose_event(GdkEventExpose* event) {
	window = get_window();
	if (window) {
		this->add_events(Gdk::BUTTON_PRESS_MASK | Gdk::BUTTON_RELEASE_MASK);

		context = window->create_cairo_context();
		context->set_line_width(1);
		context->translate(offset_horizontal, offset_vertical);

		set_background(graphlet.getGraphColor()); // draw a white background

		set_color(HAPGraphlet::color_t::getBlack()); // black is always a good start
		HAPGraphlet::const_texts_iterator tit, tit_end;
		for (tie(tit, tit_end) = graphlet.getEdgeTextsIterators(); tit != tit_end; tit++) {
			draw_text(tit->second.position.x, tit->second.position.y, tit->second.width, tit->second.textpos, tit->second.fontsize, tit->second.text, tit->second.font);
		}

		for (tie(tit, tit_end) = graphlet.getVertexTextsIterators(); tit != tit_end; tit++) {
			draw_text(tit->second.position.x, tit->second.position.y, tit->second.width, tit->second.textpos, tit->second.fontsize, tit->second.text, tit->second.font);
		}

		HAPGraphlet::const_arrows_iterator ait, ait_end;
		for (tie(ait, ait_end) = graphlet.getEdgeArrowsIterators(); ait != ait_end; ait++) {
			draw_polygon(ait->second.curvePoints, ait->second.color, ait->second.style);
		}

		HAPGraphlet::const_edges_iterator eit, eit_end;
		for (tie(eit, eit_end) = graphlet.getEdgesIterators(); eit != eit_end; eit++) {
			draw_bspline(eit->curvePoints, eit->color, eit->linewidth);
		}

		const set<HAPGraphlet::const_edges_iterator> & hset = graphlet.getHighlightedEdges();
		for (set<HAPGraphlet::const_edges_iterator>::const_iterator ceit = hset.begin(); ceit != hset.end(); ceit++) {
			draw_bspline((**ceit).curvePoints, (**ceit).color, (**ceit).linewidth * 4);
		}

		HAPGraphlet::const_vertices_iterator vit, vit_end;
		for (tie(vit, vit_end) = graphlet.getVerticesIterators(); vit != vit_end; vit++) {
			if (vit->shape == HAPGraphlet::ellipse)
				draw_ellipse(vit->curvePoints, vit->color, vit->style, vit->linewidth);
			if (vit->shape == HAPGraphlet::box)
				draw_polygon(vit->curvePoints, vit->color, vit->style);
			else if (vit->shape == HAPGraphlet::plaintext) {
				// do nothing special
			}
		}
	}
	return true;
}

/**
 *	Receives mouse button clicks
 *
 *	\param event Triggering event
 */
bool CGraphicsArea::on_button_release_event(GdkEventButton* event) {
	if (graphlet.lookupElementAtPosition(event->x - offset_horizontal, graphlet.getGraphHeight() - event->y + offset_vertical)) {
		if (graphlet.getLastResultType() == HAPGraphlet::resultType_ip) {
			cout << graphlet.getLastIP() << endl;
			signal_newLocalIP.emit(graphlet.getLastIP());
		} else if (graphlet.getLastResultType() == HAPGraphlet::resultType_rolnum) {
			cout << "New Role Number: " << graphlet.getLastRolnum() << endl;
			signal_newRolnum.emit(graphlet.getLastRolnum());
		} else if (graphlet.getLastResultType() == HAPGraphlet::resultType_edge) {
			if (graphlet.isHighlightedEdge(graphlet.getLastEdge()))
				graphlet.delHighlightedEdge(graphlet.getLastEdge());
			else
				graphlet.addHighlightedEdge(graphlet.getLastEdge());
			gdk_window_invalidate_rect(window->gobj(), NULL, true); // Gdk::Window::invalidate is not available under Debian Lenny
		} else {
			cout << "Type: " << graphlet.getLastResultType() << endl;
		}
	}
	return true;
}

/**
 *	Get graphics oversize info.
 *
 *	\return True if graphlet display exceeds screen limits.
 */
bool CGraphicsArea::is_oversize(void) {
	return graphlet.getGraphWidth() > desktop_screensize_x || graphlet.getGraphHeight() > desktop_screensize_y;
}

/**
 *	Get the drawing color of the CGraphicsArea.
 *
 *	\param red value of the red part
 *	\param green value of the green part
 *	\param blue value of the blue part
 */
void CGraphicsArea::set_color(double red, double green, double blue) {
	context->set_source_rgb(red, green, blue);
}

/**
 *	Get the drawing color of the CGraphicsArea.
 *
 *	\param color Array of 3 doubles (red, green, blue)
 */
void CGraphicsArea::set_color(HAPGraphlet::color_t color) {
	context->set_source_rgb(color[0], color[1], color[2]);
}

/**
 *	Draw the background of the CGraphicsArea. Has to be called before anything else gets drawn.
 *
 *	\param color Array of 3 doubles (red, green, blue)
 */
void CGraphicsArea::set_background(HAPGraphlet::color_t color) {
	std::vector<HAPGraphlet::pos<int> > posVec;
	posVec.push_back(HAPGraphlet::pos<int>(0, 0));
	posVec.push_back(HAPGraphlet::pos<int>(graphlet.getGraphWidth(), 0));
	posVec.push_back(HAPGraphlet::pos<int>(graphlet.getGraphWidth(), graphlet.getGraphHeight()));
	posVec.push_back(HAPGraphlet::pos<int>(0, graphlet.getGraphHeight()));
	draw_polygon(posVec, color, HAPGraphlet::solid, 1);
}

/**
 *	Draws a spline.
 *
 * \param points Vector with x/y coordinates of the line
 *	\param color Array of 3 doubles (red, green, blue)
 *	\param int Width of the line
 */
void CGraphicsArea::draw_bspline(std::vector<HAPGraphlet::pos<int> > points, HAPGraphlet::color_t color, int linewidth) {
	assert(points.size() % 3 == 1);
	context->save();
	context->set_line_width(linewidth);
	set_color(color);
	context->move_to(points[0].x, graphlet.getGraphHeight() - points[0].y);
	for (unsigned int i = 3; i < points.size(); i += 3) {
		context->curve_to(points[i - 2].x, graphlet.getGraphHeight() - points[i - 2].y, points[i - 1].x, graphlet.getGraphHeight() - points[i - 1].y,
		      points[i].x, graphlet.getGraphHeight() - points[i].y);
	}
	context->stroke();
	context->restore();
}

/**
 *	Draws a text.
 *
 * \param x X coordinate in pixels
 * \param y Y coordinate in pixels
 * \param width How long a text is in pixels
 * \param tpos Text position (currently we do not use this information but just assume it is centered)
 *	\param fontsize Size of the font in pixels
 *	\param text Text to draw
 *	\param font Font to use
 */
void CGraphicsArea::draw_text(double x, double y, double width, HAPGraphlet::textpos_t tpos, double fontsize, const std::string & text, const std::string & font) {
	context->save();
	context->move_to((int) (x - width / 2), graphlet.getGraphHeight() - y);
	context->select_font_face(font, Cairo::FONT_SLANT_NORMAL, Cairo::FONT_WEIGHT_NORMAL);
	context->set_font_size(fontsize);
	context->show_text(text);
	context->stroke();
	context->restore();
}

/**
 *	Draws an ellipse.
 *
 * \param points Vector with x/y coordinates of the line
 *	\param color Array of 3 doubles (red, green, blue)
 *	\param HAPGraphlet::style_t Style of the ellipse
 *	\param linewidth Width of the border
 */
void CGraphicsArea::draw_ellipse(const std::vector<HAPGraphlet::pos<int> > & points, HAPGraphlet::color_t color, HAPGraphlet::style_t style, int linewidth) {
	assert(points.size() == 2);
	//	cout  << "draw_ellipse with color " << color << " and linewidth " << linewidth << " at "
	//			<< points[0].x << "/" << graphlet.getHeight() - points[0].y
	//			<< " with width = " << points[1].x << " an height = " << points[1].y << endl;
	context->save();
	context->set_line_width(linewidth);
	set_color(color);
	context->translate(points[0].x, graphlet.getGraphHeight() - points[0].y);
	context->scale(points[1].x, points[1].y);
	context->begin_new_sub_path();
	context->arc(0, 0, 1, 0, 2 * M_PI);
	context->close_path();
	context->restore();
	context->stroke();
}

/**
 *	Draws a circle.
 *
 * \param x X coordinate in pixels
 * \param y Y coordinate in pixels
 *	\param r Radius in pixels
 *	\param linewidth Width of the border
 */
void CGraphicsArea::draw_circle(double x, double y, double r, int linewidth) {
	context->save();
	context->set_line_width(linewidth);
	context->begin_new_sub_path();
	context->arc(x, y, r, 0, 2 * M_PI);
	context->close_path();
	context->stroke();
	context->restore();
}

/**
 *	Draws a polygon.
 *
 * \param points Vector with x/y coordinates of the polygon
 *	\param color Array of 3 doubles (red, green, blue)
 *	\param HAPGraphlet::style_t Style of the ellipse
 *	\param linewidth Width of the border
 */
void CGraphicsArea::draw_polygon(const std::vector<HAPGraphlet::pos<int> > & points, HAPGraphlet::color_t color, HAPGraphlet::style_t style, int linewidth) {
	assert(points.size() >= 3);
	context->save();
	set_color(color);
	context->set_line_width(linewidth);
	context->begin_new_sub_path();
	context->move_to(points[0].x, graphlet.getGraphHeight() - points[0].y);
	for (vector<HAPGraphlet::pos<int> >::const_iterator it = points.begin() + 1; it != points.end(); it++) {
		context->line_to(it->x, graphlet.getGraphHeight() - it->y);
	}
	context->close_path();
	if (style == HAPGraphlet::solid)
		context->fill_preserve();
	context->stroke();
	context->restore();
}

/**
 *	Get width of graph
 *
 * \param int Width of this graph
 */
int CGraphicsArea::get_width() {
	return graphlet.getGraphWidth() + 2 * offset_horizontal;
}

/**
 *	Get height of graph
 *
 * \param int Height of this graph
 */
int CGraphicsArea::get_height() {
	return graphlet.getGraphHeight() + 2 * offset_vertical;
}
