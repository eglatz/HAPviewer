/**
 *	\file HAPGraphlet.cpp
 *	\brief Reads a DOT Graph into memory and allows easy access to it
 */
#include <string>
#include <sstream>
#include <iostream>
#include <utility>
#include <fstream>
#include <sstream>
#include <vector>
#include <limits>
#include <gvc.h>
#include <stdint.h>

//Include the BGL/Graphviz stuff from boost
#include <boost/graph/graphviz.hpp>
#include <boost/graph/iteration_macros.hpp>

#include "HAPGraphlet.h"
#include "IPv6_addr.h"
#include "gutil.h"

using namespace std;
using namespace boost;

/**
 * Constructor
 *
 * @param dotFilename DOT file to read in memory
 *
 * \exception std::string Errormessage
 */
HAPGraphlet::HAPGraphlet(std::string & dotFilename) :
	graph_graphHeight(-1), graph_graphWidth(-1), lastResultType(resultType_none) {
	// Sanity check for empty file
	if (util::getFileSize(dotFilename) == 0) {
		string errtext = "empty file.\n";
		cerr << "ERROR: " << errtext;
		throw errtext;
	}

	size_t pos = dotFilename.rfind(".dot");
	if (pos != string::npos) {
		// Check if found string is really at end of filename
		if (pos != (dotFilename.size() - 4)) {
			cout << "Filename contains \"*.dot\", but not at its end.\n";
			throw "This is not a dot file";
		}
	}

	string xdotFilename = dotFilename + ".xdot";

	try {
		prepareXDot(dotFilename, xdotFilename);
	}
	catch(...) {
		stringstream error;
		error << "Could not render \"" << dotFilename << "\" to a xdot file." << endl;
		throw error.str();
	}
	try {
		std::ifstream xdotInpuStream(xdotFilename.c_str());
		loadXDOT(xdotInpuStream);
	}
	catch(...) {
		stringstream error;
		error << "Could not load \"" << xdotFilename << "\".";
		throw error.str();
	}
}

/**
 * Transfer the DOT file to a XDOT file (does the layout)
 *
 * @param dotFilename Input DOT file
 * @param xdotFilename Resulting XDOT file
 *
 * @exception std::string Errormessage
 */
void HAPGraphlet::prepareXDot(const std::string & dotFilename, const std::string & xdotFilename) {
	GVC_t *gvc;
	graph_t *g;
	FILE *fpin;

	gvc = gvContext();

	fpin = util::openFile(dotFilename.c_str(), "r");

	g = agread(fpin);
	util::closeFile(fpin);

	if(g == NULL) {
		stringstream error;
		error << dotFilename << " is not a usable dot file";
		throw error.str();
	}

	gvLayout(gvc, g, (char *) "dot");
	if(gvc == NULL) {
		stringstream error;
		error << dotFilename << " is not a usable dot file";
		throw error.str();
	}
	gvRenderFilename(gvc, g, (char *) "xdot", (char *) xdotFilename.c_str());
	gvFreeLayout(gvc, g);
	agclose(g);
}

/**
 *	Transform graph data given in dot language into displayable graphics data.
 *	This function makes use of the Graphviz and BGL (Boost) library.
 *
 *	\param xdotFilestream Filestream of file containing a DOT graph
 *
 *	\exception std::string Error message
 */
void HAPGraphlet::loadXDOT(std::ifstream & xdotFilestream) {
	// set up all the properties for the edges and nodes. Stored as member variable
	// to save us from calling boost::get_property for almost all of them

	vertices_name = boost::get(vertex_name, graph);
	dp.property("node_id", vertices_name);

	vertices_url = boost::get(vertex_url_t(), graph);
	dp.property("URL", vertices_url);

	vertices_fontsize = boost::get(vertex_fontsize_t(), graph);
	dp.property("fontsize", vertices_fontsize);

	vertices_label = boost::get(vertex_label_t(), graph);
	dp.property("label", vertices_label);

	vertices_draw = boost::get(vertex_draw_t(), graph);
	dp.property("_draw_", vertices_draw);

	vertices_shape = boost::get(vertex_shape_t(), graph);
	dp.property("shape", vertices_shape);

	vertices_ldraw = boost::get(vertex_ldraw_t(), graph);
	dp.property("_ldraw_", vertices_ldraw);

	vertices_height = boost::get(vertex_height_t(), graph);
	dp.property("height", vertices_height);

	vertices_width = boost::get(vertex_width_t(), graph);
	dp.property("width", vertices_width);

	vertices_pos = boost::get(vertex_pos_t(), graph);
	dp.property("pos", vertices_pos);

	vertices_style = boost::get(vertex_style_t(), graph);
	dp.property("style", vertices_style);

	vertices_rolnum = boost::get(vertex_rolnum_t(), graph);
	dp.property("rolnum", vertices_rolnum);

	vertices_ip = boost::get(vertex_ip_t(), graph);
	dp.property("ip", vertices_ip);

	vertices_fontname = boost::get(vertex_fontname_t(), graph);
	dp.property("fontname", vertices_fontname);

	edges_color = boost::get(edge_color_t(), graph);
	dp.property("color", edges_color);

	edges_dir = get(edge_dir_t(), graph);
	dp.property("dir", edges_dir);

	edges_label = boost::get(edge_label_t(), graph);
	dp.property("label", edges_label);

	edges_style = boost::get(edge_style_t(), graph);
	dp.property("style", edges_style);

	edges_draw = boost::get(edge_draw_t(), graph);
	dp.property("_draw_", edges_draw);

	edges_pos = boost::get(edge_pos_t(), graph);
	dp.property("pos", edges_pos);

	edges_hdraw = boost::get(edge_hdraw_t(), graph);
	dp.property("_hdraw_", edges_hdraw);

	edges_ldraw = boost::get(edge_ldraw_t(), graph);
	dp.property("_ldraw_", edges_ldraw);

	edges_tdraw = boost::get(edge_tdraw_t(), graph);
	dp.property("_tdraw_", edges_tdraw);

	edges_lp = boost::get(edge_lp_t(), graph);
	dp.property("lp", edges_lp);

	// Use ref_property_map to turn a graph property into a property map
	boost::ref_property_map<boost_graph_t*, std::string> gname(boost::get_property(graph, graph_name));
	boost::ref_property_map<boost_graph_t*, std::string> grankdir(boost::get_property(graph, graph_rankdir_t()));
	boost::ref_property_map<boost_graph_t*, std::string> gdraw(boost::get_property(graph, graph_draw_t()));
	boost::ref_property_map<boost_graph_t*, std::string> gbb(boost::get_property(graph, graph_bb_t()));
	boost::ref_property_map<boost_graph_t*, std::string> gxdotversion(boost::get_property(graph, graph_xdotversion_t()));
	boost::ref_property_map<boost_graph_t*, std::string> gshape(boost::get_property(graph, graph_shape_t()));
	boost::ref_property_map<boost_graph_t*, std::string> gstyle(boost::get_property(graph, graph_style_t()));
	boost::ref_property_map<boost_graph_t*, std::string> grank(boost::get_property(graph, graph_rank_t()));

	dp.property("name", gname);
	dp.property("rankdir", grankdir);
	dp.property("_draw_", gdraw);
	dp.property("bb", gbb);
	dp.property("xdotversion", gxdotversion);
	dp.property("shape", gshape);
	dp.property("style", gstyle);
	dp.property("rank", grank);

	// this is needed, since some (all?) version of boost print out the whole graph to std::cerr in read_graphviz()
	std::streambuf * cerr_save = std::cerr.rdbuf();
	std::stringstream sinkStreambuf;
	std::cerr.rdbuf(sinkStreambuf.rdbuf());

	try {
		read_graphviz(xdotFilestream, graph, dp);
	}
	catch(std::exception &e) {
		std::cerr.rdbuf(cerr_save);
		std::cerr << "Error while parsing xdot file with BGL: " <<  e.what() << endl;
		throw e;
	}

	// restore std::cerr
	std::cerr.rdbuf(cerr_save);

	prepareVertices();
	prepareEdges();
	prepareGraph();
}

/**
 * Read and parse all vertex attributes we need
 */
void HAPGraphlet::prepareVertices() {
	graph_vertex_iterator vit, vit_end;

	for (tie(vit, vit_end) = vertices(graph); vit != vit_end; vit++) {
		element_vertex newvertex;

		// get name
		newvertex.name = vertices_name[*vit];

		// get label
		if (vertices_label[*vit] != "\\N" && vertices_label[*vit] != "")
			newvertex.label = vertices_label[*vit];
		else {
			cerr << "Node " << newvertex.name << " does not have a label" << endl;
			assert(false);
		}

		// get rolenum
		newvertex.rolnum = vertices_rolnum[*vit];

		// get IP
		newvertex.IP_string = vertices_ip[*vit];

		// set shape of vertex
		if (vertices_shape[*vit] == "plaintext")
			newvertex.shape = plaintext;
		else if (vertices_shape[*vit] == "ellipse")
			newvertex.shape = ellipse;
		else if (vertices_shape[*vit] == "box")
			newvertex.shape = box;
		else {
			cerr << "Shape is not supported: \"" << vertices_shape[*vit] << "\"" << endl;
			exit(1);
		}

		// parse information of the draw attribute of vertex
		{
			stringstream ss(vertices_draw[*vit]);
			char t = 'X';
			while (!ss.eof() && ss.good() && (vertices_draw[*vit].size() - ss.tellg()) > 3) {
				ss >> t;
				switch (t) {
					case 'c':
						newvertex.color = parse_PenColor(ss);
						break;
					case 'e':
						parse_VertexAttributes(newvertex, ss);
						break;
					case 'p':
						newvertex.curvePoints = parse_BPoints(ss);
						break;
					case 'S':
						parse_Style(newvertex, ss);
						break;
					default:
						cerr << "Can not handle this vertex draw-attribute: " << t << endl;
						exit(1);
				}
				t = 'Y';
			}
		}

		verticesVector.push_back(newvertex);

		// parse information of the ldraw attribute of vertex
		{
			stringstream ss(vertices_ldraw[*vit]);
			element_text newtext;
			char t = 'X';
			while (!ss.eof() && (vertices_ldraw[*vit].size() - ss.tellg()) > 2) {
				ss >> t;
				switch (t) {
					case 'F':
						parse_Font(newtext, ss);
						break;
					case 'c':
						newtext.color = parse_PenColor(ss);
						break;
					case 'T':
						parse_TextAttributes(newtext, ss);
						break;
					default:
						cerr << "Can not handle this vertex vertices_ldraw-attribute: " << t;
						if(!newtext.text.empty())
							cout << " (Text: " << newtext.text << ")";
						cout << endl;
						exit(1);
				}
				t = 'Y';
			}
			if (!newtext.text.empty())
				vertexTextMap[verticesVector.size() - 1] = newtext;
		}
	}
}

/**
 * Read and parse all edges attributes we need
 */
void HAPGraphlet::prepareEdges() {
	graph_edge_iterator eit, eit_end;

	for (tie(eit, eit_end) = edges(graph); eit != eit_end; eit++) {
		element_edge newedge;

		// get label
		if (edges_label[*eit] != "\\N" && edges_label[*eit] != "")
			newedge.label = edges_label[*eit];

		// get information of the draw attribute of edge
		{
			stringstream ss(edges_draw[*eit]);
			char t = 'X';
			while (!ss.eof() && ss.good() && (edges_draw[*eit].size() - ss.tellg()) > 2) {
				ss >> t;
				switch (t) {
					case 'c':
						newedge.color = parse_PenColor(ss);
						break;
					case 'B':
						newedge.curvePoints = parse_BPoints(ss);
						break;
					case 'S':
						parse_Style(newedge, ss);
						break;
					default:
						cerr << "Can not handle this edge draw-attribute: " << t << endl;
						exit(1);
				}
				t = 'Y';
			}
			if(t != 'X')
				edgesVector.push_back(newedge);
		}

		// get information of the ldraw attribute of edge
		{
			stringstream ss(edges_ldraw[*eit]);
			element_text newtext;
			char t = 'X';
			while (!ss.eof() && (edges_ldraw[*eit].size() - ss.tellg()) > 2) {
				ss >> t;
				switch (t) {
					case 'F':
						parse_Font(newtext, ss);
						break;
					case 'c':
						newtext.color = parse_PenColor(ss);
						break;
					case 'T':
						parse_TextAttributes(newtext, ss);
						break;
					default:
						cerr << "Can not handle this edge ldraw-attribute: " << t << endl;
						exit(1);
				}
				t = 'Y';
			}
			if(t != 'X')
				edgeTextMap[edgesVector.size() - 1] = newtext;
		}

		// get information of the edges_tdraw attribute of edge
		{
			stringstream ss(edges_tdraw[*eit]);
			element_arrow newarrow;

			char t = 'X';
			while (!ss.eof() && (edges_tdraw[*eit].size() - ss.tellg()) > 2) {
				ss >> t;
				switch (t) {
					case 'c':
					case 'C':
						newarrow.color = parse_PenColor(ss);
						break;
					case 'S':
						parse_Style(newarrow, ss);
						break;
					case 'P':
						newarrow.curvePoints = parse_BPoints(ss);
						break;
					default:
						cerr << "Can not handle this edge edges_tdraw-attribute: " << t << endl;
						exit(1);
				}
				t = 'Y';
			}
			if (newarrow.curvePoints.size() == 3)
				edgeArrowsMap.insert(std::make_pair(edgesVector.size() - 1, newarrow));
		}

		// get information of the hdraw attribute of edge
		{
			stringstream ss(edges_hdraw[*eit]);
			element_arrow newarrow;

			char t = 'X';
			while (!ss.eof() && (edges_hdraw[*eit].size() - ss.tellg()) > 2) {
				ss >> t;
				switch (t) {
					case 'c':
					case 'C':
						newarrow.color = parse_PenColor(ss);
						break;
					case 'S':
						parse_Style(newarrow, ss);
						break;
					case 'P':
						newarrow.curvePoints = parse_BPoints(ss);
						break;
					default:
						cerr << "Cant handle this edge edges_hdraw-attribute: " << t << endl;
						exit(1);
				}
				t = 'X';
			}
			if (newarrow.curvePoints.size() == 3)
				edgeArrowsMap.insert(std::make_pair(edgesVector.size() - 1, newarrow));
		}
	}
}

/**
 * Read and parse all graph attributes we need
 * @exception string Error message
 */
void HAPGraphlet::prepareGraph() {
	boost::ref_property_map<boost_graph_t*, std::string> graph_bb(boost::get_property(graph, graph_bb_t()));
	stringstream ss(graph_bb[boost::ref_property_map<boost_graph_t*, std::string>::key_type()]);
	ss.ignore(4);
	ss >> graph_graphWidth;
	ss.ignore(1);
	ss >> graph_graphHeight;
	graph_color = HAPGraphlet::color_t::getWhite(); // for now we just assume white is what we want
	if(graph_graphWidth != -1 && graph_graphHeight != -1) {
		cout << "Graph width: " << graph_graphWidth << ", Graph height: " << graph_graphHeight << endl;
	}
	else {
		throw string("It looks like you have an old version of Boost (BGL) installed. Please upgrade to Boost version 1.40 or newer.");
	}
}

/**
 * Extract a number of a stringstream
 * @param ss Stringstream to read from
 * @return int Number
 */
int HAPGraphlet::parse_NumberOfFollowingBytes(std::stringstream & ss) {
	int numberOfBytes;
	ss >> numberOfBytes;
	return numberOfBytes;
}

/**
 * Remove up to two chars from the supplied stringstream
 * @param ss Stringstream to consume up to 2 chars
 */
void HAPGraphlet::parse_consumeTrailingGarbage(std::stringstream & ss) {
	ss.ignore(2, '-'); // one space, followed by a dash
}

/**
 * Return a text of variable length
 * @param ss Stringstream to read from
 * @param length Lenght of text
 * @return std::string Text as string object
 */
std::string HAPGraphlet::parse_VarText(std::stringstream & ss, int length) {
	char buf[length + 1];
	buf[length] = '\0';
	ss.read(buf, length);
	return string(buf);
}

/**
 * Extract color
 * @param ss Stringstream to read from
 * @return HAPGraphlet::color_t Color
 *
 * @exception std::string Errormessage
 */
HAPGraphlet::color_t HAPGraphlet::parse_PenColor(std::stringstream & ss) {
	int bytes = parse_NumberOfFollowingBytes(ss);
	parse_consumeTrailingGarbage(ss);
	string color(parse_VarText(ss, bytes));

	if (color.find("#000000") != string::npos || color == "black")
		return color_t::getBlack();
	else if (color.find("#00ff00") != string::npos || color == "green")
		return color_t::getGreen();
	else if (color.find("#ff0000") != string::npos || color == "red")
		return color_t::getRed();
	else {
		string errormsg = color + " is an unknown color";
		throw errormsg;
	}
}

/**
 * Extract the x/y value of a vertex point
 * @param vertex Element to modify
 * @param ss Stringstream to read from
 */
void HAPGraphlet::parse_VertexAttributes(element_vertex & vertex, std::stringstream & ss) {
	// FIXME: ugly but easy
	vertex.curvePoints.resize(2);
	ss >> vertex.curvePoints[0].x;
	ss >> vertex.curvePoints[0].y;
	ss >> vertex.curvePoints[1].x;
	ss >> vertex.curvePoints[1].y;
}

/**
 * Extract the x/y value of a text, its position, width and the text itself
 * @param text Element to modifiy
 * @param ss Stringstream to read from
 */
void HAPGraphlet::parse_TextAttributes(element_text & text, std::stringstream & ss) {
	int tmp;
	ss >> text.position.x;
	ss >> text.position.y;

	ss >> tmp;
	switch (tmp) {
		case -1:
			text.textpos = left;
			break;
		case 0:
			text.textpos = centered;
			break;
		case 1:
			text.textpos = right;
			break;
		default:
			cerr << "There is something wrong with this text position: " << tmp << endl;
			exit(1);
	}
	ss >> text.width;
	ss >> tmp;
	parse_consumeTrailingGarbage(ss);
	text.text = parse_VarText(ss, tmp);
}

/**
 * Extract information about the font. Currently just the fontsize gets used.
 * @param text Element to update.
 * @param ss Stringstream to read from
 */
void HAPGraphlet::parse_Font(element_text & text, std::stringstream & ss) {
	ss >> text.fontsize;
	int bytes = parse_NumberOfFollowingBytes(ss);
	parse_consumeTrailingGarbage(ss);
	text.font = parse_VarText(ss, bytes); // throw away the information about the font
}

/**
 * Extract the points of a bezier curve.
 * @param ss Stringstream to read from
 * @return std::vector<HAPGraphlet::pos<int> Vector of extraced points
 */
std::vector<HAPGraphlet::pos<int> > HAPGraphlet::parse_BPoints(std::stringstream & ss) {
	vector<pos<int> > vec;
	int n = 0;
	ss >> n;
	for (int i = 0; i < n; i++) {
		pos<int> tmpPos;
		ss >> tmpPos.x;
		ss >> tmpPos.y;
		vec.push_back(tmpPos);
	}
	return vec;
}
/**
 * Extract information in the style tag
 * @param elem Element to update
 * @param ss Stringstream to read from
 */
void HAPGraphlet::parse_Style(element_withline & elem, std::stringstream & ss) {
	int varLen = 0;
	ss >> varLen;
	parse_consumeTrailingGarbage(ss);
	string stylestr(parse_VarText(ss, varLen));
	if (stylestr == "solid")
		elem.style = HAPGraphlet::solid;
	else if (stylestr == "bold")
		elem.style = HAPGraphlet::bold;
	else if (stylestr.find("setlinewidth") != string::npos) {
		stringstream setlinewidthss(stylestr);
		setlinewidthss.ignore(stylestr.size(), '(');
		setlinewidthss >> elem.linewidth;
		setlinewidthss.ignore(stylestr.size(), ')');
	} else {
		cerr << "Unknown style: " << hex << "0x" << stylestr << endl;
		exit(1);
	}
}

/**
 * Looks up the element at a specific x/y point. If somethings gets hit, lastResultType gets updated.
 * @param x X value
 * @param y Y value
 * @return bool True if something got hit
 */
bool HAPGraphlet::lookupElementAtPosition(int x, int y) {
	for (const_vertices_iterator vit = verticesVector.begin(); vit != verticesVector.end(); vit++) {
		if (vit->collides(pos<int> (x, y), 3)) {
			// triggers ONLY if clicked on a remote IPs
			if ((vit->shape == ellipse) && (vit->name.find("k5_") != string::npos)) {
				lastIP = vit->IP_string;
				lastResultType = resultType_ip;
				return true;
			}
			// triggers ONLY if clicked on a summary node
			if (vit->shape == box) {
				cout << "new latRolnum: " << lastRolnum << endl;
				lastRolnum = vit->rolnum;
				lastResultType = resultType_rolnum;
				return true;
			}
		}
	}

	for (const_edges_iterator eit = edgesVector.begin(); eit != edgesVector.end(); eit++) {
		if (eit->collides(pos<int> (x, y), 3)) {
			lastEdge = eit;
			lastResultType = resultType_edge;
			return true;
		}
	}

	lastResultType = resultType_none;
	return false;
}

/**
 * Returns the color red
 * @return color_t Red color
 */
HAPGraphlet::color_t HAPGraphlet::color_t::getRed() {
	color_t color;
	color[0] = numeric_limits<double>::max();
	color[1] = 0;
	color[2] = 0;
	return color;
}

/**
 * Returns the color green
 * @return color_t Green color
 */
HAPGraphlet::color_t HAPGraphlet::color_t::getGreen() {
	color_t color;
	color[0] = 0;
	color[1] = numeric_limits<double>::max();
	color[2] = 0;
	return color;
}

/**
 * Returns the color blue
 * @return color_t Blue color
 */
HAPGraphlet::color_t HAPGraphlet::color_t::getBlue() {
	color_t color;
	color[0] = 0;
	color[1] = 0;
	color[2] = numeric_limits<double>::max();
	return color;
}

/**
 * Returns the color white
 * @return color_t White color
 */
HAPGraphlet::color_t HAPGraphlet::color_t::getWhite() {
	color_t color;
	std::fill(color.begin(), color.end(), numeric_limits<double>::max());
	return color;
}

/**
 * Returns the color black
 * @return color_t Black color
 */
HAPGraphlet::color_t HAPGraphlet::color_t::getBlack() {
	color_t color;
	std::fill(color.begin(), color.end(), 0);
	return color;
}

/**
 * Decides if a x/y hits this vertex
 * @param point X/Y point
 * @param tolerance How far away is close enough
 * @return bool True if this element got hit/is close enough
 */
bool HAPGraphlet::element_vertex::collides(pos<int> point, double tolerance) const {

	if (shape == ellipse) {
		if ((point.x >= curvePoints[0].x - curvePoints[1].x) && (point.x <= curvePoints[0].x + curvePoints[1].x) && (point.y >= curvePoints[0].y
		      - curvePoints[1].y) && (point.y <= curvePoints[0].y + curvePoints[1].y))
			return true;
	} else if (shape == box) {
		if ((point.x >= curvePoints[2].x) && (point.x <= curvePoints[0].x) && (point.y >= curvePoints[2].y) && (point.y <= curvePoints[0].y))
			return true;
	}
	return false;
}

/**
 * Decides if a x/y hits this edge
 * @param point X/Y point
 * @param tolerance How far away is close enough
 * @return bool True if this element got hit/is close enough
 */
bool HAPGraphlet::element_edge::collides(pos<int> point, double tolerance) const {
	double delta = tolerance / 100.0;
	std::vector<HAPGraphlet::pos<int> > subvec;
	for (unsigned int i = 3; i < curvePoints.size(); i += 3) {
		subvec.clear();
		subvec.push_back(curvePoints[i - 3]);
		subvec.push_back(curvePoints[i - 2]);
		subvec.push_back(curvePoints[i - 1]);
		subvec.push_back(curvePoints[i]);
		for (double d = 0.0; d < 1.0; d += delta) {
			pos<int> p = getPointForT(subvec, d);
			//				cout << "Delta: " << d << ", X=" << p.x << "/Y=" << p.y << endl;
			if (p.isCloseEnough(point, tolerance))
				return true;
		}
	}
	//}
	return false;
}
/**
 * Get the x/y point at a specific part of the spline.
 * This implementation works "good enough", but it would not harm anyone if it would be
 * changed to a non-recursive one
 * @param points Points for this curve
 * @param t Defines which point between the first and the last element (t = 0..1) in points we want to calculate
 * @return HAPGraphlet::pos<int> Requested Point
 */
HAPGraphlet::pos<int> HAPGraphlet::element_edge::getPointForT(const std::vector<pos<int> > & points, double t) const {
	assert(!points.empty());
	if (points.size() == 1)
		return points.front();
	std::vector<pos<int> > newPoints;
	for (unsigned int i = 0; i < points.size() - 1; i++) {
		pos<int> a = points[i];
		pos<int> b = points[i + 1];
		pos<int> res(a.x + (b.x - a.x) * t, a.y + (b.y - a.y) * t);
		newPoints.push_back(res);
	}
	return getPointForT(newPoints, t);
}

/**
 * Tests, if two points are close enought
 * @param point Point
 * @param tolerance Tolerance
 * @return bool True if close enough, otherwise false
 */
template<typename T> bool HAPGraphlet::pos<T>::isCloseEnough(pos<T> point, T tolerance) {
	if (x >= point.x - tolerance && x <= point.x + tolerance && y >= point.y - tolerance && y <= point.y + tolerance)
		return true;
	return false;
}
