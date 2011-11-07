#ifndef HAPGRAPHLET_H_
#define HAPGRAPHLET_H_

#include <map>
#include <iosfwd>
#include <string>
#include <stdint.h>
#include <sstream>
#include <vector>
#include <algorithm>
#include <boost/array.hpp>
#include <boost/noncopyable.hpp>

//Include the BGL/Graphviz stuff from boost
#include <boost/graph/graphviz.hpp>
#include <boost/graph/iteration_macros.hpp>

#include "IPv6_addr.h"

/**
 * \class Reads a dot file into memory and allows various operation on it
 */
class HAPGraphlet: boost::noncopyable {
	public:
	/**
	 * \class Represents a point in 2d (x/y)
	 */
		template<typename T> struct pos {
				T x;
				T y;
				pos(T x, T y) :
					x(x), y(y) {
				}
				;
				pos() {
				}
				;
				bool isCloseEnough(pos<T> point, T tolerance);
		};

	private:
		// This is needed for the Boost/Graphviz stuff
		struct graph_rankdir_t {
				typedef boost::graph_property_tag kind;
		};
		struct graph_rank_t {
				typedef boost::graph_property_tag kind;
		};
		struct graph_draw_t {
				typedef boost::graph_property_tag kind;
		};
		struct graph_bb_t {
				typedef boost::graph_property_tag kind;
		};
		struct graph_xdotversion_t {
				typedef boost::graph_property_tag kind;
		};
		struct graph_shape_t {
				typedef boost::graph_property_tag kind;
		};
		struct graph_style_t {
				typedef boost::graph_property_tag kind;
		};

		struct vertex_url_t {
				typedef boost::vertex_property_tag kind;
		};
		struct vertex_fontsize_t {
				typedef boost::vertex_property_tag kind;
		};
		struct vertex_label_t {
				typedef boost::vertex_property_tag kind;
		};
		struct vertex_shape_t {
				typedef boost::vertex_property_tag kind;
		};
		struct vertex_draw_t {
				typedef boost::vertex_property_tag kind;
		};
		struct vertex_ldraw_t {
				typedef boost::vertex_property_tag kind;
		};
		struct vertex_height_t {
				typedef boost::vertex_property_tag kind;
		};
		struct vertex_width_t {
				typedef boost::vertex_property_tag kind;
		};
		struct vertex_pos_t {
				typedef boost::vertex_property_tag kind;
		};
		struct vertex_style_t {
				typedef boost::vertex_property_tag kind;
		};
		struct vertex_rolnum_t {
				typedef boost::vertex_property_tag kind;
		};
		struct vertex_ip_t {
				typedef boost::vertex_property_tag kind;
		};
		struct vertex_fontname_t {
				typedef boost::vertex_property_tag kind;
		};

		struct edge_dir_t {
				typedef boost::edge_property_tag kind;
		};
		struct edge_label_t {
				typedef boost::edge_property_tag kind;
		};
		struct edge_style_t {
				typedef boost::edge_property_tag kind;
		};
		struct edge_draw_t {
				typedef boost::edge_property_tag kind;
		};
		struct edge_hdraw_t {
				typedef boost::edge_property_tag kind;
		};
		struct edge_ldraw_t {
				typedef boost::edge_property_tag kind;
		};
		struct edge_tdraw_t {
				typedef boost::edge_property_tag kind;
		};
		struct edge_pos_t {
				typedef boost::edge_property_tag kind;
		};
		struct edge_lp_t {
				typedef boost::edge_property_tag kind;
		};

	public:
		// Vertex properties
		typedef boost::property<boost::vertex_name_t, std::string, boost::property<boost::vertex_color_t, std::string, boost::property<vertex_url_t, std::string,
		      boost::property<vertex_fontsize_t, int, boost::property<vertex_label_t, std::string, boost::property<vertex_draw_t, std::string, boost::property<
		            vertex_ldraw_t, std::string, boost::property<vertex_height_t, double, boost::property<vertex_width_t, double, boost::property<vertex_pos_t,
		                  std::string, boost::property<vertex_style_t, std::string, boost::property<vertex_shape_t, std::string, boost::property<vertex_rolnum_t,
		                        signed int, boost::property<vertex_ip_t, std::string, boost::property<vertex_fontname_t, std::string> > > > > > > > > > > > > > > vertex_p;

		// Edge properties
		typedef boost::property<boost::edge_color_t, std::string, boost::property<edge_dir_t, std::string, boost::property<edge_label_t, std::string,
		      boost::property<edge_style_t, std::string, boost::property<edge_draw_t, std::string, boost::property<edge_pos_t, std::string, boost::property<
		            edge_hdraw_t, std::string, boost::property<edge_tdraw_t, std::string, boost::property<edge_ldraw_t, std::string, boost::property<edge_lp_t,
		                  std::string> > > > > > > > > > edge_p;

		// Graph properties
		typedef boost::property<boost::graph_name_t, std::string, boost::property<graph_rankdir_t, std::string, boost::property<graph_rank_t, std::string,
		      boost::property<graph_draw_t, std::string, boost::property<graph_bb_t, std::string, boost::property<graph_xdotversion_t, std::string,
		            boost::property<graph_shape_t, std::string, boost::property<graph_style_t, std::string> > > > > > > > graph_p;

		// adjacency_list-based type
		typedef boost::adjacency_list<boost::vecS, boost::vecS, boost::undirectedS, vertex_p, edge_p, graph_p> boost_graph_t;

		/**
		 * \class Stores a color (RGB) 
		 */
		struct color_t: public boost::array<double, 3> {
				/**
				 * Constructor: default constructor
				 */
				color_t() {
					std::fill(begin(), end(), 0.0);
				}
				static color_t getRed();
				static color_t getGreen();
				static color_t getBlue();
				static color_t getWhite();
				static color_t getBlack();
		};

		// There are many more, but that's all we need
		enum shape_t {
			plaintext, ellipse, box
		};
		enum textpos_t {
			centered, left, right
		};
		enum style_t {
			dashed, dotted, solid, invis, bold, // nodes and edges
			filled,
			diagonals,
			rounded
		// nodes only
		};

	private:
		/**
		 * \class Base version of an element in a graph
		 */
		struct element {
				std::string label; ///< Label for this element
				color_t color; ///< Color for this element
				style_t style; ///< Style for this element

				/**
				 * Tests, if two points collides
				 * @param point Point
				 * @param tolerance Tolerance
				 * @return bool True if collides
				 */
				virtual bool collides(pos<int> point, double tolerance) const {
					return false;
				}
		};

		/**
		 * \class Element in a graph, has a linewidth attribute
		 */
		struct element_withline: public element {
				int linewidth; ///< width of line
				/**
				 * Default constructor
				 */
				element_withline() :
					linewidth(1) {
				}
		};

		/**
		 *	\class Edge in a graph
		 */
		struct element_edge: public element_withline {
				virtual bool collides(pos<int> point, double tolerance) const;
				pos<int> getPointForT(const std::vector<pos<int> > & points, double t) const;
				std::vector<pos<int> > curvePoints; ///< A vector of coordinates that define the curve
		};

		/**
		 * \class Vertex in a graph
		 */
		struct element_vertex: public element_withline {
				int width; ///< X position of the text
				int height; ///< Y position of the text
				std::string name; ///< Name of the element
				std::string IP_string; ///< Label/Text of the vertex
				int rolnum; ///< Rolenum of vertex
				shape_t shape; ///< Shape of this vertex
				std::vector<pos<int> > curvePoints; ///< A vector of coordinates that defines the appearance
				virtual bool collides(pos<int> point, double tolerance) const;
		};

		/**
		 * \class Text in a graph
		 */
		struct element_text: public element {
				int width; ///< Length of the rendered text as calculated by graphviz
				double fontsize; ///< Fontsize
				pos<int> position; ///< Baseline point for the text
				textpos_t textpos; ///< Position of text
				std::string text; ///< Text/Label
				std::string font;
				element_text(): width(0), fontsize(0), position(0,0), text(""), font("Arial"){}
		};

		/**
		 * \class Arrow in a graph
		 */
		struct element_arrow: public element_withline {
				std::vector<pos<int> > curvePoints; ///< Shape of the arrow
		};

		int graph_graphHeight; ///< Height of the graph
		int graph_graphWidth; ///< Width of the graph
		color_t graph_color; ///< Color of the graph

		// Construct an empty graph and prepare the dynamic_property_maps.
		boost_graph_t graph; ///< Our graph
		boost::dynamic_properties dp; ///< All the dynamic properties

		boost::property_map<boost_graph_t, boost::vertex_name_t>::type vertices_name;
		boost::property_map<boost_graph_t, vertex_url_t>::type vertices_url;
		boost::property_map<boost_graph_t, vertex_fontsize_t>::type vertices_fontsize;
		boost::property_map<boost_graph_t, vertex_label_t>::type vertices_label;
		boost::property_map<boost_graph_t, vertex_shape_t>::type vertices_shape;
		boost::property_map<boost_graph_t, vertex_draw_t>::type vertices_draw;
		boost::property_map<boost_graph_t, vertex_ldraw_t>::type vertices_ldraw;
		boost::property_map<boost_graph_t, vertex_height_t>::type vertices_height;
		boost::property_map<boost_graph_t, vertex_width_t>::type vertices_width;
		boost::property_map<boost_graph_t, vertex_pos_t>::type vertices_pos;
		boost::property_map<boost_graph_t, vertex_style_t>::type vertices_style;
		boost::property_map<boost_graph_t, vertex_rolnum_t>::type vertices_rolnum;
		boost::property_map<boost_graph_t, vertex_ip_t>::type vertices_ip;
		boost::property_map<boost_graph_t, vertex_fontname_t>::type vertices_fontname;

		boost::property_map<boost_graph_t, boost::edge_color_t>::type edges_color;
		boost::property_map<boost_graph_t, edge_dir_t>::type edges_dir;
		boost::property_map<boost_graph_t, edge_label_t>::type edges_label;
		boost::property_map<boost_graph_t, edge_style_t>::type edges_style;
		boost::property_map<boost_graph_t, edge_draw_t>::type edges_draw;
		boost::property_map<boost_graph_t, edge_pos_t>::type edges_pos;
		boost::property_map<boost_graph_t, edge_hdraw_t>::type edges_hdraw;
		boost::property_map<boost_graph_t, edge_ldraw_t>::type edges_ldraw;
		boost::property_map<boost_graph_t, edge_tdraw_t>::type edges_tdraw;
		boost::property_map<boost_graph_t, edge_lp_t>::type edges_lp;

		typedef boost::graph_traits<boost_graph_t>::vertex_iterator graph_vertex_iterator;
		typedef boost::graph_traits<boost_graph_t>::edge_iterator graph_edge_iterator;

	public:
		typedef std::vector<element_edge> edgesVector_t;
		typedef std::vector<element_vertex> verticesVector_t;
		typedef std::multimap<unsigned int, element_arrow> arrowsVector_t; // there can be more than one arrow per edge
		typedef std::map<unsigned int, element_text> textsVector_t;

	private:
		verticesVector_t verticesVector; ///< Provides access to all vertices attributes
		edgesVector_t edgesVector; ///< Provides access to all edges attributes
		arrowsVector_t edgeArrowsMap; ///< Provides access to all arrows attributes
		textsVector_t edgeTextMap; ///< Provides access to all edgeText attributes
		textsVector_t vertexTextMap; ///< Provides access to all vertexText attributes

	public:
		typedef textsVector_t::const_iterator const_texts_iterator;
		typedef arrowsVector_t::const_iterator const_arrows_iterator;
		typedef edgesVector_t::const_iterator const_edges_iterator;
		typedef verticesVector_t::const_iterator const_vertices_iterator;

		typedef textsVector_t::iterator texts_iterator;
		typedef arrowsVector_t::iterator arrows_iterator;
		typedef edgesVector_t::iterator edges_iterator;
		typedef verticesVector_t::iterator vertices_iterator;

		/**
		 * \enum Used to tell outside object which kind of object got hit last time
		 */
		enum resultType {
			resultType_none, resultType_rolnum, resultType_ip, resultType_edge
		};

		HAPGraphlet(std::string & dotFilename);

		/**
		 * Provides a const iterator to traverse all edgesVector elements
		 * @return A pair of the begin() and end() iterator of edgesVector
		 */
		std::pair<const_edges_iterator, const_edges_iterator> getEdgesIterators() {
			return std::make_pair(edgesVector.begin(), edgesVector.end());
		}

		/**
		 * Provides a const iterator to traverse all verticesVector elements
		 * @return A pair of the begin() and end() iterator of verticesVector
		 */
		std::pair<const_vertices_iterator, const_vertices_iterator> getVerticesIterators() {
			return std::make_pair(verticesVector.begin(), verticesVector.end());
		}

		/**
		 * Provides a const iterator to traverse all arrows elements
		 * @return A pair of the begin() and end() iterator of edgeArrowsMap
		 */
		std::pair<const_arrows_iterator, const_arrows_iterator> getEdgeArrowsIterators() {
			return std::make_pair(edgeArrowsMap.begin(), edgeArrowsMap.end());
		}

		/**
		 * Provides a const iterator to traverse all edgeTexts elements
		 * @return A pair of the begin() and end() iterator of edgeTextMap
		 */
		std::pair<const_texts_iterator, const_texts_iterator> getEdgeTextsIterators() {
			return std::make_pair(edgeTextMap.begin(), edgeTextMap.end());
		}

		/**
		 * Provides a const iterator to traverse all vertexTexts elements
		 * @return A pair of the begin() and end() iterator of vertexTextMap
		 */
		std::pair<const_texts_iterator, const_texts_iterator> getVertexTextsIterators() {
			return std::make_pair(vertexTextMap.begin(), vertexTextMap.end());
		}

		/**
		 * Get graph height
		 * @return int Height
		 */
		int getGraphHeight() {
			return graph_graphHeight;
		}

		/**
		 * Get graph width
		 * @return int Width
		 */
		int getGraphWidth() {
			return graph_graphWidth;
		}

		/**
		 * Get color of graph
		 * @return color_t Color
		 */
		color_t getGraphColor() {
			return graph_color;
		}


		bool lookupElementAtPosition(int x, int y);

		/**
		 * Return the type of the latest result of lookupElementAtPosition()
		 * @return resultType Type of latest result
		 */
		resultType getLastResultType() {
			return lastResultType;
		}

		/**
		 * Return the last hit remote IP
		 * @return IPv6_addr remote IP
		 */
		IPv6_addr getLastIP() {
			return lastIP;
		}

		/**
		 * Return the rolenumber of the last hit vertex
		 * @return
		 */
		int getLastRolnum() {
			return lastRolnum;
		}

		/**
		 * Return an iterator to the last hit edge
		 * @return
		 */
		edgesVector_t::const_iterator getLastEdge() {
			return lastEdge;
		}

		std::set<const_edges_iterator> highlighted_edges; ///< Contains references to all highlighted edges

		/**
		 * Add a new highlighted edge
		 * @param e Edge to highlight
		 */
		void addHighlightedEdge(const_edges_iterator e) {
			highlighted_edges.insert(e);
		}

		/**
		 * Look up if edge is already highlighted
		 * @param e Edge in question
		 * @return bool True if this edge is already highlighted
		 */
		bool isHighlightedEdge(const_edges_iterator e) {
			return highlighted_edges.find(e) != highlighted_edges.end();
		}

		/**
		 * "un"-highlight an edge
		 * @param e Edge to remove from the highlighted ones
		 */
		void delHighlightedEdge(const_edges_iterator e) {
			highlighted_edges.erase(e);
		}
		/**
		 * Get all highlighted edges at once
		 * @return std::set<const_edges_iterator> Const reference to all the highlighted edges
		 */
		const std::set<const_edges_iterator> & getHighlightedEdges() {
			return highlighted_edges;
		}

	private:
		resultType lastResultType; ///< Latest resulttype
		IPv6_addr lastIP; ///< Latest IP
		int lastRolnum; ///< Latest rolenum
		edgesVector_t::const_iterator lastEdge; ///< latest edge

		void loadXDOT(std::ifstream & xdotFilestream);
		void prepareXDot(const std::string & dotFilename, const std::string & xdotFilename);

		void prepareVertices();
		void prepareEdges();
		void prepareGraph();

		// a few helping functions
		int parse_NumberOfFollowingBytes(std::stringstream & ss);
		void parse_consumeTrailingGarbage(std::stringstream & ss);
		std::string parse_VarText(std::stringstream & ss, int length);

		// handlers for the different attributes
		color_t parse_PenColor(std::stringstream & ss);
		double parse_Fontsize(std::stringstream & ss);
		std::vector<pos<int> > parse_BPoints(std::stringstream & ss);
		void parse_Style(element_withline & elem, std::stringstream & ss);

		// vertices only
		void parse_VertexAttributes(element_vertex & vertex, std::stringstream & ss);

		// text only
		void parse_TextAttributes(element_text & text, std::stringstream & ss);
		void parse_Font(element_text & text, std::stringstream & ss);
};

#endif /* HAPGRAPHLET_H_ */
