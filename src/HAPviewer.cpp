/**
 *
 *	\file HAPviewer.cpp
 *	\brief A handy host application profile graphlet viewer written in GTKMM/C++.
 *	Supports the visualization of graphics files and of graph files
 *	containing graph descriptions in DOT language. Furthermore,
 *	hpg (host profile graphlet) binary files can be loaded and then
 *	browsed through a metadata table. Selected graphlets can be
 *	visualized. 
 */
#include <signal.h>
#if defined(linux) || defined(__linux__)
#include <execinfo.h> // libexecinfo, should be preinstalled everywhere
#include <cxxabi.h> // demangling C++ names
#endif // linux
#include <gtkmm/main.h>
#include <glibmm/thread.h>
#include <giomm.h>
#include <iostream>
#include <string>

#include "gview.h"
#include "mainpage_HAPviewer.h"

using namespace std;

#if defined(linux) || defined(__linux__)
/**
 * Prints a stacktrace
 */
void print_stacktrace() {
	void *array[20];
	size_t size;
	char **messages;

	size = backtrace(array, sizeof(array)/sizeof(void**));
	messages = backtrace_symbols (array, size);

	if(messages != NULL) {
		cout << "Stacktrace:\n";
		for (size_t i = 2; i < size; i++ ) { // do not print out the frame of print_stacktrace and handle_signal
			cerr << i-2 << ": " << messages[i];

			string raw_message(messages[i]);
			size_t begin = raw_message.find("(");	// I hope no library contains a '(' in the path+...
			size_t end = raw_message.rfind("+"); 	// Fingers crossed once again...

			if( begin != string::npos && end != string::npos) {
				int status = -1;
				string message(raw_message.begin()+1 + begin, raw_message.begin() + end);
				char *demangledName = abi::__cxa_demangle(message.c_str(), NULL, NULL, &status);
				if(status == 0) // no error happened
					cerr << ", " << demangledName;
				free(demangledName);
			}
			cerr << "\n";
		}
	}
	else {
		cerr << "Sorry, not even a stacktrace is available." << endl;
	}
	free(messages);

}

/**
 * Handles the signals. Prints out a stacktrace in any case and quits if the signal was anything else than SIGUSR1
 * @param signal
 */
void handle_signal(int signal) {
	if(signal != SIGUSR1) {
		cerr << "Looks like we found a bug.\n";
		print_stacktrace();
		cerr << "Hint: addr2line is a nice tool for translating the addresses above into source code lines." << endl;
		exit(1);
	}
	if(signal == SIGUSR1) {
		print_stacktrace();
	}
}
#endif // linux

int main(int argc, char *argv[]) {
#if defined(linux) || defined(__linux__)
	// set up the signal handlers
	signal(SIGABRT, handle_signal); // for our assertions
	signal(SIGUSR1, handle_signal); // for our debugging
	signal(SIGILL, handle_signal);  // for the real bugs
	signal(SIGSEGV, handle_signal);
#endif // linux

	// Initialize all the libraries used
	Glib::thread_init();
	Gio::init();
	Gtk::Main kit(argc, argv);

	// main view of application
	CView window(argv);

	// Shows the window and returns when it is closed
	Gtk::Main::run(window);

	return 0;
}
