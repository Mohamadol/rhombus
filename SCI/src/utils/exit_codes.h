#ifndef SCI_EXIT_CODES_H
#define SCI_EXIT_CODES_H

#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <unistd.h>

namespace sci {

enum ExitCode {
  EXIT_BIND_LISTEN_FAILURE = 1,
  EXIT_CONNECT_TIMEOUT     = 2,
  EXIT_CONNECTION_LOST     = 3,
  EXIT_FATAL_SIGNAL        = 4,
};

inline void fatal_signal_handler(int sig) {
  const char *name = "unknown";
  switch (sig) {
    case SIGSEGV: name = "segmentation fault (SIGSEGV)"; break;
    case SIGABRT: name = "aborted (SIGABRT)"; break;
    case SIGBUS:  name = "bus error (SIGBUS)"; break;
    case SIGFPE:  name = "floating point exception (SIGFPE)"; break;
    case SIGPIPE: name = "broken pipe (SIGPIPE)"; break;
  }
  fprintf(stderr, "[error] process terminated by signal: %s\n"
                  "[error] --> status-code: %d\n", name, EXIT_FATAL_SIGNAL);
  _exit(EXIT_FATAL_SIGNAL);
}

inline void install_error_handlers() {
  signal(SIGSEGV, fatal_signal_handler);
  signal(SIGABRT, fatal_signal_handler);
  signal(SIGBUS,  fatal_signal_handler);
  signal(SIGFPE,  fatal_signal_handler);
  signal(SIGPIPE, fatal_signal_handler);
}

} // namespace sci
#endif // SCI_EXIT_CODES_H
