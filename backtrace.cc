////
#include "backtrace.h"
#include <cstring>
#include <cstdlib>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <fcntl.h>
#include <string>
#include <memory>
#include <cxxabi.h>
#include <execinfo.h>

const char kMangledSymbolPrefix[] = "_Z";
const char kSymbolCharacters[] =
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_";
///
void DemangleInternal(std::string &symbol) {
  std::string::size_type search_from = 0;
  while (search_from < symbol.size()) {
    // Look for the start of a mangled symbol from search_from
    std::string::size_type mangled_start =
        symbol.find(kMangledSymbolPrefix, search_from);
    if (mangled_start == std::string::npos) {
      break; // Mangled symbol not found
    }
    // Look for the end of the mangled symbol
    std::string::size_type mangled_end =
        symbol.find_first_not_of(kSymbolCharacters, mangled_start);
    if (mangled_end == std::string::npos) {
      mangled_end = symbol.size();
    }
    std::string mangled_symbol =
        symbol.substr(mangled_start, mangled_end - mangled_start);
    // Try to demangle the mangled symbol candidate
    int status = -4; // some arbitrary value to eliminate the compiler warning
    std::unique_ptr<char, void (*)(void *)> demangled_symbol{
        abi::__cxa_demangle(mangled_symbol.c_str(), nullptr, 0, &status),
        std::free};
    // 0 Demangling is success
    if (0 == status) {
      // Remove the mangled symbol
      symbol.erase(mangled_start, mangled_end - mangled_start);
      // Insert the demangled symbol
      symbol.insert(mangled_start, demangled_symbol.get());
      // Next time, we will start right after the demangled symbol
      search_from = mangled_start + strlen(demangled_symbol.get());
    } else {
      // Failed to demangle. Retry after the "_Z" we just found
      search_from = mangled_start + 2;
    }
  }
}

/// http://www.unix.com/man-page/freebsd/3/backtrace_symbols_fd/ BSD Compatible
void symbolizetrace(int sig) {
  void *addresses[1024];
  int size = backtrace(addresses, 1024);
  std::string stack_;
  std::unique_ptr<char *, void (*)(void *)> symbols{
      backtrace_symbols(addresses, size), std::free};
  for (int i = 0; i < size; ++i) {
    std::string demangled(symbols.get()[i]);
    DemangleInternal(demangled);
    stack_.append(demangled);
    stack_.append("\n");
  }
  fprintf(stderr, "%s\n", stack_.data());
  signal(sig, SIG_DFL);
  raise(sig);
}

extern "C" void backtraceinit() {
  signal(SIGSEGV, symbolizetrace); // Invaild memory address
  signal(SIGABRT, symbolizetrace); // Abort signal
}
