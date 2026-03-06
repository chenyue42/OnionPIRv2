#include "tests.h"
#include <cstring>
#include <string>

int main(int argc, char *argv[]) {
  bool use_compression = true;
  std::string test_name = "pir";

  for (int i = 1; i < argc; i++) {
    if (strcmp(argv[i], "--no-compress") == 0) {
      use_compression = false;
    } else if (strcmp(argv[i], "--test") == 0 && i + 1 < argc) {
      test_name = argv[++i];
    }
  }
  PirTest().run_test(test_name, use_compression);
  return 0;
}