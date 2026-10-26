#include "artifact_ref.hpp"
#include "limits.hpp"
#include <iostream>

int main() {
  std::cout << "component=kryvola-engines status=foundation execution_available=false control_max_bytes="
            << kryvola::spec::control_bytes << '\n';
  return 0;
}
