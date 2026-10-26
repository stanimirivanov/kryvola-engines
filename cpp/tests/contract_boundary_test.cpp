#include "artifact_ref.hpp"
#include "kryvola/engine_api.hpp"
#include "limits.hpp"
#include <cstddef>
#include <limits>

using kryvola::engine::fits_control;

int main() {
  // Explicit exit checks remain active in all build modes, including NDEBUG.
  if (!fits_control(kryvola::spec::control_bytes) || fits_control(kryvola::spec::control_bytes + 1) ||
      fits_control(std::numeric_limits<std::size_t>::max())) {
    return 1;
  }
  if (kryvola::engine::Capabilities{}.execution_available) {
    return 1;
  }
  kryvola::spec::ArtifactRef reference;
  reference.schema_version = "1";
  return reference.schema_version == "1" ? 0 : 1;
}
