#pragma once
#include "limits.hpp"
#include <cstddef>

namespace kryvola::engine {
struct Capabilities {
  bool execution_available = false;
};

// Caller supplies the encoded metadata size before submission to an engine.
constexpr bool fits_control(std::size_t size) noexcept {
  return size <= spec::control_bytes;
}
}  // namespace kryvola::engine
