#pragma once
#include <string_view>
#include <optional>
#include <string>
#include <cstdint>
#include <cstddef>

namespace DPI {

class QUICExtractor {
public:
    // Uses std::string_view for zero-copy parsing to keep FastPath threads lightning fast
    static std::optional<std::string> extract(std::string_view payload);

private:
    // Helper to decode QUIC Variable-Length Integers
    static uint64_t getVarInt(std::string_view data, size_t& offset);
};

} // namespace DPI
