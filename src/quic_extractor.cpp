#include "quic_extractor.h"
#include <stdexcept>

namespace DPI {

uint64_t QUICExtractor::getVarInt(std::string_view data, size_t& offset) {
    if (offset >= data.size()) return 0;
    
    uint8_t first = data[offset];
    uint8_t length = 1 << ((first & 0xC0) >> 6);
    
    if (offset + length > data.size()) return 0;
    
    uint64_t value = first & 0x3F;
    for (size_t i = 1; i < length; ++i) {
        value = (value << 8) | static_cast<uint8_t>(data[offset + i]);
    }
    
    offset += length;
    return value;
}

std::optional<std::string> QUICExtractor::extract(std::string_view payload) {
    if (payload.size() < 40) return std::nullopt;

    // 1. Check if it's a Long Header (Header Form bit = 1)
    if ((payload[0] & 0x80) == 0) return std::nullopt;
    
    // 2. Check if it's an Initial Packet (Type bits = 0x00)
    // Mask out the packet number length (bottom 4 bits)
    if ((payload[0] & 0x30) != 0x00) return std::nullopt;

    size_t offset = 1;
    
    // 3. Skip Version (4 bytes)
    offset += 4;
    if (offset >= payload.size()) return std::nullopt;

    // 4. Skip Destination Connection ID
    uint8_t dcil = payload[offset++];
    offset += dcil;
    if (offset >= payload.size()) return std::nullopt;

    // 5. Skip Source Connection ID
    uint8_t scil = payload[offset++];
    offset += scil;
    if (offset >= payload.size()) return std::nullopt;

    // 6. Skip Token
    uint64_t token_len = getVarInt(payload, offset);
    offset += token_len;
    if (offset >= payload.size()) return std::nullopt;

    // 7. Skip Length (of the rest of the packet)
    getVarInt(payload, offset);
    
    // 8. Skip Packet Number (assume 1 to 4 bytes based on bottom bits of byte 0)
    uint8_t pn_len = (payload[0] & 0x03) + 1;
    offset += pn_len;

    // 9. We are now at the QUIC Frames. Look for the CRYPTO frame (Type 0x06)
    while (offset < payload.size()) {
        uint64_t frame_type = getVarInt(payload, offset);
        
        if (frame_type == 0x00) continue; // PADDING
        
        if (frame_type == 0x06) {         // CRYPTO
            getVarInt(payload, offset);   // Skip Offset
            uint64_t crypto_len = getVarInt(payload, offset); // Skip Length
            
            if (offset + crypto_len > payload.size()) return std::nullopt;
            
            // The CRYPTO frame payload is the TLS Handshake!
            std::string_view tls_data = payload.substr(offset, crypto_len);
            
            // Re-use standard SNI extraction logic on the raw TLS data
            // Verify TLS handshake & Client Hello
            if (tls_data.size() < 43) return std::nullopt;
            if (tls_data[0] != 0x01) return std::nullopt; // Handshake Type: Client Hello
            
            size_t tls_offset = 38; // Skip to Session ID
            
            uint8_t sess_len = tls_data[tls_offset];
            tls_offset += 1 + sess_len;
            if (tls_offset + 2 > tls_data.size()) return std::nullopt;
            
            uint16_t cipher_len = (static_cast<uint8_t>(tls_data[tls_offset]) << 8) | 
                                   static_cast<uint8_t>(tls_data[tls_offset+1]);
            tls_offset += 2 + cipher_len;
            if (tls_offset + 1 > tls_data.size()) return std::nullopt;
            
            uint8_t comp_len = tls_data[tls_offset];
            tls_offset += 1 + comp_len;
            if (tls_offset + 2 > tls_data.size()) return std::nullopt;
            
            uint16_t ext_len = (static_cast<uint8_t>(tls_data[tls_offset]) << 8) | 
                                static_cast<uint8_t>(tls_data[tls_offset+1]);
            tls_offset += 2;
            
            size_t ext_end = tls_offset + ext_len;
            while (tls_offset + 4 <= ext_end && tls_offset + 4 <= tls_data.size()) {
                uint16_t e_type = (static_cast<uint8_t>(tls_data[tls_offset]) << 8) | 
                                   static_cast<uint8_t>(tls_data[tls_offset+1]);
                uint16_t e_len = (static_cast<uint8_t>(tls_data[tls_offset+2]) << 8) | 
                                  static_cast<uint8_t>(tls_data[tls_offset+3]);
                tls_offset += 4;
                
                if (e_type == 0x0000 && tls_offset + 5 <= tls_data.size()) { // SNI
                    uint16_t sni_len = (static_cast<uint8_t>(tls_data[tls_offset+3]) << 8) | 
                                        static_cast<uint8_t>(tls_data[tls_offset+4]);
                    if (tls_offset + 5 + sni_len <= tls_data.size()) {
                        return std::string(tls_data.data() + tls_offset + 5, sni_len);
                    }
                }
                tls_offset += e_len;
            }
            return std::nullopt;
        } else {
            // Unhandled frame before CRYPTO, break for safety
            break;
        }
    }
    
    return std::nullopt;
}

} // namespace DPI
