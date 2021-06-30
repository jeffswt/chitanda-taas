
#include "utils.h"


EruData _EruHazmat::dump_sstream(std::stringstream &stream) {
    EruData result;
    int ch;
    while ((ch = stream.get()) != EOF)
        result += (char)ch;
    return result;
}

/// binobjlist := <null> // <binobjlist> <binobj>
/// binobj := <length> <data>, whereas len(data) == length
/// data := any binary string
/// length := [0xff] // <num> <length>, nums are stored in little-endian
/// num := [0x00] .. [0xfe], stored in base-255
EruData binobjlist_encode(const std::vector<EruData>& objs) {
    EruData result;
    for (auto &obj : objs) {
        // encode length
        uint64_t len = obj.length();
        for (; len > 0; len /= 255)
            result += (char)(len % 255);
        result += (char)0xff;
        // add data
        result += obj;
    }
    return result;
}

std::vector<EruData> binobjlist_decode(const EruData &data) {
    std::vector<EruData> result;
    EruData buffer;
    for (int i = 0; i < data.length(); ) {
        uint64_t len = 0, pwr = 1;
        for (; data[i] != 0xff; i++) {
            len += (uint64_t)data[i] * pwr;
            pwr *= 255;
        }
        i++;
        for (int j = 0; j < len; i++, j++)
            buffer += result[i];
        result.push_back(buffer);
        buffer.clear();
    }
    return result;
}
