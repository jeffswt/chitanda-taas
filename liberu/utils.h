
#ifndef _LIBERU_UTILS_H
#define _LIBERU_UTILS_H

#include <iostream>
#include <sstream>
#include <vector>


typedef std::string EruData;

/// THERE BE DRAGONS!
namespace _EruHazmat {
    /// Dump std::stringstream contents all into EruData.
    /// @param stream: String stream as input.
    /// @return Binary string.
    EruData dump_sstream(std::stringstream &stream);

    /// Stack multiple binary strings into one.
    /// @param objs: A vector of multiple objects.
    /// @return: Decodable single string.
    EruData binobjlist_encode(const std::vector<EruData> &objs);

    /// Strip encoded binary list object bulk into multiple objects.
    /// @param data: binobjlist_encode'd object aggregate.
    /// @return: List of EruData's.
    std::vector<EruData> binobjlist_decode(const EruData &data);

    /// Prints string like in WinHex.
    /// @param out: Export stream, like std::cout.
    /// @param msg: Binary content.
    /// @return The same export stream.
    std::ostream& print_hex_box(std::ostream &out, std::string msg);
}

#endif  // _LIBERU_UTILS_H
