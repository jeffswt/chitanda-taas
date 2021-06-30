
#ifndef _LIBERU_UTILS_H
#define _LIBERU_UTILS_H

#include <iostream>
#include <sstream>


typedef std::string EruData;

/// THERE BE DRAGONS!
namespace _EruHazmat {
    /// Dump std::stringstream contents all into EruData.
    /// @param stream: String stream as input.
    /// @return Binary string.
    EruData dump_sstream(std::stringstream &stream);
}

#endif  // _LIBERU_UTILS_H
