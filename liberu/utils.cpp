
#include "utils.h"


EruData _EruHazmat::dump_sstream(std::stringstream &stream) {
    EruData result;
    int ch;
    while ((ch = stream.get()) != EOF)
        result += (char)ch;
    return result;
}
