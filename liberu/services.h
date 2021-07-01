
#include "../liberu.h"


EruData provide_service_s(EruData &input);

extern "C" {
    // /// @param arr: Input array of 64-bit integers.
    // /// @param nmemb: Number of integers.
    // /// @param out: Array of output strings [secret, cloud, data].
    // /// @param lens: Length of output strings.
    // void svc_request_addition(int64_t *arr, int nmemb, char **out, int **lens);
    // int svc_request_multiply(int64_t *arr, int nmembs, char **out);
    int provide_service(char *input, int inlen, char **out);
}
