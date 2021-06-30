
#include <iostream>
#include "liberu.h"

using namespace std;


int main(int argc, char** argv) {
    printf("starting client\n");
    EruSession client(128);
    client.generate_key();
    auto secret_key = client.get_key().secret();
    auto cloud_key = client.get_key().cloud();
    printf("    key length = %d\n", secret_key.length());
    auto env1 = client.env();
    auto x = env1->malloc(2);
    printf("  encrypting\n");
    env1->encrypt(x, true);
    env1->encrypt(x + 1, false);
    printf("  exporting\n");
    auto data1 = env1->bexport(x), data2 = env1->bexport(x + 1);
    printf("    data length = %d / %d\n", data1.length(), data2.length());
    printf("  closing\n");
    env1->mfree(x, 2);

    printf("starting server\n");
    EruSession server(128);
    server.set_key(EruKey::from_cloud(cloud_key));
    auto env2 = server.env();
    printf("  loading data\n");
    auto y = env2->malloc(4);
    env2->bimport(y, data1);
    env2->bimport(y + 1, data2);
    printf("  calculating\n");
    env2->land(y + 2, y, y + 1);
    env2->lor(y + 3, y, y + 1);
    printf("  exporting\n");
    data1 = env2->bexport(y + 2), data2 = env2->bexport(y + 3);
    env2->mfree(y, 4);

    printf("starting client 3\n");
    EruSession alice(128);
    alice.set_key(EruKey::from_secret(secret_key));
    auto env3 = alice.env();
    printf("  loading data\n");
    auto z = env3->malloc(2);
    env3->bimport(z, data1);
    env3->bimport(z + 1, data2);
    printf("  decrypting data\n");
    bool res1 = env3->decrypt(z), res2 = env3->decrypt(z + 1);
    printf("    result = %d / %d\n", res1, res2);
    env3->mfree(z, 2);

    return 0;
}
