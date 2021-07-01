
#include <iostream>
#include "liberu.h"

using namespace std;


int main(int argc, char **argv) {
    EruData secret_key, cloud_key, data1, data2;
    printf("starting client\n"); {
        EruContext<EruGate> ctx(128);
        ctx.gen_secret_key();
        secret_key = ctx.get_secret_key();
        cloud_key = ctx.get_cloud_key();
        EruBool<EruGate> a(&ctx), b(&ctx);
        a = true;
        b = false;
        data1 = a.bexport();
        data2 = b.bexport();
    }
    printf("starting server\n"); {
        EruContext<EruGate> ctx(128);
        ctx.set_cloud_key(cloud_key);
        EruBool<EruGate> a(&ctx), b(&ctx), c(&ctx);
        a.bimport(data1);
        b.bimport(data2);
        c = a || b;
        b = a && b;
        data1 = b.bexport();
        data2 = c.bexport();
    }
    printf("starting client 2\n"); {
        EruContext<EruGate> ctx(128);
        ctx.set_secret_key(secret_key);
        EruBool<EruGate> a(&ctx), b(&ctx);
        a.bimport(data1);
        b.bimport(data2);
        bool r1 = a.decrypt(), r2 = b.decrypt();
        printf("  result = %d / %d\n", r1, r2);
    }
    return 0;
}
