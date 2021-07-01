
#include <iostream>
#include "liberu.h"

using namespace std;


void type_int_sample() {
    EruData secret_key, cloud_key, data1, data2;
    printf("starting client\n"); {
        EruContext<EruGate> ctx(128);
        ctx.gen_secret_key();
        secret_key = ctx.get_secret_key();
        cloud_key = ctx.get_cloud_key();
        EruIntGeneral<EruGate, 64> a(&ctx), b(&ctx);
        a = 3;
        b = 15;
        data1 = a.bexport();
        data2 = b.bexport();
        printf("  length = %d/%d\n", data1.length(), data2.length());
    }
    printf("starting server\n"); {
        EruContext<EruGate> ctx(128);
        ctx.set_cloud_key(cloud_key);
        EruIntGeneral<EruGate, 64> a(&ctx);
        EruIntGeneral<EruGate, 64> b(&ctx);
        a.bimport(data1);
        b.bimport(data2);
        a = a * b;
        b *= a;
        data1 = a.bexport();
        data2 = b.bexport();
    }
    printf("starting client 2\n"); {
        EruContext<EruGate> ctx(128);
        ctx.set_secret_key(secret_key);
        EruIntGeneral<EruGate, 64> a(&ctx), b(&ctx);
        a.bimport(data1);
        b.bimport(data2);
        int64_t r1 = a.decrypt(), r2 = b.decrypt();
        printf("  result = %lld / %lld\n", r1, r2);
    }
}
