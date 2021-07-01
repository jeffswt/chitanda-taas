
#include <iostream>
#include "liberu.h"

using namespace std;


int main(int argc, char** argv) {
    EruData secret_key, cloud_key, data1, data2;
    printf("starting client\n"); {
        EruContext<EruGate> ctx(128);
        ctx.gen_secret_key();
        secret_key = ctx.get_secret_key();
        cloud_key = ctx.get_cloud_key();
        auto env = ctx._env();
        auto x_ = ctx.allocate(2);
        auto x = x_.ptr();
        env->lval(x, true);
        env->lval(x + 1, false);
        data1 = env->bexport(x);
        data2 = env->bexport(x + 1);
        ctx.free(x_);
    }
    printf("starting server\n"); {
        EruContext<EruGate> ctx(128);
        ctx.set_cloud_key(cloud_key);
        auto env = ctx._env();
        auto x_ = ctx.allocate(4);
        auto x = x_.ptr();
        env->bimport(x, data1);
        env->bimport(x + 1, data2);
        env->land(x + 2, x, x + 1);
        env->lor(x + 3, x, x + 1);
        data1 = env->bexport(x + 2);
        data2 = env->bexport(x + 3);
        ctx.free(x_);
    }
    printf("starting client 2\n"); {
        EruContext<EruGate> ctx(128);
        ctx.set_secret_key(secret_key);
        auto env = ctx._env();
        auto x_ = ctx.allocate(2);
        auto x = x_.ptr();
        env->bimport(x, data1);
        env->bimport(x + 1, data2);
        bool r1 = env->decrypt(x), r2 = env->decrypt(x + 1);
        ctx.free(x_);
        printf("  result = %d / %d\n", r1, r2);
    }
    return 0;
}
