
#include "services.h"

using namespace std;


vector<EruData> svc_addition(vector<EruData> &vals) {
    EruContext<EruGate> ctx(128);
    ctx.set_cloud_key(vals[0]);
    EruInt64(EruGate) res(&ctx);
    res = 0;
    for (int i = 1; i < vals.size(); i++) {
        EruInt64(EruGate) tmp(&ctx);
        tmp.bimport(vals[i]);
        res += tmp;
    }
    vector<EruData> vec;
    vec.push_back(res.bexport());
    return vec;
}

vector<EruData> svc_multiply(vector<EruData> &vals) {
    EruContext<EruGate> ctx(128);
    ctx.set_cloud_key(vals[0]);
    EruInt64(EruGate) res(&ctx);
    res = 1;
    for (int i = 1; i < vals.size(); i++) {
        EruInt64(EruGate) tmp(&ctx);
        tmp.bimport(vals[i]);
        res *= tmp;
    }
    vector<EruData> vec;
    vec.push_back(res.bexport());
    return vec;
}

EruData provide_service_s(EruData &input) {
    auto x = _EruHazmat::binobjlist_decode(input);
    string id = x[0];
    vector<EruData> y;
    for (int i = 1; i < x.size(); i++)
        y.push_back(x[i]);
    // verdict
    vector<EruData> z;
    if (id == "add")
        z = svc_addition(y);
    else if (id == "mul")
        z = svc_multiply(y);
    // done
    return _EruHazmat::binobjlist_encode(z);
}

int provide_service(char *input, int inlen, char **out) {
    EruData einp;
    for (int i = 0; i < inlen; i++)
        einp += input[i];
    EruData eout = provide_service_s(einp);
    int olen = eout.length();
    *out = new char[olen];
    for (int i = 0; i < olen; i++)
        (*out)[i] = eout[i];
    return olen;
}
