
#include <tfhe/tfhe.h>
#include <memory>


typedef std::string EruData;
typedef LweSample EruGate;

class EruKey {
protected:
    std::shared_ptr<TFheGateBootstrappingSecretKeySet> _secret;
    std::shared_ptr<TFheGateBootstrappingCloudKeySet> _cloud;
public:
    // constructors
    EruKey();
    EruKey(const EruKey &other);
    EruKey(std::shared_ptr<TFheGateBootstrappingSecretKeySet> secret_key,
        std::shared_ptr<TFheGateBootstrappingCloudKeySet> cloud_key);
    static EruKey from_raw_secret(
        std::shared_ptr<TFheGateBootstrappingSecretKeySet> key);
    static EruKey from_raw_cloud(
        std::shared_ptr<TFheGateBootstrappingSecretKeySet> key);
    static EruKey from_secret(EruData key);
    static EruKey from_cloud(EruData key);
    // data retrievers
    const TFheGateBootstrappingSecretKeySet* secret_raw();
    const TFheGateBootstrappingCloudKeySet* cloud_raw();
    EruData secret();
    EruData cloud();
};

template <typename _T>
class EruEnv {
    // Provides a trait for logical arithmetic environment. Also supporting
    // envryption and decryption.
public:
    virtual _T* malloc(size_t size);  // allocate memory
    virtual void mfree(_T* ptr, size_t size);  // free memory
    virtual void lval(_T *r, const bool a);  // r = true / false
    virtual void ldup(_T *r, const _T *a);  // r = a
    virtual void lnot(_T *r, const _T *a);  // r = !a
    virtual void land(_T *r, const _T *a, const _T *b);  // r =  a && b
    virtual void lor(_T *r, const _T *a, const _T *b);  // r = a || b
    virtual void lnand(_T *r, const _T *a, const _T *b);  // r = !(a && b)
    virtual void lnor(_T *r, const _T *a, const _T *b);  // r = !(a || b)
    virtual void lxor(_T *r, const _T *a, const _T *b);  // r = a ^ b
    virtual void lxnor(_T *r, const _T *a, const _T *b);  // r = !(a ^ b)
    virtual void landyn(_T *r, const _T *a, const _T *b);  // r = a && !b
    virtual void landny(_T *r, const _T *a, const _T *b);  // r = !a && b
    virtual void loryn(_T *r, const _T *a, const _T *b);  // r = a || !b
    virtual void lorny(_T *r, const _T *a, const _T *b);  // r = !a || b
    virtual void lifelse(_T *r, const _T *a, const _T *b, const _T *c);  // mux
    virtual void encrypt(_T *r, const bool a);  // bool -> _T
    virtual bool decrypt(const _T *a);  // _T -> bool
};

class EruEnvPlain : public EruEnv<bool> {
public:
    bool* malloc(size_t size) {
        return new bool[size]; }
    void mfree(bool *ptr, size_t size) {
        delete[] ptr; }
    void lval(bool *r, const bool a) {
        *r = a; }
    void ldup(bool *r, const bool *a) {
        *r = *a; }
    void lnot(bool *r, const bool *a) {
        *r = !*a; }
    void land(bool *r, const bool *a, const bool *b) {
        *r = *a && *b; }
    void lor(bool *r, const bool *a, const bool *b) {
        *r = *a || *b; }
    void lnand(bool *r, const bool *a, const bool *b) {
        *r = !(*a && *b); }
    void lnor(bool *r, const bool *a, const bool *b) {
        *r = !(*a || *b); }
    void lxor(bool *r, const bool *a, const bool *b) {
        *r = *a ^ *b; }
    void lxnor(bool *r, const bool *a, const bool *b) {
        *r = !(*a ^ *b); }
    void landyn(bool *r, const bool *a, const bool *b) {
        *r = *a && !*b; }
    void landny(bool *r, const bool *a, const bool *b) {
        *r = !*a && *b; }
    void loryn(bool *r, const bool *a, const bool *b) {
        *r = *a || !*b; }
    void lorny(bool *r, const bool *a, const bool *b) {
        *r = !*a || *b; }
    void lifelse(bool *r, const bool *a, const bool *b, const bool *c) {
        *r = *a ? *b : *c; }
    void encrypt(bool *r, const bool a) {
        *r = a; }
    bool decrypt(const bool *a) {
        return *a; }
};

class EruEnvFhe : public EruEnv<EruGate> {
protected:
    EruSession *_session;
    TFheGateBootstrappingCloudKeySet *_key_cache;
    TFheGateBootstrappingCloudKeySet* _key();
public:
    EruEnvFhe();
    EruEnvFhe(EruSession *session);
    EruEnvFhe(const EruEnvFhe &other);
    EruGate* malloc(size_t size);
    void mfree(EruGate* ptr, size_t size);
    void lval(EruGate *r, const bool a);
    void ldup(EruGate *r, const EruGate *a);
    void lnot(EruGate *r, const EruGate *a);
    void land(EruGate *r, const EruGate *a, const EruGate *b);
    void lor(EruGate *r, const EruGate *a, const EruGate *b);
    void lnand(EruGate *r, const EruGate *a, const EruGate *b);
    void lnor(EruGate *r, const EruGate *a, const EruGate *b);
    void lxor(EruGate *r, const EruGate *a, const EruGate *b);
    void lxnor(EruGate *r, const EruGate *a, const EruGate *b);
    void landyn(EruGate *r, const EruGate *a, const EruGate *b);
    void landny(EruGate *r, const EruGate *a, const EruGate *b);
    void loryn(EruGate *r, const EruGate *a, const EruGate *b);
    void lorny(EruGate *r, const EruGate *a, const EruGate *b);
    void lifelse(EruGate *r, const EruGate *a, const EruGate *b,
        const EruGate *c);
    void encrypt(EruGate *r, const bool a);
    bool decrypt(const EruGate *a);
};

class EruSession {
protected:
    int _min_lambda;
    std::shared_ptr<TFheGateBootstrappingParameterSet> _params;
    EruKey _key;
public:
    EruSession(int min_lambda);
    EruSession(const EruSession &other);
    // Reset session seed
    void set_seed();
    // Generate new keypair
    void generate_key();
    // Set existing key
    void set_key(EruKey key);
    // Get key
    EruKey get_key();
};
