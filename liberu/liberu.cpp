
#include <tfhe/tfhe_io.h>
#include <openssl/rand.h>
#include "liberu.h"

#include <sstream>


EruData _extract_sstream_data(std::stringstream &stream) {
    EruData result;
    int ch;
    while ((ch = stream.get()) != EOF)
        result += (char)ch;
    return result;
}

class _TFheGateBootstrappingParameterSetDeleter {
public:
    void operator() (TFheGateBootstrappingParameterSet *ptr) {
        delete_gate_bootstrapping_parameters(ptr);
    }
};

class _TFheGateBootstrappingSecretKeySetDeleter {
public:
    void operator() (TFheGateBootstrappingSecretKeySet *ptr) {
        delete_gate_bootstrapping_secret_keyset(ptr);
    }
};

class _TFheGateBootstrappingCloudKeySetDeleter {
public:
    void operator() (TFheGateBootstrappingCloudKeySet *ptr) {
        delete_gate_bootstrapping_cloud_keyset(ptr);
    }
};

// Key manager

EruKey::EruKey() : _secret(nullptr), _cloud(nullptr) {}

EruKey::EruKey(const EruKey &other) : _secret(other._secret),
    _cloud(other._cloud) {}

EruKey::EruKey(std::shared_ptr<TFheGateBootstrappingSecretKeySet> secret_key,
    std::shared_ptr<TFheGateBootstrappingCloudKeySet> cloud_key) :
    _secret(secret_key), _cloud(cloud_key) {}

EruKey EruKey::from_secret_raw(
        std::shared_ptr<TFheGateBootstrappingSecretKeySet> key) {
    return EruKey(key, nullptr);
}

EruKey EruKey::from_cloud_raw(
        std::shared_ptr<TFheGateBootstrappingCloudKeySet> key) {
    return EruKey(nullptr, key);
}

EruKey EruKey::from_secret(EruData key) {
    std::stringstream stream;
    stream.write(key.c_str(), key.length());
    return EruKey::from_secret_raw(
        std::shared_ptr<TFheGateBootstrappingSecretKeySet>(
            new_tfheGateBootstrappingSecretKeySet_fromStream(stream),
            _TFheGateBootstrappingSecretKeySetDeleter()
        )
    );
}

EruKey EruKey::from_cloud(EruData key) {
    std::stringstream stream;
    stream.write(key.c_str(), key.length());
    return EruKey::from_cloud_raw(
        std::shared_ptr<TFheGateBootstrappingCloudKeySet>(
            new_tfheGateBootstrappingCloudKeySet_fromStream(stream),
            _TFheGateBootstrappingCloudKeySetDeleter()
        )
    );
}

const TFheGateBootstrappingSecretKeySet* EruKey::secret_raw() {
    return _secret.get();
}

const TFheGateBootstrappingCloudKeySet* EruKey::cloud_raw() {
    if (_secret != nullptr)
        return &_secret.get()->cloud;
    return _cloud.get();
}

EruData EruKey::secret() {
    std::stringstream stream;
    export_tfheGateBootstrappingSecretKeySet_toStream(stream, secret_raw());
    return _extract_sstream_data(stream);
}

EruData EruKey::cloud() {
    std::stringstream stream;
    export_tfheGateBootstrappingCloudKeySet_toStream(stream, cloud_raw());
    return _extract_sstream_data(stream);
}

// Environment base class definitions

template <typename _T>
_T* EruEnv<_T>::malloc(size_t size) { return nullptr; }

template <typename _T>
void EruEnv<_T>::mfree(_T* ptr, size_t size) {}

template <typename _T>
void EruEnv<_T>::lval(_T *r, const bool a) {}

template <typename _T>
void EruEnv<_T>::ldup(_T *r, const _T *a) {}

template <typename _T>
void EruEnv<_T>::lnot(_T *r, const _T *a) {}

template <typename _T>
void EruEnv<_T>::land(_T *r, const _T *a, const _T *b) {}

template <typename _T>
void EruEnv<_T>::lor(_T *r, const _T *a, const _T *b) {}

template <typename _T>
void EruEnv<_T>::lnand(_T *r, const _T *a, const _T *b) {}

template <typename _T>
void EruEnv<_T>::lnor(_T *r, const _T *a, const _T *b) {}

template <typename _T>
void EruEnv<_T>::lxor(_T *r, const _T *a, const _T *b) {}

template <typename _T>
void EruEnv<_T>::lxnor(_T *r, const _T *a, const _T *b) {}

template <typename _T>
void EruEnv<_T>::landyn(_T *r, const _T *a, const _T *b) {}

template <typename _T>
void EruEnv<_T>::landny(_T *r, const _T *a, const _T *b) {}

template <typename _T>
void EruEnv<_T>::loryn(_T *r, const _T *a, const _T *b) {}

template <typename _T>
void EruEnv<_T>::lorny(_T *r, const _T *a, const _T *b) {}

template <typename _T>
void EruEnv<_T>::lifelse(_T *r, const _T *a, const _T *b, const _T *c) {}

template <typename _T>
void EruEnv<_T>::encrypt(_T *r, const bool a) {}

template <typename _T>
bool EruEnv<_T>::decrypt(const _T *a) { return false; }

// Raw environment

bool* EruEnvPlain::malloc(size_t size) {
    return new bool[size];
}

void EruEnvPlain::mfree(bool *ptr, size_t size) {
    delete[] ptr;
}

void EruEnvPlain::lval(bool *r, const bool a) {
    *r = a;
}

void EruEnvPlain::ldup(bool *r, const bool *a) {
    *r = *a;
}

void EruEnvPlain::lnot(bool *r, const bool *a) {
    *r = !*a;
}

void EruEnvPlain::land(bool *r, const bool *a, const bool *b) {
    *r = *a && *b;
}

void EruEnvPlain::lor(bool *r, const bool *a, const bool *b) {
    *r = *a || *b;
}

void EruEnvPlain::lnand(bool *r, const bool *a, const bool *b) {
    *r = !(*a && *b);
}

void EruEnvPlain::lnor(bool *r, const bool *a, const bool *b) {
    *r = !(*a || *b);
}

void EruEnvPlain::lxor(bool *r, const bool *a, const bool *b) {
    *r = *a ^ *b;
}

void EruEnvPlain::lxnor(bool *r, const bool *a, const bool *b) {
    *r = !(*a ^ *b);
}

void EruEnvPlain::landyn(bool *r, const bool *a, const bool *b) {
    *r = *a && !*b;
}

void EruEnvPlain::landny(bool *r, const bool *a, const bool *b) {
    *r = !*a && *b;
}

void EruEnvPlain::loryn(bool *r, const bool *a, const bool *b) {
    *r = *a || !*b;
}

void EruEnvPlain::lorny(bool *r, const bool *a, const bool *b) {
    *r = !*a || *b;
}

void EruEnvPlain::lifelse(bool *r, const bool *a, const bool *b,
        const bool *c) {
    *r = *a ? *b : *c;
}

void EruEnvPlain::encrypt(bool *r, const bool a) {
    *r = a;
}

bool EruEnvPlain::decrypt(const bool *a) {
    return *a;
}

// Encrypted FHE environment

TFheGateBootstrappingCloudKeySet* EruEnvFhe::_key() {
    if (_session == nullptr)
        return nullptr;
    return const_cast<TFheGateBootstrappingCloudKeySet*>(
        _session->get_key().cloud_raw()
    );
}

EruEnvFhe::EruEnvFhe() : _session(nullptr) {}

EruEnvFhe::EruEnvFhe(EruSession *session) : _session(session) {}

EruEnvFhe::EruEnvFhe(const EruEnvFhe &other) : _session(other._session) {}

EruGate* EruEnvFhe::malloc(size_t size) {
    auto params = _session->params();
    return new_gate_bootstrapping_ciphertext_array(size, params);
}

void EruEnvFhe::mfree(EruGate* ptr, size_t size) {
    delete_gate_bootstrapping_ciphertext_array(size, ptr);
}

void EruEnvFhe::lval(EruGate *r, const bool a) {
    bootsCONSTANT(r, a, _key());
}

void EruEnvFhe::ldup(EruGate *r, const EruGate *a) {
    bootsCOPY(r, a, _key());
}

void EruEnvFhe::lnot(EruGate *r, const EruGate *a) {
    bootsNOT(r, a, _key());
}

void EruEnvFhe::land(EruGate *r, const EruGate *a, const EruGate *b) {
    bootsAND(r, a, b, _key());
}

void EruEnvFhe::lor(EruGate *r, const EruGate *a, const EruGate *b) {
    bootsOR(r, a, b, _key());
}

void EruEnvFhe::lnand(EruGate *r, const EruGate *a, const EruGate *b) {
    bootsNAND(r, a, b, _key());
}

void EruEnvFhe::lnor(EruGate *r, const EruGate *a, const EruGate *b) {
    bootsNOR(r, a, b, _key());
}

void EruEnvFhe::lxor(EruGate *r, const EruGate *a, const EruGate *b) {
    bootsXOR(r, a, b, _key());
}

void EruEnvFhe::lxnor(EruGate *r, const EruGate *a, const EruGate *b) {
    bootsXNOR(r, a, b, _key());
}

void EruEnvFhe::landyn(EruGate *r, const EruGate *a, const EruGate *b) {
    bootsANDYN(r, a, b, _key());
}

void EruEnvFhe::landny(EruGate *r, const EruGate *a, const EruGate *b) {
    bootsANDNY(r, a, b, _key());
}

void EruEnvFhe::loryn(EruGate *r, const EruGate *a, const EruGate *b) {
    bootsORYN(r, a, b, _key());
}

void EruEnvFhe::lorny(EruGate *r, const EruGate *a, const EruGate *b) {
    bootsORNY(r, a, b, _key());
}

void EruEnvFhe::lifelse(EruGate *r, const EruGate *a, const EruGate *b,
        const EruGate *c) {
    bootsMUX(r, a, b, c, _key());
}

void EruEnvFhe::encrypt(EruGate *r, const bool a) {
    bootsSymEncrypt(r, a, _session->get_key().secret_raw());
}

bool EruEnvFhe::decrypt(const EruGate *a) {
    return bootsSymDecrypt(a, _session->get_key().secret_raw()) != 0;
}

// Session manager

EruSession::EruSession(int min_lambda) : _min_lambda(min_lambda) {
    _params = std::shared_ptr<TFheGateBootstrappingParameterSet>(
        new_default_gate_bootstrapping_parameters(_min_lambda),
        _TFheGateBootstrappingParameterSetDeleter()
    );
    _env = std::shared_ptr<EruEnvFhe>(new EruEnvFhe(this));
}

EruSession::EruSession(const EruSession &other) :
    _min_lambda(other._min_lambda), _params(other._params),
    _key(other._key), _env(other._env) {}

void EruSession::set_seed() {
    // This function is cryptographically secure
    int size = _min_lambda * 2 / 32 + 1;
    auto buffer = std::unique_ptr<uint32_t>(new uint32_t[size]);
    if (RAND_bytes((unsigned char*)buffer.get(), size * 4) != 1)
        throw std::runtime_error("cannot generate secure seed");
    set_seed(buffer.get(), size);
}

void EruSession::set_seed(uint32_t values[], size_t size) {
    tfhe_random_generator_setSeed(values, size);
}

void EruSession::generate_key(bool seed) {
    if (seed)
        set_seed();
    TFheGateBootstrappingSecretKeySet *key;
    key = new_random_gate_bootstrapping_secret_keyset(_params.get());
    auto ptr = std::shared_ptr<TFheGateBootstrappingSecretKeySet>(key,
        _TFheGateBootstrappingSecretKeySetDeleter());
    _key = EruKey::from_secret_raw(ptr);
}

void EruSession::set_key(EruKey key) {
    _key = key;
}

EruKey EruSession::get_key() {
    return _key;
}

TFheGateBootstrappingParameterSet* EruSession::params() {
    return _params.get();
}

EruEnvFhe* EruSession::env() {
    return _env.get();
}
