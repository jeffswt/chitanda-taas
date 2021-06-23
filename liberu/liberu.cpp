
#include <tfhe/tfhe.h>
#include <tfhe/tfhe_io.h>

#include <openssl/rand.h>

#include <iostream>
#include <memory>
#include <sstream>

class EruException : public std::exception {
private:
    std::string _what;
public:
    EruException(std::string what) : _what(what) {}
    const char* what() {
        return this->_what.c_str();
    }
};

typedef std::string EruBytes;

EruBytes _extract_sstream_data(std::stringstream &stream) {
    EruBytes result;
    int ch;
    while ((ch = stream.get()) != EOF)
        result += (char)ch;
    return result;
}

class TFheGateBootstrappingParameterSetDeleter {
public:
    void operator() (TFheGateBootstrappingParameterSet *ptr) {
        delete_gate_bootstrapping_parameters(ptr);
    }
};

class TFheGateBootstrappingSecretKeySetDeleter {
public:
    void operator() (TFheGateBootstrappingSecretKeySet *ptr) {
        delete_gate_bootstrapping_secret_keyset(ptr);
    }
};

class EruKeys {
protected:
    std::shared_ptr<TFheGateBootstrappingParameterSet> _bootstrap_params;
    std::shared_ptr<TFheGateBootstrappingSecretKeySet> _secret_key;
    std::shared_ptr<TFheGateBootstrappingCloudKeySet> _cloud_key;
public:
    EruKeys() : _bootstrap_params(nullptr), _secret_key(nullptr),
        _cloud_key(nullptr) {}
    EruKeys(std::shared_ptr<TFheGateBootstrappingParameterSet> bp,
        std::shared_ptr<TFheGateBootstrappingSecretKeySet> sk) :
        _bootstrap_params(bp), _secret_key(sk), _cloud_key(nullptr) {}
    EruKeys(std::shared_ptr<TFheGateBootstrappingParameterSet> bp,
        std::shared_ptr<TFheGateBootstrappingCloudKeySet> ck) :
        _bootstrap_params(bp), _secret_key(nullptr), _cloud_key(ck) {}
    EruKeys(const EruKeys &other) :
        _bootstrap_params(other._bootstrap_params),
        _secret_key(other._secret_key) {}
    EruBytes secret_key() {
        std::stringstream stream;
        export_tfheGateBootstrappingSecretKeySet_toStream(
            stream, this->get_secret_key());
        return _extract_sstream_data(stream);
    }
    EruBytes cloud_key() {
        std::stringstream stream;
        export_tfheGateBootstrappingCloudKeySet_toStream(
            stream, this->get_cloud_key());
        return _extract_sstream_data(stream);
    }
    const TFheGateBootstrappingSecretKeySet* get_secret_key() {
        return this->_secret_key.get();
    }
    const TFheGateBootstrappingCloudKeySet* get_cloud_key() {
        const TFheGateBootstrappingCloudKeySet *ptr;
        if (_secret_key != nullptr)
            ptr = &this->_secret_key.get()->cloud;
        else
            ptr = this->_cloud_key.get();
        return ptr;
    }
};

class EruEnv {
protected:
    int minimum_lambda = 110;
    std::shared_ptr<TFheGateBootstrappingParameterSet> _bootstrap_params;
    EruKeys _keys;
public:
    EruEnv() {
        this->_bootstrap_params = std::shared_ptr
            <TFheGateBootstrappingParameterSet>(
            new_default_gate_bootstrapping_parameters(minimum_lambda),
            TFheGateBootstrappingParameterSetDeleter()
        );
    }
    void seed() {
        // Resets seed of Eru environment using system random engine.
        // This function is cryptographically secure.
        int size = minimum_lambda * 2 / 32 + 1;  // how many uint32_t nums
        uint32_t *buffer = new uint32_t[size];
        if (RAND_bytes((unsigned char*)buffer, size * 4) != 1)
            throw EruException("cannot generate seed");
        tfhe_random_generator_setSeed(buffer, size);
    }
    void make_keys() {
        // Generates brand new secret key (and corresponding cloud keys).
        this->seed();
        TFheGateBootstrappingSecretKeySet *key;
        key = new_random_gate_bootstrapping_secret_keyset(
            this->_bootstrap_params.get());
        auto ptr = std::shared_ptr<TFheGateBootstrappingSecretKeySet>(key,
            TFheGateBootstrappingSecretKeySetDeleter());
        this->_keys = EruKeys(this->_bootstrap_params, ptr);
    }
    void set_keys(EruKeys keys) {
        this->_keys = keys;
    }
    EruKeys get_keys() {
        return this->_keys;
    }
    // creation and destruction of values
    LweSample* create(int size) {
        return new_gate_bootstrapping_ciphertext_array(size,
            this->_bootstrap_params.get());
    }
    void destroy(LweSample *a, int size) {
        delete_gate_bootstrapping_ciphertext_array(size, a);
    }
    // copy of homomorphic functions running in this environment
    #define _basic_unary_op(defined_name, tfhe_func_name)                     \
    void defined_name(LweSample *r, const LweSample *a) {                     \
        tfhe_func_name(r, a, this->_keys.get_cloud_key());                    \
    }
    #define _basic_binary_op(defined_name, tfhe_func_name)                    \
    void defined_name(LweSample *r, const LweSample *a, const LweSample *b) { \
        tfhe_func_name(r, a, b, this->_keys.get_cloud_key());                 \
    }
    _basic_unary_op(ldup, bootsCOPY)  // r = a
    _basic_unary_op(lnot, bootsNOT)  // r = !a
    _basic_binary_op(land, bootsAND)  // r =  a && b
    _basic_binary_op(lor, bootsOR)  // r = a || b
    _basic_binary_op(lnand, bootsNAND)  // r = !(a && b)
    _basic_binary_op(lnor, bootsNOR)  // r = !(a || b)
    _basic_binary_op(lxor, bootsXOR)  // r = a ^ b = (a != b)
    _basic_binary_op(lxnor, bootsXNOR)  // r = !(a ^ b) = (a == b)
    _basic_binary_op(landyn, bootsANDYN)  // r = a && !b
    _basic_binary_op(landny, bootsANDNY)  // r = !a && b
    _basic_binary_op(loryn, bootsORYN)  // r = a || !b
    _basic_binary_op(lorny, bootsORNY)  // r = !a || b
    #undef _basic_unary_op
    #undef _basic_binary_op
    void lval(LweSample *r, bool a) {  // r = true / false
        bootsCONSTANT(r, a, this->_keys.get_cloud_key());
    }
    void lifelse(LweSample *r, const LweSample *a, const LweSample *b,
        const LweSample *c) {  // r = a ? b : c
        bootsMUX(r, a, b, c, this->_keys.get_cloud_key());
    }
    // encryption and decryption
    void encrypt(LweSample *r, bool a) {
        bootsSymEncrypt(r, a, this->_keys.get_secret_key());
    }
    bool decrypt(const LweSample *a) {
        return bootsSymDecrypt(a, this->_keys.get_secret_key()) != 0;
    }
};

using namespace std;

int main(int argc, char** argv) {
    EruEnv client;
    client.make_keys();
    auto input = client.create(2);
    client.lval(input, true);
    client.lval(input + 1, false);

    EruEnv server;
    server.set_keys(client.get_keys());
    auto res = server.create(1);
    printf("started.\n");
    for (int i = 0; i < 10000; i++)
        server.lor(res, input, input + 1);
    printf("done.\n");

    bool fn = client.decrypt(res);
    cout << fn << endl;
    return 0;
}
