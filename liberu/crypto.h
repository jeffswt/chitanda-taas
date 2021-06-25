
// crypto.h: basic crypto functions
// MIT License
//
// Copyright (c) 2021 Geoffrey Tang
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to
// deal in the Software without restriction, including without limitation the
// rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
// sell copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
// IN THE SOFTWARE.

#ifndef _LIBERU_CRYPTO_H
#define _LIBERU_CRYPTO_H

#include <tfhe/tfhe.h>
#include <memory>


typedef std::string EruData;
typedef LweSample EruGate;
class EruKey;
template <typename _T> class EruEnv;
class EruEnvPlain;
class EruEnvFhe;
class EruSession;

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
    static EruKey from_secret_raw(
        std::shared_ptr<TFheGateBootstrappingSecretKeySet> key);
    static EruKey from_cloud_raw(
        std::shared_ptr<TFheGateBootstrappingCloudKeySet> key);
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
    bool* malloc(size_t size);
    void mfree(bool *ptr, size_t size);
    void lval(bool *r, const bool a);
    void ldup(bool *r, const bool *a);
    void lnot(bool *r, const bool *a);
    void land(bool *r, const bool *a, const bool *b);
    void lor(bool *r, const bool *a, const bool *b);
    void lnand(bool *r, const bool *a, const bool *b);
    void lnor(bool *r, const bool *a, const bool *b);
    void lxor(bool *r, const bool *a, const bool *b);
    void lxnor(bool *r, const bool *a, const bool *b);
    void landyn(bool *r, const bool *a, const bool *b);
    void landny(bool *r, const bool *a, const bool *b);
    void loryn(bool *r, const bool *a, const bool *b);
    void lorny(bool *r, const bool *a, const bool *b);
    void lifelse(bool *r, const bool *a, const bool *b, const bool *c);
    void encrypt(bool *r, const bool a);
    bool decrypt(const bool *a);
};

class EruEnvFhe : public EruEnv<EruGate> {
private:
    EruSession *_session;
    TFheGateBootstrappingCloudKeySet* _key();
public:
    EruEnvFhe();
    EruEnvFhe(EruSession *session);
    EruEnvFhe(const EruEnvFhe &other);
    EruGate* malloc(size_t size);
    void mfree(EruGate *ptr, size_t size);
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
    void lifelse(EruGate *r, const EruGate *a, const EruGate *b, const EruGate *c);
    void encrypt(EruGate *r, const bool a);
    bool decrypt(const EruGate *a);
};

class EruSession {
protected:
    int _min_lambda;
    std::shared_ptr<TFheGateBootstrappingParameterSet> _params;
    EruKey _key;
    std::shared_ptr<EruEnvFhe> _env;
public:
    EruSession(int min_lambda);
    EruSession(const EruSession &other);
    // Reset session seed
    void set_seed();
    void set_seed(uint32_t values[], size_t size);
    // Generate new keypair
    void generate_key(bool seed = true);
    // Set existing key
    void set_key(EruKey key);
    // Get key
    EruKey get_key();
    // Get current parameters
    TFheGateBootstrappingParameterSet* params();
    // Get session environment
    EruEnvFhe* env();
};

#endif  // _LIBERU_CRYPTO_H
