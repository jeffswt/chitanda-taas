
// context.h: context exposing to users
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

#ifndef _LIBERU_CONTEXT_H
#define _LIBERU_CONTEXT_H

#include "crypto.h"
#include "alloc.h"


template <typename _T>
class EruContext {
private:
    std::unique_ptr<EruSession> __session;
    std::unique_ptr<EruAllocator<_T>> __allocator;
    std::unique_ptr<EruEnv<_T>> __env;  // when __session is unavailable
public:
    EruContext(int min_lambda) {
        __session = nullptr;
        __allocator = std::unique_ptr<EruAllocator<_T>>(new EruAllocator<_T>(
            16, nullptr));
        __env = std::unique_ptr<EruEnv<_T>>((EruEnv<_T>*)new EruEnvPlain());
    }
    // Medium-level interfaces that you really shouldn't touch
    // unless you know what you're doing
    EruSession* _session() {
        return __session.get();
    }
    EruAllocator<_T>* _allocator() {
        return __allocator.get();
    }
    EruEnv<_T>* _env() {
        if (__session != nullptr)
            return (EruEnv<_T>*)__session.get()->env();
        return __env.get();
    }
    // Key management
    void gen_secret_key() {
        if (__session != nullptr)
            __session.get()->generate_key();
    }
    void set_secret_key(EruData key) {
        if (__session != nullptr)
            __session.get()->set_key(EruKey::from_secret(key));
    }
    void set_cloud_key(EruData key) {
        if (__session != nullptr)
            __session.get()->set_key(EruKey::from_cloud(key));
    }
    EruData get_secret_key() {
        if (__session != nullptr)
            return __session.get()->get_key().secret();
        return "";
    }
    EruData get_cloud_key() {
        if (__session != nullptr)
            return __session.get()->get_key().cloud();
        return "";
    }
    // Memory management
    EruBits<_T> allocate(size_t size) {
        return __allocator.get()->allocate(size);
    }
    void free(EruBits<_T> ptr) {
        __allocator.get()->free(ptr);
    }
};

template <>
EruContext<EruGate>::EruContext(int min_lambda);

#endif  // _LIBERU_CONTEXT_H
