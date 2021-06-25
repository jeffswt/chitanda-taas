
// context.cpp: context exposing to users
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

#include "context.h"


template <typename _T>
EruContext<_T>::EruContext(int min_lambda) {
    __session = nullptr;
    __allocator = std::unique_ptr<EruAllocator<_T>>(new EruAllocator<_T>(
        16, nullptr));
    __env = std::unique_ptr<EruEnv<_T>>((EruEnv<_T>*)new EruEnvPlain());
}
template <>
EruContext<EruGate>::EruContext(int min_lambda) {
    __session = std::unique_ptr<EruSession>(new EruSession(min_lambda));
    __allocator = std::unique_ptr<EruAllocator<EruGate>>(
        new EruAllocator<EruGate>(16, __session.get()->params())
    );
    __env = nullptr;
}

template <typename _T>
EruSession* EruContext<_T>::_session() {
    return __session.get();
}

template <typename _T>
EruAllocator<_T>* EruContext<_T>::_allocator() {
    return __allocator.get();
}

template <typename _T>
EruEnv<_T>* EruContext<_T>::_env() {
    if (__session != nullptr)
        return (EruEnv<_T>*)__session.get()->env();
    return __env.get();
}

template <typename _T>
void EruContext<_T>::gen_secret_key() {
    if (__session != nullptr)
        __session.get()->generate_key();
}

template <typename _T>
void EruContext<_T>::set_secret_key(EruData key) {
    if (__session != nullptr)
        __session.get()->set_key(EruKey::from_secret(key));
}

template <typename _T>
void EruContext<_T>::set_cloud_key(EruData key) {
    if (__session != nullptr)
        __session.get()->set_key(EruKey::from_cloud(key));
}

template <typename _T>
EruData EruContext<_T>::get_secret_key() {
    if (__session != nullptr)
        return __session.get()->get_key().secret();
    return "";
}

template <typename _T>
EruData EruContext<_T>::get_cloud_key() {
    if (__session != nullptr)
        return __session.get()->get_key().cloud();
    return "";
}
