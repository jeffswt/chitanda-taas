
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

#include "liberu_base.h"
#include "liberu_alloc.h"

template <typename _T>
class EruContext {
private:
    std::unique_ptr<EruSession> __session;
    std::unique_ptr<EruAllocator<_T>> __allocator;
    std::unique_ptr<EruEnv<_T>> __env;  // when __session is unavailable
public:
    EruContext(int min_lambda);
    // Medium-level interfaces that you really shouldn't touch
    // unless you know what you're doing
    EruSession* _session();
    EruAllocator<_T>* _allocator();
    EruEnv<_T>* _env();
    // Key management
    void gen_secret_key();
    void set_secret_key(EruData key);
    void set_cloud_key(EruData key);
    EruData get_secret_key();
    EruData get_cloud_key();
};

#endif  // _LIBERU_CONTEXT_H
