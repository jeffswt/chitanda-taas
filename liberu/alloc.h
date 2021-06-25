
// alloc.h: default self-adaptive allocator
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

#ifndef _LIBERU_ALLOC_H
#define _LIBERU_ALLOC_H

#include "crypto.h"
#include <vector>

template <typename _T>
class EruBits {
    // Allocator returned data delegate. Do remember to free this as it would
    // not be done automatically.
private:
    _T *_field;
    size_t __size, __chunk, __offset;
public:
    EruBits(_T *field, size_t size, size_t chunk, size_t offset);
    size_t _size();
    size_t _chunk();
    size_t _offset();
    // get contained pointer
    _T* ptr();
};

template <typename _T>
class EruAllocator {
    // Allocator that returns data delegates upon user requirement. The data
    // pointers are guaranteed to be consequent.
private:
    std::vector<std::pair<size_t, std::shared_ptr<_T>>> _pool;  // chunks
    std::vector<size_t> _pool_free;  // free size per chunk
    std::vector<std::vector<bool>> _pool_used;  // used blocks per chunk
    size_t _size;  // allocator pool size
    size_t _size_free;  // remaining non-allocated area
    void *_params;  // bootstrap params, leave null if not encrypting
public:
    EruAllocator(size_t default_size, void *params);
    size_t size();
    // Increase allocator container size by [size] objects.
    void expand_by(size_t size);
    // Increase allocator container size up to [target_size] objects. Pool will
    // not shrink if given target size is less than actual size.
    void expand(size_t target_size);
    // Allocates consequent memory objects.
    EruBits<_T> allocate(size_t size);
    // Free allocated object for later use. They will remain in pool anyway.
    void free(EruBits<_T> ptr);
};

#endif  // _LIBERU_ALLOC_H
