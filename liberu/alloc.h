
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

#include <vector>

#include "crypto.h"


/// THERE BE DRAGONS!
namespace _EruHazmat {
    /// Allocates memory items with libc or others.
    template <typename _T>
    _T* allocator_pool_creator(size_t size, void *data) {
        return new _T[size];
    }
    template <>
    EruGate* allocator_pool_creator<EruGate>(size_t size, void *data);

    /// Low-level memory deleters. Automatically executed on allocator unscope
    template <typename _T>
    class AllocatorEntryDeleter {
    public:
        AllocatorEntryDeleter(size_t size) {}
        void operator() (_T *ptr) {
            free(ptr);
        }
    };
    template <>
    class AllocatorEntryDeleter<EruGate> {
    private:
        size_t _size;
    public:
        AllocatorEntryDeleter(size_t size);
        void operator() (EruGate *ptr);
    };
}

/// Allocator returned data delegate. Do remember to free this as it would
/// not be done automatically.
template <typename _T>
class EruBits {
private:
    _T *_field;
    size_t __size, __chunk, __offset;
public:
    EruBits(_T *field, size_t size, size_t chunk, size_t offset) :
        _field(field), __size(size), __chunk(chunk), __offset(offset) {}
    size_t _size() {
        return __size;
    }
    size_t _chunk() {
        return __chunk;
    }
    size_t _offset() {
        return __offset;
    }
    _T* foo() {
        _T *p = new _T();
        return p;
    }
    /// Retrieve contained pointer.
    /// @return Pointer to delegated object.
    _T* ptr() {
        return _field;
    }
};

/// Allocator that returns data delegates upon user requirement. The data
/// pointers are guaranteed to be consequent.
template <typename _T>
class EruAllocator {
private:
    std::vector<std::pair<size_t, std::shared_ptr<_T>>> _pool;  // chunks
    std::vector<size_t> _pool_free;  // free size per chunk
    std::vector<std::vector<bool>> _pool_used;  // used blocks per chunk
    size_t _size;  // allocator pool size
    size_t _size_free;  // remaining non-allocated area
    void *_params;  // bootstrap params, leave null if not encrypting
public:
    EruAllocator(size_t default_size, void *params) {
        _pool.clear();
        _pool_free.clear();
        _pool_used.clear();
        _size = 0;
        _size_free = 0;
        _params = params;
        expand(default_size);
    }
    /// Get number of allocated elements.
    /// @return The number of allocated elements with allocate().
    size_t size() {
        return _size;
    }
    /// Increase allocator container size by [size] objects.
    void expand_by(size_t size) {
        // low-level allocate
        _T *ptr = _EruHazmat::allocator_pool_creator<_T>(size, _params);
        auto deleter = _EruHazmat::AllocatorEntryDeleter<_T>(size);
        _pool.push_back(std::make_pair(size, std::shared_ptr<_T>(ptr, deleter)));
        _pool_free.push_back(size);
        _pool_used.push_back(std::vector<bool>(size, false));
        // update flags
        _size += size;
        _size_free += size;
    }
    /// Increase allocator container size up to target_size objects. Pool will
    /// not shrink if given target size is less than actual size.
    void expand(size_t target_size) {
        if (target_size <= _size)
            return ;
        expand_by(target_size - _size);
    }
    /// Allocates consequent memory objects.
    /// @param target_size: number of consequent objects to allocate.
    /// @return Delegate EruBits object to allocated array.
    EruBits<_T> allocate(size_t target_size) {
        // attempts to find consecutive empty blocks
        bool found = false;
        size_t chunk = 0, offset = 0;
        if (_size_free >= target_size)
            for (; chunk < _pool.size(); chunk++) {
                if (_pool_free[chunk] < target_size)
                    continue;
                // scan area
                size_t conseq_empty = 0;  // count of consecutive non-used blocks
                for (offset = 0; offset < target_size && conseq_empty <
                        target_size; offset++) {
                    if (_pool_used[chunk][offset])
                        conseq_empty = 0;
                    else
                        conseq_empty += 1;
                }
                // if current chunk satisfies, mark done
                if (conseq_empty >= target_size) {
                    found = true;
                    break;
                }
            }
        // if no such is found, allocate new chunk
        if (!found) {
            chunk = _pool.size();
            offset = 0;
            expand_by(target_size);
        }
        // mark blocks as used, also maintaining flags
        for (size_t i = 0; i < target_size; i++)
            _pool_used[chunk][offset + i] = true;
        _pool_free[chunk] -= target_size;
        _size_free -= target_size;
        // give this to the caller
        _T *ptr = _pool[chunk].second.get() + offset;
        return EruBits<_T>(ptr, target_size, chunk, offset);
    }
    /// Free allocated object for later use. They will remain in pool anyway.
    void free(EruBits<_T> ptr) {
        size_t size = ptr._size(), chunk = ptr._chunk(),
            offset = ptr._offset();
        for (size_t i = 0; i < ptr._size(); i++)
            _pool_used[chunk][offset + i] = false;
        // does not really free those blocks anyway
        _pool_free[chunk] += size;
        _size_free += size;
    }
};

#endif  // _LIBERU_ALLOC_H
