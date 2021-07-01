
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

#include <map>
#include <stack>

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
    size_t __size;
public:
    EruBits() : _field(nullptr), __size(0) {}
    EruBits(_T *field, size_t size) : _field(field), __size(size) {}
    size_t _size() {
        return __size;
    }
    /// Retrieve contained pointer.
    /// @return Pointer to delegated object.
    _T* ptr() const {
        return _field;
    }
};

/// Allocator that returns data delegates upon user requirement. The data
/// pointers are guaranteed to be consequent.
template <typename _T>
class EruAllocator {
private:
    /// The pool ensures no stack is empty at any time.
    std::map<size_t, std::stack<_T*>> _pool;  // size > stack
    /// This map holds of currently allocated objects.
    std::map<_T*, size_t> _pool_used;
    size_t _size;
    void *_params;  // bootstrap params, leave null if not encrypting
    _T* _pool_get(size_t size) {
        _T *ptr;
        if (_pool.find(size) != _pool.end()) {
            ptr = _pool[size].top();
            _pool[size].pop();
            if (_pool[size].empty())
                _pool.erase(size);
        } else {
            ptr = _EruHazmat::allocator_pool_creator<_T>(size, _params);
        }
        _pool_used[ptr] = size;
        return ptr;
    }
    void _pool_put(_T *ptr, size_t size) {
        if (_pool.find(size) == _pool.end())
            _pool[size] = std::stack<_T*>();
        _pool[size].push(ptr);
        _pool_used.erase(ptr);
    }
public:
    EruAllocator(void *params) {
        _pool.clear();
        _size = 0;
        _params = params;
    }
    ~EruAllocator() {
        for (auto &pr : _pool) {
            auto deleter = _EruHazmat::AllocatorEntryDeleter<_T>(pr.first);
            while (!pr.second.empty()) {
                deleter(pr.second.top());
                pr.second.pop();
            }
        }
        for (auto &pr : _pool_used) {
            _EruHazmat::AllocatorEntryDeleter<_T>(pr.second)(pr.first);
        }
    }
    /// Get number of allocated elements.
    /// @return The number of allocated elements with allocate().
    size_t size() {
        return _size;
    }
    /// Allocates consequent memory objects.
    /// @param size: number of consequent objects to allocate.
    /// @return Delegate EruBits object to allocated array.
    EruBits<_T> allocate(size_t size) {
        _T *ptr = _pool_get(size);
        return EruBits<_T>(ptr, size);
    }
    /// Free allocated object for later use. They will remain in pool anyway.
    void free(EruBits<_T> ptr) {
        _pool_put(ptr.ptr(), ptr._size());
    }
};

#endif  // _LIBERU_ALLOC_H
