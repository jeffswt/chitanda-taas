
// liberu_alloc.cpp: default allocator
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

#include "liberu_alloc.h"


// Allocated object container

template <typename _T>
EruBits<_T>::EruBits(_T *field, size_t size, size_t chunk, size_t offset) :
    _field(field), __size(size), __chunk(chunk), __offset(offset) {}

template <typename _T>
size_t EruBits<_T>::_size() {
    return __size;
}

template <typename _T>
size_t EruBits<_T>::_chunk() {
    return __chunk;
}

template <typename _T>
size_t EruBits<_T>::_offset() {
    return __offset;
}

template <typename _T>
_T* EruBits<_T>::ptr() {
    return _field;
}

// Memory allocation related

template <typename _T>
EruAllocator<_T>::EruAllocator(size_t default_size, void *params) {
    _pool.clear();
    _pool_free.clear();
    _pool_used.clear();
    _size = 0;
    _size_free = 0;
    _params = params;
    expand(default_size);
}

// Low-level memory allocators..
template <typename _T>
_T* _eru_allocator_pool_entry_creator(size_t size, void *data) {
    return new _T[size];
}
template <>
EruGate* _eru_allocator_pool_entry_creator<EruGate>(size_t size, void *data) {
    auto params = (TFheGateBootstrappingParameterSet*)data;
    return new_gate_bootstrapping_ciphertext_array(size, params);
}

// Low-level memory deleters. Automatically executed on EruAllocator unscope
template <typename _T>
class _EruAllocatorPoolEntryDeleter {
public:
    _EruAllocatorPoolEntryDeleter(size_t size) {}
    void operator() (_T *ptr) {
        free(ptr);
    }
};
template <>
class _EruAllocatorPoolEntryDeleter<EruGate> {
private:
    size_t _size;
public:
    _EruAllocatorPoolEntryDeleter(size_t size) : _size(size) {}
    void operator() (EruGate *ptr) {
        delete_gate_bootstrapping_ciphertext_array(_size, ptr);
    }
};

template <typename _T>
void EruAllocator<_T>::expand_by(size_t size) {
    // low-level allocate
    _T *ptr = _eru_allocator_pool_entry_creator<_T>(size, _params);
    auto deleter = _EruAllocatorPoolEntryDeleter<_T>(size);
    _pool.push_back(std::make_pair(size, std::shared_ptr<_T>(ptr, deleter)));
    _pool_free.push_back(size);
    _pool_used.push_back(std::vector<bool>(size, false));
    // update flags
    _size += size;
    _size_free += size;
}

template <typename _T>
void EruAllocator<_T>::expand(size_t target_size) {
    if (target_size <= _size)
        return ;
    expand_by(target_size - _size);
}

template <typename _T>
EruBits<_T> EruAllocator<_T>::allocate(size_t target_size) {
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

template <typename _T>
void EruAllocator<_T>::free(EruBits<_T> ptr) {
    size_t size = ptr._size(), chunk = ptr._chunk(), offset = ptr._offset();
    for (size_t i = 0; i < ptr._size(); i++)
        _pool_used[chunk][offset + i] = false;
    // does not really free those blocks anyway
    _pool_free[chunk] += size;
    _size_free += size;
}
