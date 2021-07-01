
#ifndef _LIBERU_TYPE_INT
#define _LIBERU_TYPE_INT

#include "context.h"
#include "type_bool.h"


/// Integer stored in little-endian format.
/// 0     1     ... Size-2      Size-1
/// [2^0] [2^1] ... [2^_Size-1] [sign: 0 = positive, 1 = negative]
template <typename _T, size_t _Size>
class EruIntGeneral {
private:
    EruContext<_T> *_ctx;
    EruBits<_T> _value;
    bool _active;
    void _free() {
        if (_active) {
            _ctx->free(_value);
            _active = false;
        }
    }
    void _check_sibling(EruIntGeneral<_T, _Size> *other) {
        if (_ctx != other->_ctx)
            throw std::runtime_error("attempting cross-context arithmetic");
    }
    /// Hidden assignment operation
    void _assign(int64_t value) {
        auto env = _ctx->_env();
        auto p = _ptr();
        if (value >= 0) {
            for (size_t i = 0; i < 63; i++)
                env->lval(p + i, (value & (1ll << i)) ? true : false);
            for (size_t i = 63; i < _Size; i++)
                env->lval(p + i, false);
        } else {
            uint64_t *uvalue = (uint64_t*)&value;
            for (size_t i = 0; i < 64; *uvalue >>= 1, i++)
                env->lval(p + i, (*uvalue & 1) ? true : false);
            for (size_t i = 64; i < _Size; i++)
                env->lval(p + i, true);
        }
    }
public:
    /// Get delegated pointer. Dangerous!
    _T* _ptr() const {
        return _value.ptr();
    }
    /// Raw constructor. Value undetermined.
    EruIntGeneral(EruContext<_T> *ctx) : _ctx(ctx), _active(true) {
        _value = _ctx->allocate(_Size);
    }
    /// Constructs with predetermined value.
    EruIntGeneral(EruContext<_T> *ctx, EruBits<_T> value) : _ctx(ctx),
        _value(value), _active(true) {}
    /// Copy constructor that really copies data...
    /// EruIntGeneral this(other);
    EruIntGeneral(const EruIntGeneral<_T, _Size> &other) : _ctx(other._ctx),
            _active(true) {
        _value = _ctx->allocate(_Size);
        auto env = _ctx->_env();
        auto p1 = _ptr(), p2 = other._ptr();
        for (size_t i = 0; i < _Size; i++)
            env->ldup(p1 + i, p2 + i);
    }
    /// Copy constructor. Will not copy itself.
    /// EruIntGeneral this = other;
    EruIntGeneral<_T, _Size>& operator = (EruIntGeneral<_T, _Size> &other) {
        if (this == &other)
            return *this;
        _check_sibling(&other);
        auto env = _ctx->_env();
        auto p1 = _ptr(), p2 = other._ptr();
        for (size_t i = 0; i < _Size; i++)
            env->ldup(p1 + i, p2 + i);
        return *this;
    }
    /// Move constructor.
    /// EruIntGeneral this = (other_expr);
    EruIntGeneral<_T, _Size>& operator = (EruIntGeneral<_T, _Size> &&other) {
        _check_sibling(&other);
        _free();
        _ctx = other._ctx;
        _value = other._value;
        _active = true;
        other._active = false;  // won't free over there this time
        return *this;
    }
    /// Destructor.
    ~EruIntGeneral() {
        _free();
    }
    /// Encrypt & decrypt
    void encrypt(const int64_t value) {
        _assign(value);
    }
    int64_t decrypt() {
        uint64_t result = 0;
        auto env = _ctx->_env();
        auto p = _ptr();
        for (size_t i = 0; i < 64 && i < _Size; i++)
            if (env->decrypt(p + i))
                result |= (uint64_t)1 << i;
        return static_cast<int64_t>(result);
    }
    /// Import & export
    void bimport(const EruData &data) {
        auto split = _EruHazmat::binobjlist_decode(data);
        auto env = _ctx->_env();
        auto p = _ptr();
        for (size_t i = 0; i < _Size; i++)
            env->bimport(p + i, split[i]);
    }
    EruData bexport() {
        std::vector<EruData> tmp;
        auto env = _ctx->_env();
        auto p = _ptr();
        for (size_t i = 0; i < _Size; i++)
            tmp.push_back(env->bexport(p + i));
        return _EruHazmat::binobjlist_encode(tmp);
    }
    /// Sets constant value.
    EruIntGeneral<_T, _Size>& operator = (const int64_t value) {
        _assign(value);
        return *this;
    }
    /// Addition.
    EruIntGeneral<_T, _Size> operator + (EruIntGeneral<_T, _Size> &other) {
        _check_sibling(&other);
        EruBits<_T> res = _ctx->allocate(_Size);
        EruBits<_T> carry = _ctx->allocate(3);  // 0 stores the data
        auto env = _ctx->_env();
        auto a = _ptr(), b = other._ptr(), c = res.ptr(), pc = carry.ptr();
        env->lval(pc, false);
        for (size_t i = 0; i < _Size; i++) {
            // c[i] = a[i] ^ b[i] ^ carry[0]
            //   carry[1] = a[i] ^ b[i],
            //   c[i] = carry[1] ^ carry[0]
            env->lxor(pc + 1, a + i, b + i);
            env->lxor(c + i, pc + 1, pc + 0);
            // carry = count(a[i], b[i], c[i]) >= 2
            //   carry[1] = a[i] && carry[0],
            //   carry[2] = b[i] && carry[0],
            //   carry[2] = carry[1] || carry[2],
            //   carry[1] = a[i] && b[i],
            //   carry[0] = carry[1] || carry[2]
            env->land(pc + 1, a + i, pc);
            env->land(pc + 2, b + i, pc);
            env->lor(pc + 2, pc + 1, pc + 2);
            env->land(pc + 1, a + i, b + i);
            env->lor(pc, pc + 1, pc + 2);
        }
        _ctx->free(carry);
        return EruIntGeneral<_T, _Size>(_ctx, res);
    }
    EruIntGeneral<_T, _Size>& operator += (EruIntGeneral<_T, _Size> &other) {
        _check_sibling(&other);
        auto res = *this + other;
        _free();
        _value = res._value;
        _active = true;
        res._active = false;
        return *this;
    }
    /// Subtraction.
    EruIntGeneral<_T, _Size> operator - (EruIntGeneral<_T, _Size> &other) {
        _check_sibling(&other);
        EruBits<_T> res = _ctx->allocate(_Size);
        EruBits<_T> borrow = _ctx->allocate(2);  // 0 stores the data
        auto env = _ctx->_env();
        auto a = _ptr(), b = other._ptr(), c = res.ptr(), pb = borrow.ptr();
        env->lval(pb, false);
        for (size_t i = 0; i < _Size; i++) {
            // c[i] = a[i] ^ b[i] ^ borrow[0]
            //   borrow[1] = a[i] ^ b[i],
            //   c[i] = borrow[1] ^ borrow[0]
            env->lxor(pb + 1, a + i, b + i);
            env->lxor(c + i, pb + 1, pb);
            // borrow[0] = (b[i] && borrow[0]) || (a[i] == 0 && b[i] == 1) ||
            //     (a[i] == 0 && borrow[0] == 1)
            //   borrow[1] = b[i] || borrow[0]
            //   borrow[1] = !a[i] && borrow[1]
            //   borrow[0] = b[i] && borrow[0]
            //   borrow[0] = borrow[0] || borrow[1]
            env->lor(pb + 1, b + i, pb);
            env->landny(pb + 1, a + i, pb + 1);
            env->land(pb, b + i, pb);
            env->lor(pb, pb, pb + 1);
        }
        _ctx->free(borrow);
        return EruIntGeneral<_T, _Size>(_ctx, res);
    }
    EruIntGeneral<_T, _Size>& operator -= (EruIntGeneral<_T, _Size> &other) {
        _check_sibling(&other);
        auto res = *this - other;
        _free();
        _value = res._value;
        _active = true;
        res._active = false;
        return *this;
    }
    /// Negate value.
    EruIntGeneral<_T, _Size> operator - () {
        EruBits<_T> res = _ctx->allocate(_Size);
        EruBits<_T> flag = _ctx->allocate(1);  // 01111..1
        auto env = _ctx->_env();
        auto a = _ptr(), b = res.ptr(), pf = flag.ptr();
        env->lval(pf, false);
        for (size_t i = 0; i < _Size; i++) {
            // b[i] = flag ? !a[i] : a[i]
            //   b[i] = a[i] ^ flag;
            env->lxor(b + i, a + i, pf);
            // flag = flag | a[i];
            env->lor(pf, pf, a + i);
        }
        _ctx->free(flag);
        return EruIntGeneral<_T, _Size>(_ctx, res);
    }
    /// Left-shift (equiv. *2)
    EruIntGeneral<_T, _Size> operator << (int64_t bits) {
        if (bits < 0)
            return *this >> (-bits);
        EruBits<_T> res = _ctx->allocate(_Size);
        auto env = _ctx->_env();
        auto a = _ptr(), b = res.ptr();
        for (size_t i = _Size; i >= 1 && i >= bits + 1; i--)
            env->ldup(b + (i - 1), a + (i - bits - 1));
        for (size_t i = bits; i >= 1; i--)
            env->lval(b + (i - 1), false);
        return EruIntGeneral<_T, _Size>(_ctx, res);
    }
    EruIntGeneral<_T, _Size>& operator <<= (int64_t bits) {
        if (bits < 0) {
            *this >>= (-bits);
            return *this;
        }
        auto env = _ctx->_env();
        auto a = _ptr();
        for (size_t i = _Size; i >= 1 && i >= bits + 1; i--)
            env->ldup(a + (i - 1), a + (i - bits - 1));
        for (size_t i = bits; i >= 1; i--)
            env->lval(a + (i - 1), false);
        return *this;
    }
    /// Right-shift (equiv. /2)
    EruIntGeneral<_T, _Size> operator >> (int64_t bits) {
        if (bits < 0)
            return *this << (-bits);
        EruBits<_T> res = _ctx->allocate(_Size);
        auto env = _ctx->_env();
        auto a = _ptr(), b = res.ptr();
        size_t i;
        for (i = 0; i + bits < _Size; i++)
            env->ldup(b + i, a + i + bits);
        for (; i < _Size; i++)
            env->ldup(b + i, a + (_Size - 1));
        return EruIntGeneral<_T, _Size>(_ctx, res);
    }
    EruIntGeneral<_T, _Size> operator >>= (int64_t bits) {
        if (bits < 0) {
            *this <<= (-bits);
            return *this;
        }
        auto env = _ctx->_env();
        auto a = _ptr();
        size_t i;
        for (i = 0; i + bits < _Size; i++)
            env->ldup(a + i, a + i + bits);
        for (; i + 1 < _Size; i++)
            env->ldup(a + i, a + (_Size - 1));
        return *this;
    }
    /// Multiply!
    EruIntGeneral<_T, _Size> operator * (EruIntGeneral<_T, _Size> &other) {
        _check_sibling(&other);
        // using two's complement mean's that we won't need to care about
        // signs during the calculation
        EruIntGeneral<_T, _Size> res(_ctx);
        EruIntGeneral<_T, _Size> tmp(_ctx);
        auto env = _ctx->_env();
        auto p1 = _ptr();
        res = 0;
        for (size_t i = 0; i < _Size; i++) {
            tmp = other;
            tmp <<= i;
            auto p2 = tmp._ptr();
            for (size_t j = 0; j < _Size; j++)
                env->land(p2 + j, p2 + j, p1 + i);
            res += tmp;
        }
        return res;
    }
    EruIntGeneral<_T, _Size>& operator *= (EruIntGeneral<_T, _Size> &other) {
        _check_sibling(&other);
        auto res = *this * other;
        _free();
        _value = res._value;
        _active = true;
        res._active = false;
        return *this;
    }
};

// template <typename _T>
// class EruInt : EruIntGeneral<_T, 64> {};

#endif  // _LIBERU_TYPE_INT
