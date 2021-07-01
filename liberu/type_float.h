
#ifndef _LIBERU_TYPE_FLOAT
#define _LIBERU_TYPE_FLOAT

#include "context.h"
#include "type_int.h"


/// Floating-point number stored in IEEE-754-like format. Currently missing
/// NaN support.
template <typename _T, size_t _ExpSize, size_t _DigSize>
class EruFloatGeneral {
private:
    typedef EruFloatGeneral<_T, _ExpSize, _DigSize> _Self;
    typedef EruIntGeneral<_T, _ExpSize> _ExpInt;
    typedef EruIntGeneral<_T, (_DigSize + 1) * 2> _DigInt;
    static constexpr size_t _Size = 1 + _ExpSize + _DigSize;
    EruContext<_T> *_ctx;
    EruBits<_T> _value;
    bool _active;
    void _free() {
        if (_active) {
            _ctx->free(_value);
            _active = false;
        }
    }
    void _check_sibling(_Self *other) {
        if (_ctx != other->_ctx)
            throw std::runtime_error("attempting cross-context arithmetic");
    }
    /// Hidden assignment operation
    void _assign(double value) {
        const size_t d_exp = 11, d_dig = 52;
        uint64_t iv = *(uint64_t*)(&value);
        auto env = _ctx->_env();
        auto p = _ptr();
        // set sign
        #define bitof(t, x) ((t & ((uint64_t)1 << (x))) == 0 ? false : true)
        env->lval(p + _DigSize + _ExpSize, bitof(iv, d_dig + d_exp));
        // set exponent
        uint64_t exp = 0;  // on f64, exp -= 1023
        for (size_t i = 0; i < d_exp; i++)
            exp |= ((iv >> (d_dig + i)) & 1) << i;
        exp -= ((uint64_t)1 << (d_exp - 1)) - 1;
        exp += ((uint64_t)1 << (_ExpSize - 1)) - 1;
        for (size_t i = 0; i < _ExpSize; i++)
            env->lval(p + _DigSize + i, bitof(exp, i));
        // set fraction
        size_t i = 0;
        for (i = 0; i < d_dig && i < _DigSize; i++)
            env->lval(p + _DigSize - 1 - i, bitof(iv, d_dig - 1 - i));
        for (; i < _DigSize; i++)
            env->lval(p + _DigSize - 1 - i, false);
        #undef bitof
    }
public:
    /// Get delegated pointer. Dangerous!
    _T* _ptr() const {
        return _value.ptr();
    }
    /// Raw constructor. Value undetermined.
    EruFloatGeneral(EruContext<_T> *ctx) : _ctx(ctx), _active(true) {
        _value = _ctx->allocate(_Size);
    }
    /// Constructs with predetermined value.
    EruFloatGeneral(EruContext<_T> *ctx, EruBits<_T> value) : _ctx(ctx),
        _value(value), _active(true) {}
    /// Copy constructor that really copies data...
    /// EruFloatGeneral this(other);
    EruFloatGeneral(const _Self &other) : _ctx(other._ctx),
            _active(true) {
        _value = _ctx->allocate(_Size);
        auto env = _ctx->_env();
        auto p1 = _ptr(), p2 = other._ptr();
        for (size_t i = 0; i < _Size; i++)
            env->ldup(p1 + i, p2 + i);
    }
    /// Copy constructor. Will not copy itself.
    /// EruIntGeneral this = other;
    _Self& operator = (_Self &other) {
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
    /// EruFloatGeneral this = (other_expr);
    _Self& operator = (_Self &&other) {
        _check_sibling(&other);
        _free();
        _ctx = other._ctx;
        _value = other._value;
        _active = true;
        other._active = false;  // won't free over there this time
        return *this;
    }
    /// Destructor.
    ~EruFloatGeneral() {
        _free();
    }
    /// Encrypt & decrypt
    void encrypt(const double value) {
        _assign(value);
    }
    double decrypt() {
        const size_t d_exp = 11, d_dig = 52;
        uint64_t result = 0;
        auto env = _ctx->_env();
        auto p = _ptr();
        // extract sign
        #define setbit(t, x, y) t |= (env->decrypt(p + (y)) ?                 \
            (uint64_t)1 : 0) << (x)
        // extract exponent
        uint64_t exp = 0;  // on f64, exp -= 1023
        for (size_t i = 0; i < _ExpSize; i++)
            setbit(exp, i, _DigSize + i);
        exp -= ((uint64_t)1 << (_ExpSize - 1)) - 1;
        exp += ((uint64_t)1 << (d_exp - 1)) - 1;
        for (size_t i = 0; i < d_exp; i++)
            result |= ((exp >> i) & 1) << (d_dig + i);
        // extract fraction
        for (size_t i = 0; i < _DigSize && i < d_dig; i++)
            setbit(result, d_dig - 1 - i, _DigSize - 1 - i);
        #undef setbit
        return *(double*)(&result);
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
    _Self& operator = (const double value) {
        _assign(value);
        return *this;
    }
};

#define EruFloat16(_T) EruFloatGeneral<_T, 5, 10>
#define EruFloat32(_T) EruFloatGeneral<_T, 8, 23>
#define EruFloat64(_T) EruFloatGeneral<_T, 11, 52>
#define EruFloat128(_T) EruFloatGeneral<_T, 15, 112>
#define EruFloat256(_T) EruFloatGeneral<_T, 19, 236>
#define EruFloat(_T) EruFloatGeneral<_T, 8, 23>
#define EruDouble(_T) EruFloatGeneral<_T, 11, 52>

#endif  // _LIBERU_TYPE_FLOAT
