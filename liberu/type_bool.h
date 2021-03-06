
#ifndef _LIBERU_TYPE_BOOL
#define _LIBERU_TYPE_BOOL

#include "context.h"


template <typename _T>
class EruBool {
private:
    EruContext<_T> *_ctx;
    EruBits<_T> _value;
    /// If this is set to false, _value does not need to be freed. In theory
    /// this value will never be false as long as it's not a temporary rvalue.
    bool _active;
    /// Frees _value manually. Uses _active to avoid double-free.
    void _free() {
        if (_active) {
            _ctx->free(_value);
            _active = false;
        }
    }
    /// If another object is not within the same context as this is, throw.
    void _check_sibling(EruBool<_T> *other) {
        if (_ctx != other->_ctx)
            throw std::runtime_error("attempting cross-context arithmetic");
    }
public:
    /// Get delegated pointer. Dangerous!
    _T* _ptr() const {
        return _value.ptr();
    }
    /// Raw constructor. Value undetermined.
    EruBool(EruContext<_T> *ctx) : _ctx(ctx), _active(true) {
        _value = _ctx->allocate(1);
    }
    /// Constructs with predetermined value.
    EruBool(EruContext<_T> *ctx, EruBits<_T> value) : _ctx(ctx),
        _value(value), _active(true) {}
    /// Copy constructor that really copies data...
    /// EruBool this(other);
    EruBool(const EruBool<_T> &other) : _ctx(other._ctx), _active(true) {
        _value = _ctx->allocate(1);
        _ctx->_env()->ldup(_ptr(), other._ptr());
    }
    /// Copy constructor. Will not copy itself.
    /// EruBool this = other;
    EruBool<_T>& operator = (EruBool<_T> &other) {
        if (this == *other)
            return *this;
        _check_sibling(&other);
        _ctx->_env()->ldup(_ptr(), other._ptr());
        return *this;
    }
    /// Move constructor.
    /// EruBool this = (other_expr);
    EruBool<_T>& operator = (EruBool<_T> &&other) {
        _check_sibling(&other);
        _free();
        _ctx = other._ctx;
        _value = other._value;
        _active = true;
        other._active = false;  // won't free over there this time
        return *this;
    }
    /// Destructor.
    ~EruBool() {
        _free();
    }
    /// Encrypt & decrypt
    void encrypt(const bool value) {
        _ctx->_env()->encrypt(_ptr(), value);
    }
    bool decrypt() {
        return _ctx->_env()->decrypt(_ptr());
    }
    /// Import & export
    void bimport(const EruData &data) {
        _ctx->_env()->bimport(_ptr(), data);
    }
    EruData bexport() {
        return _ctx->_env()->bexport(_ptr());
    }
    /// Sets constant value to value.
    EruBool<_T>& operator = (const bool value) {
        _ctx->_env()->lval(_ptr(), value);
        return *this;
    }
    // Unary operations
    #define eru_bool_unary_op(op, env_op)                                     \
    EruBool<_T> op () {                                                       \
        EruBits<_T> result = _ctx->allocate(1);                               \
        _ctx->_env()->env_op(result.ptr(), _ptr());                           \
        return EruBool<_T>(_ctx, result);                                     \
    }
    eru_bool_unary_op(operator !, lnot);
    eru_bool_unary_op(operator ~, lnot);
    #undef eru_bool_unary_op
    // Binary operations.
    #define eru_bool_binary_op(op, env_op)                                    \
    EruBool<_T> op (EruBool<_T> &other) {                                     \
        EruBits<_T> result = _ctx->allocate(1);                               \
        _ctx->_env()->env_op(result.ptr(), _ptr(), other._ptr());             \
        return EruBool<_T>(_ctx, result);                                     \
    }
    eru_bool_binary_op(operator &&, land);
    eru_bool_binary_op(operator ||, lor);
    eru_bool_binary_op(operator ^, lxor);
    eru_bool_binary_op(operator &, land);
    eru_bool_binary_op(operator |, lor);
    eru_bool_binary_op(operator ==, lxnor);
    eru_bool_binary_op(operator !=, lxor);
    #undef eru_bool_binary_op
};

#endif  // _LIBERU_TYPE_BOOL
