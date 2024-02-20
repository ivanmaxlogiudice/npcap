#ifndef NAPI_COMMON_H
#define NAPI_COMMON_H

#include <node_api.h>

// Empty value so that macros here are able to return NULL or void
#define NODE_API_RETVAL_NOTHING // Intentionally blank #define

#define assert_base(env, assertion, message, returnValue)           \
    do {                                                            \
        if (!(assertion)) {                                         \
            napi_throw_error(env, NULL, message);                   \
            return returnValue;                                     \
        }                                                           \
    } while(0)                                                      \

// Returns NULL on failed assertion.
#define assert(env, assertion)                                      \
    assert_base(                                                    \
        env,                                                        \
        assertion,                                                  \
        "assertion (" #assertion ") failed",                        \
        NULL                                                        \
    )

// Returns empty on failed assertion.
#define assert_void(env, assertion)                                 \
    assert_base(                                                    \
        env,                                                        \
        assertion,                                                  \
        "assertion (" #assertion ") failed",                        \
        NODE_API_RETVAL_NOTHING                                     \
    )

// Returns NULL on failed assertion.
#define assert_message(env, assertion, message)                     \
    assert_base(env, assertion, message, NULL)

// Returns empty on failed assertion.
#define assert_message_void(env, assertion, message)                \
    assert_base(env, assertion, message, NODE_API_RETVAL_NOTHING)

#define assert_call(env, assertion)                                 \
    assert_base(                                                    \
        env,                                                        \
        (napi_ok == assertion),                                     \
        "assertion (" #assertion ") failed",                        \
        NULL                                                        \
    )

#define declare_method(name, fn)                                    \
    { name, 0, fn, 0, 0, 0, napi_default, 0 }

const char* GetStringFromArg(napi_env env, napi_value arg);
const int32_t GetNumberFromArg(napi_env env, napi_value arg);
const bool GetBooleanFromArg(napi_env env, napi_value arg);

#endif
