#ifndef NAPI_COMMON_H
#define NAPI_COMMON_H

#include <pcap/pcap.h>
#include <node_api.h>
#include <string>
#include <cstring>

// Empty value so that macros here are able to return NULL or void
#define RETVAL_NOTHING // Intentionally blank #define

#define THROW_LAST_ERROR(env, assertion)                                    \
    do {                                                                    \
        const napi_extended_error_info* error;                              \
        napi_get_last_error_info((env), &error);                            \
        bool isPending;                                                     \
        napi_is_exception_pending((env), &isPending);                       \
        if (!isPending) {                                                   \
            const char* errorMessage = error->error_message != nullptr      \
                ? error->error_message                                      \
                : "assertion (" #assertion ") failed";                      \
            napi_throw_error((env), nullptr, errorMessage);                 \
        }                                                                   \
    } while (0);

#define ASSERT_CALL_BASE(env, assertion, returnValue)                       \
    do {                                                                    \
        if ((assertion) != napi_ok) {                                       \
            THROW_LAST_ERROR(env, assertion != napi_ok);                    \
            return returnValue;                                             \
        }                                                                   \
    } while (0);

#define ASSERT_BASE(env, assertion, message, returnValue)                   \
    do {                                                                    \
        if (!(assertion)) {                                                 \
            napi_throw_error((env), nullptr, message);                      \
            return returnValue;                                             \
        }                                                                   \
    } while(0); 

#endif

// Returns `NULL` on failed assertion.
#define ASSERT(env, assertion)                                              \
    ASSERT_BASE(                                                            \
        env,                                                                \
        assertion,                                                          \
        "assertion (" #assertion ") failed.",                               \
        nullptr                                                             \
    );

// Returns `NULL` on failed assertion with a custom message.
#define ASSERT_MESSAGE(env, assertion, message)                             \
    ASSERT_BASE(env, assertion, message, nullptr);

// Returns `NULL` if the call doesn't return napi_ok
#define ASSERT_CALL(env, call)                                              \
    ASSERT_CALL_BASE(env, call, nullptr);

// Returns `empty` on failed assertion.
#define ASSERT_VOID(env, assertion)                                         \
    ASSERT_BASE(                                                            \
        env,                                                                \
        assertion,                                                          \
        "assertion (" #assertion ") failed.",                               \
        RETVAL_NOTHING                                                      \
    );

// Returns `empty` on failed assertion with a custom message.
#define ASSERT_MESSAGE_VOID(env, assertion, message)                        \
    ASSERT_BASE(env, assertion, message, RETVAL_NOTHING);

// Returns `empty` if the call doesn't return napi_ok.
#define ASSERT_CALL_VOID(env, assertion)                                    \
    ASSERT_CALL_BASE(env, assertion, RETVAL_NOTHING);

// Declare a method.
#define DECLARE_METHOD(name, fn)                                            \
    { name, 0, fn, 0, 0, 0, napi_default, 0 }

std::string GetStringFromArg(napi_env env, napi_value arg);
int32_t GetNumberFromArg(napi_env env, napi_value arg);
bool GetBooleanFromArg(napi_env env, napi_value arg);

napi_value ReturnBoolean(napi_env env, bool value);
