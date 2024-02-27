#include "common.h"

const char* GetStringFromArg(napi_env env, napi_value arg) {
    size_t bufferSize;
    ASSERT_CALL(env, napi_get_value_string_utf8(env, arg, nullptr, 0, &bufferSize));
    
    char* buffer = new char[bufferSize + 1];
    ASSERT_CALL(env, napi_get_value_string_utf8(env, arg, buffer, bufferSize + 1, nullptr));

    return buffer;
}

const int32_t GetNumberFromArg(napi_env env, napi_value arg) {
    int32_t number;
    napi_get_value_int32(env, arg, &number);

    return number;
}

const bool GetBooleanFromArg(napi_env env, napi_value arg) {
    bool isBoolean;
    napi_get_value_bool(env, arg, &isBoolean);

    return isBoolean;
}

napi_value ReturnBoolean(napi_env env, bool value) {
    napi_value returnValue;
    ASSERT_CALL(env, napi_get_boolean(env, value, &returnValue));

    return returnValue;
}
