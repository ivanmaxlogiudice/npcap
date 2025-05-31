#include "common.h"
#include <string>

std::string GetStringFromArg(napi_env env, napi_value arg) {
    size_t bufferSize;
    ASSERT_CALL(env, napi_get_value_string_utf8(env, arg, nullptr, 0, &bufferSize));
    
    std::string result(bufferSize, '\0');
    ASSERT_CALL(env, napi_get_value_string_utf8(env, arg, &result[0], bufferSize + 1, nullptr));
    
    return result;
}

int32_t GetNumberFromArg(napi_env env, napi_value arg) {
    int32_t number;
    napi_get_value_int32(env, arg, &number);

    return number;
}

bool GetBooleanFromArg(napi_env env, napi_value arg) {
    bool isBoolean;
    napi_get_value_bool(env, arg, &isBoolean);

    return isBoolean;
}

napi_value ReturnBoolean(napi_env env, bool value) {
    napi_value returnValue;
    ASSERT_CALL(env, napi_get_boolean(env, value, &returnValue));

    return returnValue;
}
