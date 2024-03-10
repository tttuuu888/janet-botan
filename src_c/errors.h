/*
 * Copyright (c) 2024, Janet-botan Seungki Kim
 *
 * Janet-botan is released under the MIT License. (see LICENSE)
 */

#ifndef ERRORS_H
#define ERRORS_H

#define JANET_BOTAN_ASSERT(ret_from_ffi)            \
    if (ret_from_ffi) {                             \
        janet_panic(getBotanError(ret_from_ffi));   \
    }                                               \

static const char* getBotanError(int error) {
    switch(error) {
    case 0:     return "BOTAN_FFI_SUCCESS";
    case 1:     return "BOTAN_FFI_INVALID_VERIFIER";
    case -1:    return "BOTAN_FFI_ERROR_INVALID_INPUT";
    case -2:    return "BOTAN_FFI_ERROR_BAD_MAC";
    case -10:   return "BOTAN_FFI_ERROR_INSUFFICIENT_BUFFER_SPACE";
    case -11:   return "BOTAN_FFI_ERROR_STRING_CONVERSION_ERROR";
    case -20:   return "BOTAN_FFI_ERROR_EXCEPTION_THROWN";
    case -21:   return "BOTAN_FFI_ERROR_OUT_OF_MEMORY";
    case -22:   return "BOTAN_FFI_ERROR_SYSTEM_ERROR";
    case -23:   return "BOTAN_FFI_ERROR_INTERNAL_ERROR";
    case -30:   return "BOTAN_FFI_ERROR_BAD_FLAG";
    case -31:   return "BOTAN_FFI_ERROR_NULL_POINTER";
    case -32:   return "BOTAN_FFI_ERROR_BAD_PARAMETER";
    case -33:   return "BOTAN_FFI_ERROR_KEY_NOT_SET";
    case -34:   return "BOTAN_FFI_ERROR_INVALID_KEY_LENGTH";
    case -35:   return "BOTAN_FFI_ERROR_INVALID_OBJECT_STATE";
    case -40:   return "BOTAN_FFI_ERROR_NOT_IMPLEMENTED";
    case -50:   return "BOTAN_FFI_ERROR_INVALID_OBJECT";
    case -75:   return "BOTAN_FFI_ERROR_TLS_ERROR";
    case -76:   return "BOTAN_FFI_ERROR_HTTP_ERROR";
    case -77:   return "BOTAN_FFI_ERROR_ROUGHTIME_ERROR";
    case -100:  return "BOTAN_FFI_ERROR_UNKNOWN_ERROR";
    default:    return "BOTAN_FFI_ERROR_UNKNOWN_ERROR";
    }
}

#endif /* ERRORS_H */
