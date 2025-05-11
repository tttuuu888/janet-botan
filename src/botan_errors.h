/*
 * Copyright (c) 2024, Janet-botan Seungki Kim
 *
 * Janet-botan is released under the MIT License, see the LICENSE file.
 */

#ifndef BOTAN_ERRORS_H
#define BOTAN_ERRORS_H

#define JANET_BOTAN_ASSERT(ret_from_ffi)            \
    if (ret_from_ffi < 0) {                         \
        janet_panic(getBotanError(ret_from_ffi));   \
    }                                               \

static const char* getBotanError(int error) {
    switch(error) {
        case BOTAN_FFI_SUCCESS:
            return "BOTAN_FFI_SUCCESS";

        case BOTAN_FFI_INVALID_VERIFIER:
            return "BOTAN_FFI_INVALID_VERIFIER";

        case BOTAN_FFI_ERROR_INVALID_INPUT:
            return "BOTAN_FFI_ERROR_INVALID_INPUT";
        case BOTAN_FFI_ERROR_BAD_MAC:
            return "BOTAN_FFI_ERROR_BAD_MAC";
        case BOTAN_FFI_ERROR_NO_VALUE:
            return "BOTAN_FFI_ERROR_NO_VALUE";

        case BOTAN_FFI_ERROR_INSUFFICIENT_BUFFER_SPACE:
            return "BOTAN_FFI_ERROR_INSUFFICIENT_BUFFER_SPACE";
        case BOTAN_FFI_ERROR_STRING_CONVERSION_ERROR:
            return "BOTAN_FFI_ERROR_STRING_CONVERSION_ERROR";

        case BOTAN_FFI_ERROR_EXCEPTION_THROWN:
            return "BOTAN_FFI_ERROR_EXCEPTION_THROWN";
        case BOTAN_FFI_ERROR_OUT_OF_MEMORY:
            return "BOTAN_FFI_ERROR_OUT_OF_MEMORY";
        case BOTAN_FFI_ERROR_SYSTEM_ERROR:
            return "BOTAN_FFI_ERROR_SYSTEM_ERROR";
        case BOTAN_FFI_ERROR_INTERNAL_ERROR:
            return "BOTAN_FFI_ERROR_INTERNAL_ERROR";

        case BOTAN_FFI_ERROR_BAD_FLAG:
            return "BOTAN_FFI_ERROR_BAD_FLAG";
        case BOTAN_FFI_ERROR_NULL_POINTER:
            return "BOTAN_FFI_ERROR_NULL_POINTER";
        case BOTAN_FFI_ERROR_BAD_PARAMETER:
            return "BOTAN_FFI_ERROR_BAD_PARAMETER";
        case BOTAN_FFI_ERROR_KEY_NOT_SET:
            return "BOTAN_FFI_ERROR_KEY_NOT_SET";
        case BOTAN_FFI_ERROR_INVALID_KEY_LENGTH:
            return "BOTAN_FFI_ERROR_INVALID_KEY_LENGTH";
        case BOTAN_FFI_ERROR_INVALID_OBJECT_STATE:
            return "BOTAN_FFI_ERROR_INVALID_OBJECT_STATE";

        case BOTAN_FFI_ERROR_NOT_IMPLEMENTED:
            return "BOTAN_FFI_ERROR_NOT_IMPLEMENTED";
        case BOTAN_FFI_ERROR_INVALID_OBJECT:
            return "BOTAN_FFI_ERROR_INVALID_OBJECT";

        case BOTAN_FFI_ERROR_TLS_ERROR:
            return "BOTAN_FFI_ERROR_TLS_ERROR";
        case BOTAN_FFI_ERROR_HTTP_ERROR:
            return "BOTAN_FFI_ERROR_HTTP_ERROR";
        case BOTAN_FFI_ERROR_ROUGHTIME_ERROR:
            return "BOTAN_FFI_ERROR_ROUGHTIME_ERROR";
        case BOTAN_FFI_ERROR_TPM_ERROR:
            return "BOTAN_FFI_ERROR_TPM_ERROR";

        case BOTAN_FFI_ERROR_UNKNOWN_ERROR:
            return "BOTAN_FFI_ERROR_UNKNOWN_ERROR";
        default:
            return "BOTAN_FFI_ERROR_UNKNOWN_ERROR";
    }
}

#endif /* BOTAN_ERRORS_H */
