/*
 * Copyright (c) 2024, Janet-botan Seungki Kim
 *
 * Janet-botan is released under the Simplified BSD License. (see LICENSE)
 */

#ifndef UTILITY_H
#define UTILITY_H

static Janet cfun_constant_time_compare(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 2);
    JanetByteView x = janet_getbytes(argv, 0);
    JanetByteView y = janet_getbytes(argv, 1);
    if (x.len != y.len)
        return janet_wrap_false();
    int ret = botan_constant_time_compare(x.bytes, y.bytes, x.len);
    return janet_wrap_boolean(ret == 0);
}

static Janet cfun_hex_encode(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 1);
    JanetByteView bin = janet_getbytes(argv, 0);
    JanetBuffer *encoded = janet_buffer(bin.len * 2);
    int ret = botan_hex_encode(bin.bytes, bin.len, (char*)encoded->data, 0);
    if (ret) {
        janet_panic(getBotanError(ret));
    }
    encoded->count = bin.len * 2;
    return janet_wrap_buffer(encoded);
}

static Janet cfun_hex_decode(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 1);
    JanetByteView str = janet_getbytes(argv, 0);
    JanetBuffer *decoded = janet_buffer(str.len);
    size_t out_len;
    int ret = botan_hex_decode(str.bytes, str.len, (char*)decoded->data, &out_len);
    if (ret) {
        janet_panic(getBotanError(ret));
    }
    decoded->count = out_len;
    return janet_wrap_buffer(decoded);
}

static JanetReg utility_cfuns[] = {
    {"constant-time-compare", cfun_constant_time_compare,
     "(constant-time-compare x y)\n\n"
     "Check if buffer `x` equals buffer `y`. Returns a boolean."
    },
    {"hex-encode", cfun_hex_encode, "(hex-encode bin)\n\n"
     "Performs hex encoding of binary data in `bin`. Returns the buffer."
    },
    {"hex-decode", cfun_hex_decode, "(hex-decode str)\n\n"
     "Performs hex decoding of string data in `str`. Returns the buffer."
    },
    {NULL, NULL, NULL}
};

#endif /* UTILITY_H */
