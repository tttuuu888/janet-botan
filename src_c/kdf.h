/*
 * Copyright (c) 2024, Janet-botan Seungki Kim
 *
 * Janet-botan is released under the MIT License. (see LICENSE)
 */

#ifndef KDF_H
#define KDF_H

static Janet cfun_kdf(int32_t argc, Janet *argv) {
    janet_arity(argc, 4, 5);
    const char *algo = janet_getcstring(argv, 0);
    size_t out_len = janet_getsize(argv, 1);
    JanetByteView secret = janet_getbytes(argv, 2);
    JanetByteView salt = janet_getbytes(argv, 3);
    JanetBuffer *out = janet_buffer(out_len);
    JanetByteView label;
    label.bytes = NULL;
    label.len = 0;

    if (argc == 5) {
        label = janet_getbytes(argv, 4);
    }

    int ret = botan_kdf(algo, out->data, out_len,
                        secret.bytes, secret.len,
                        salt.bytes, salt.len,
                        label.bytes, label.len);
    JANET_BOTAN_ASSERT(ret);

    out->count = out_len;
    return janet_wrap_string(janet_string(out->data, out->count));
}

static JanetReg kdf_cfuns[] = {
    {"kdf", cfun_kdf,
     "(kdf algo out_len secret salt &opt label)\n\n"
     "Performs a key derviation function (such as “HKDF(SHA-384)”) over the "
     "provided secret, salt and label values. Returns a value of the "
     "specified length."
    },
    {NULL, NULL, NULL}
};

#endif /* KDF_H */
