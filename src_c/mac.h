/*
 * Copyright (c) 2024, Janet-botan Seungki Kim
 *
 * Janet-botan is released under the MIT License. (see LICENSE)
 */

#ifndef MAC_H
#define MAC_H

static Janet cfun_mac_init(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 1);
    const char *name = janet_getcstring(argv, 0);
    botan_mac_t mac;

    int ret = botan_mac_init(&mac, name, 0);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_pointer(mac);
}

static Janet cfun_mac_destroy(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 1);
    botan_mac_t mac = janet_getpointer(argv, 0);

    int ret = botan_mac_destroy(mac);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_nil();
}

static Janet cfun_mac_clear(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 1);
    botan_mac_t mac = janet_getpointer(argv, 0);

    int ret = botan_mac_clear(mac);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_nil();
}

static Janet cfun_mac_output_length(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 1);
    botan_mac_t mac = janet_getpointer(argv, 0);
    size_t output_len;

    int ret = botan_mac_output_length(mac, &output_len);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_number((double)output_len);
}

static Janet cfun_mac_get_min_keylen(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 1);
    botan_mac_t mac = janet_getpointer(argv, 0);
    size_t spec;

    int ret = botan_mac_get_keyspec(mac, &spec, NULL, NULL);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_number((double)spec);
}

static Janet cfun_mac_get_max_keylen(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 1);
    botan_mac_t mac = janet_getpointer(argv, 0);
    size_t spec;

    int ret = botan_mac_get_keyspec(mac, NULL, &spec, NULL);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_number((double)spec);
}

static Janet cfun_mac_set_key(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 2);
    botan_mac_t mac = janet_getpointer(argv, 0);
    JanetByteView key = janet_getbytes(argv, 1);

    int ret = botan_mac_set_key(mac, key.bytes, key.len);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_nil();
}

static Janet cfun_mac_set_nonce(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 2);
    botan_mac_t mac = janet_getpointer(argv, 0);
    JanetByteView key = janet_getbytes(argv, 1);

    int ret = botan_mac_set_nonce(mac, key.bytes, key.len);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_nil();
}

static Janet cfun_mac_update(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 2);
    botan_mac_t mac = janet_getpointer(argv, 0);
    JanetByteView input = janet_getbytes(argv, 1);

    int ret = botan_mac_update(mac, input.bytes, input.len);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_nil();
}

static Janet cfun_mac_final(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 1);
    botan_mac_t mac = janet_getpointer(argv, 0);
    size_t output_len;

    int ret = botan_mac_output_length(mac, &output_len);
    JANET_BOTAN_ASSERT(ret);

    uint8_t *output = janet_string_begin(output_len);
    ret = botan_mac_final(mac, output);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_string(janet_string_end(output));
}

static JanetReg mac_cfuns[] = {
    {"mac/init", cfun_mac_init, "(mac/init name)\n\n"
     "Creates a MAC of the given name, e.g., \"HMAC(SHA-384)\"."
    },
    {"mac/destroy", cfun_mac_destroy, "(mac/destroy mac)\n\n"
     "Destroy the `mac` object created by `mac/init`."
    },
    {"mac/clear", cfun_mac_clear, "(mac/clear mac)\n\n"
     "Reset the state of `mac` back to clean, "
     "as if no key and input has been supplied."
    },
    {"mac/output-length", cfun_mac_output_length,
     "(mac/output-length mac)\n\n"
     "Return the output length of the `mac`"
    },
    {"mac/get-min-keylen", cfun_mac_get_min_keylen,
     "(mac/get-min-keylen mac)\n\n"
     "Return the minimum-keylength which can be provided to MAC computation."
    },
    {"mac/get-max-keylen", cfun_mac_get_max_keylen,
     "(mac/get-max-keylen mac)\n\n"
     "Return the maximum-keylength which can be provided to MAC computation."
    },
    {"mac/set-key", cfun_mac_set_key, "(mac/set-key mac key)\n\n"
     "Set the `key` for the MAC calculation."
    },
    {"mac/set-nonce", cfun_mac_set_nonce, "(mac/set-nonce mac key)\n\n"
     "Set the `nonce` for the MAC calculation."
     "Note that not all MAC algorithms require a nonce. If a nonce is required,"
     " the function has to be called before the data is processed. "
    },
    {"mac/update", cfun_mac_update, "(mac/update mac input)\n\n"
     "Add input to the MAC computation."
    },
    {"mac/final", cfun_mac_final, "(mac/final mac)\n\n"
     "Finalize the MAC and return the output"
    },
    {NULL, NULL, NULL}
};

#endif /* MAC_H */
