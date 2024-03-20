/*
 * Copyright (c) 2024, Janet-botan Seungki Kim
 *
 * Janet-botan is released under the MIT License, see the LICENSE file.
 */

#ifndef BOTAN_MAC_H
#define BOTAN_MAC_H

typedef struct botan_mac_obj {
    botan_mac_t mac;
} botan_mac_obj_t;

/* Abstract Object functions */
static int mac_gc_fn(void *data, size_t len);
static int mac_get_fn(void *data, Janet key, Janet *out);

/* Janet functions */
static Janet mac_new(int32_t argc, Janet *argv);
static Janet mac_clear(int32_t argc, Janet *argv);
static Janet mac_output_length(int32_t argc, Janet *argv);
static Janet mac_get_keyspec(int32_t argc, Janet *argv);
static Janet mac_set_key(int32_t argc, Janet *argv);
static Janet mac_set_nonce(int32_t argc, Janet *argv);
static Janet mac_update(int32_t argc, Janet *argv);
static Janet mac_final(int32_t argc, Janet *argv);

static JanetAbstractType mac_obj_type = {
    "botan/mac",
    mac_gc_fn,
    NULL,
    mac_get_fn,
    JANET_ATEND_GET
};

static JanetMethod mac_methods[] = {
    {"clear", mac_clear},
    {"output-length", mac_output_length},
    {"get-keyspec", mac_get_keyspec},
    {"set-key", mac_set_key},
    {"set-nonce", mac_set_nonce},
    {"update", mac_update},
    {"final", mac_final},
    {NULL, NULL},
};

static JanetAbstractType *get_mac_obj_type() {
    return &mac_obj_type;
}

/* Abstract Object functions */
static int mac_gc_fn(void *data, size_t len) {
    botan_mac_obj_t *obj = (botan_mac_obj_t *)data;

    int ret = botan_mac_destroy(obj->mac);
    JANET_BOTAN_ASSERT(ret);

    return 0;
}

static int mac_get_fn(void *data, Janet key, Janet *out) {
    (void)data;
    if (!janet_checktype(key, JANET_KEYWORD)) {
        return 0;
    }

    return janet_getmethod(janet_unwrap_keyword(key), mac_methods, out);
}

/* Janet functions */
static Janet mac_new(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 1);
    botan_mac_obj_t *obj = janet_abstract(&mac_obj_type, sizeof(botan_mac_obj_t));
    memset(obj, 0, sizeof(botan_mac_obj_t));
    const char *name = janet_getcstring(argv, 0);

    int ret = botan_mac_init(&obj->mac, name, 0);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_abstract(obj);
}

static Janet mac_clear(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 1);
    botan_mac_obj_t *obj = janet_getabstract(argv, 0, get_mac_obj_type());
    botan_mac_t mac = obj->mac;

    int ret = botan_mac_clear(mac);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_abstract(obj);
}

static Janet mac_output_length(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 1);
    botan_mac_obj_t *obj = janet_getabstract(argv, 0, get_mac_obj_type());
    botan_mac_t mac = obj->mac;
    size_t output_len;

    int ret = botan_mac_output_length(mac, &output_len);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_number((double)output_len);
}

static Janet mac_get_keyspec(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 1);
    botan_mac_obj_t *obj = janet_getabstract(argv, 0, get_mac_obj_type());
    botan_mac_t mac = obj->mac;
    size_t min_key, max_key, mod_key;

    int ret = botan_mac_get_keyspec(mac, &min_key, &max_key, &mod_key);
    JANET_BOTAN_ASSERT(ret);

    Janet spec[3] = {janet_wrap_number((double)min_key),
                     janet_wrap_number((double)max_key),
                     janet_wrap_number((double)mod_key)};
    return janet_wrap_tuple(janet_tuple_n(spec, 3));
}

static Janet mac_set_key(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 2);
    botan_mac_obj_t *obj = janet_getabstract(argv, 0, get_mac_obj_type());
    botan_mac_t mac = obj->mac;
    JanetByteView key = janet_getbytes(argv, 1);

    int ret = botan_mac_set_key(mac, key.bytes, key.len);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_abstract(obj);
}

static Janet mac_set_nonce(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 2);
    botan_mac_obj_t *obj = janet_getabstract(argv, 0, get_mac_obj_type());
    botan_mac_t mac = obj->mac;
    JanetByteView key = janet_getbytes(argv, 1);

    int ret = botan_mac_set_nonce(mac, key.bytes, key.len);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_abstract(obj);
}

static Janet mac_update(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 2);
    botan_mac_obj_t *obj = janet_getabstract(argv, 0, get_mac_obj_type());
    botan_mac_t mac = obj->mac;
    JanetByteView input = janet_getbytes(argv, 1);

    int ret = botan_mac_update(mac, input.bytes, input.len);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_abstract(obj);
}

static Janet mac_final(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 1);
    botan_mac_obj_t *obj = janet_getabstract(argv, 0, get_mac_obj_type());
    botan_mac_t mac = obj->mac;
    size_t output_len;

    int ret = botan_mac_output_length(mac, &output_len);
    JANET_BOTAN_ASSERT(ret);

    uint8_t *output = janet_string_begin(output_len);
    ret = botan_mac_final(mac, output);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_string(janet_string_end(output));
}

static JanetReg mac_cfuns[] = {
    {"mac/new", mac_new, "(mac/new name)\n\n"
     "Creates a MAC of the given name, e.g., \"HMAC(SHA-384)\"."
    },
    {"mac/clear", mac_clear, "(mac/clear mac)\n\n"
     "Reset the state of `mac` back to clean, "
     "as if no key and input has been supplied, return self."
    },
    {"mac/output-length", mac_output_length,
     "(mac/output-length mac)\n\n"
     "Return the output length of the `mac`"
    },
    {"mac/get-keyspec", mac_get_keyspec,
     "(mac/get-keyspec mac)\n\n"
     "Return the key spec of the `mac` in format of "
     "[max-key-length min-key-length mod-key-length]."
    },
    {"mac/set-key", mac_set_key, "(mac/set-key mac key)\n\n"
     "Set the `key` for the MAC calculation, return self."
    },
    {"mac/set-nonce", mac_set_nonce, "(mac/set-nonce mac key)\n\n"
     "Set the `nonce` for the MAC calculation, return self."
     "Note that not all MAC algorithms require a nonce. If a nonce is required,"
     " the function has to be called before the data is processed. "
    },
    {"mac/update", mac_update, "(mac/update mac input)\n\n"
     "Add input to the MAC computation, return self."
    },
    {"mac/final", mac_final, "(mac/final mac)\n\n"
     "Finalize the MAC and return the output"
    },
    {NULL, NULL, NULL}
};

static void submod_mac(JanetTable *env) {
    janet_cfuns(env, "botan", mac_cfuns);
    janet_register_abstract_type(get_mac_obj_type());
}

#endif /* BOTAN_MAC_H */
