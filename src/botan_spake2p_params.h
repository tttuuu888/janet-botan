/*
 * Copyright (c) 2026, Janet-botan Seungki Kim
 *
 * Janet-botan is released under the MIT License, see the LICENSE file.
 */

#ifndef BOTAN_SPAKE2P_PARAMS_H
#define BOTAN_SPAKE2P_PARAMS_H

typedef struct botan_spake2p_params_obj {
    botan_spake2p_params_t spake2p_params;
} botan_spake2p_params_obj_t;

/* Abstract Object functions */
static int spake2p_params_gc_fn(void *data, size_t len);
static int spake2p_params_get_fn(void *data, Janet key, Janet *out);

/* Janet functions */
static Janet spake2p_params_new(int32_t argc, Janet *argv);
static Janet spake2p_params_new_custom(int32_t argc, Janet *argv);
static Janet spake2p_params_share_size(int32_t argc, Janet *argv);
static Janet spake2p_params_confirmation_size(int32_t argc, Janet *argv);
static Janet spake2p_derive_secret(int32_t argc, Janet *argv);
static Janet spake2p_registration_record(int32_t argc, Janet *argv);

static JanetAbstractType spake2p_params_obj_type = {
    "botan/spake2p-params",
    spake2p_params_gc_fn,
    NULL,
    spake2p_params_get_fn,
    JANET_ATEND_GET
};

static JanetMethod spake2p_params_methods[] = {
    {"share-size", spake2p_params_share_size},
    {"confirmation-size", spake2p_params_confirmation_size},
    {NULL, NULL},
};

static JanetAbstractType *get_spake2p_params_obj_type() {
    return &spake2p_params_obj_type;
}

/* Abstract Object functions */
static int spake2p_params_gc_fn(void *data, size_t len) {
    botan_spake2p_params_obj_t *obj = (botan_spake2p_params_obj_t *)data;

    int ret = botan_spake2p_params_destroy(obj->spake2p_params);
    JANET_BOTAN_ASSERT(ret);

    return 0;
}

static int spake2p_params_get_fn(void *data, Janet key, Janet *out) {
    (void)data;
    if (!janet_checktype(key, JANET_KEYWORD)) {
        return 0;
    }

    return janet_getmethod(janet_unwrap_keyword(key), spake2p_params_methods, out);
}

/* Janet functions */
static Janet spake2p_params_new(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 1);
    botan_spake2p_params_obj_t *obj = janet_abstract(&spake2p_params_obj_type, sizeof(botan_spake2p_params_obj_t));
    memset(obj, 0, sizeof(botan_spake2p_params_obj_t));

    const char *ciphersuite = janet_getcstring(argv, 0);
    int ret = botan_spake2p_params_init(&obj->spake2p_params, ciphersuite);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_abstract(obj);
}

static Janet spake2p_params_new_custom(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 3);
    botan_spake2p_params_obj_t *obj = janet_abstract(&spake2p_params_obj_type, sizeof(botan_spake2p_params_obj_t));
    memset(obj, 0, sizeof(botan_spake2p_params_obj_t));

    botan_ec_group_obj_t *obj2 = janet_getabstract(argv, 0, get_ec_group_obj_type());
    botan_ec_group_t ec_group = obj2->ec_group;

    JanetByteView seed = janet_getbytes(argv, 1);

    const char *hash = janet_getcstring(argv, 2);
    int ret = botan_spake2p_params_init_custom(&obj->spake2p_params, ec_group,
                                               (const uint8_t *)seed.bytes, seed.len,
                                               hash);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_abstract(obj);
}

static Janet spake2p_params_share_size(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 1);
    botan_spake2p_params_obj_t *obj = janet_getabstract(argv, 0, get_spake2p_params_obj_type());
    botan_spake2p_params_t params = obj->spake2p_params;
    size_t size = 0;

    int ret = botan_spake2p_params_share_size(params, &size);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_number((double)size);
}

static Janet spake2p_params_confirmation_size(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 1);
    botan_spake2p_params_obj_t *obj = janet_getabstract(argv, 0, get_spake2p_params_obj_type());
    botan_spake2p_params_t params = obj->spake2p_params;
    size_t size = 0;

    int ret = botan_spake2p_params_confirmation_size(params, &size);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_number((double)size);
}

static Janet spake2p_derive_secret(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 5);
    botan_spake2p_params_obj_t *obj = janet_getabstract(argv, 0, get_spake2p_params_obj_type());
    botan_spake2p_params_t params = obj->spake2p_params;
    const char *password = janet_getcstring(argv, 1);
    JanetByteView prover_id = janet_getbytes(argv, 2);
    JanetByteView verifier_id = janet_getbytes(argv, 3);
    JanetByteView salt = janet_getbytes(argv, 4);

    view_data_t data;
    int ret = botan_spake2p_derive_secret(params, password,
                                          (const uint8_t *)prover_id.bytes, prover_id.len,
                                          (const uint8_t *)verifier_id.bytes, verifier_id.len,
                                          (const uint8_t *)salt.bytes, salt.len,
                                          &data, (botan_view_bin_fn)view_bin_func);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_string(janet_string(data.data, data.len));
}

static Janet spake2p_registration_record(int32_t argc, Janet *argv) {
    janet_arity(argc, 2, 3);
    botan_spake2p_params_obj_t *obj = janet_getabstract(argv, 0, get_spake2p_params_obj_type());
    botan_spake2p_params_t params = obj->spake2p_params;
    JanetByteView secret = janet_getbytes(argv, 1);

    int ret;
    botan_rng_t rng;
    botan_rng_obj_t *obj2 = janet_optabstract(argv, argc, 2, get_rng_obj_type(), NULL);
    if (obj2) {
        rng = obj2->rng;
    } else {
        obj2 = janet_abstract(&rng_obj_type, sizeof(botan_rng_obj_t));
        memset(obj2, 0, sizeof(botan_rng_obj_t));

        ret = botan_rng_init(&obj2->rng, "system");
        JANET_BOTAN_ASSERT(ret);
        rng = obj2->rng;
    }

    view_data_t data;
    ret = botan_spake2p_registration_record(params, rng,
                                            (const uint8_t *)secret.bytes, secret.len,
                                            &data, (botan_view_bin_fn)view_bin_func);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_string(janet_string(data.data, data.len));
}

static JanetReg spake2p_params_cfuns[] = {
    {"spake2p-params/new", spake2p_params_new,
     "(spake2p-params/new ciphersuite)\n\n"
     "Creates a new SPAKE2+ system parameters object from an RFC 9383 "
     "`ciphersuite` name, one of \"P256-SHA256\", \"P256-SHA512\", "
     "\"P384-SHA256\", \"P384-SHA512\" or \"P521-SHA512\". "
     "Returns `spake2p-params-obj`."
    },
    {"spake2p-params/new-custom", spake2p_params_new_custom,
     "(spake2p-params/new-custom ec-group-obj seed hash)\n\n"
     "Creates a new SPAKE2+ system parameters object for an arbitrary group. "
     "`seed` is a byte string from which the M/N group elements are derived "
     "using hash to curve, which not all groups support. `hash` is a hash "
     "function name (e.g., \"SHA-256\"). Both peers must use the same group, "
     "seed and hash. Returns `spake2p-params-obj`."
    },
    {"spake2p-params/share-size", spake2p_params_share_size,
     "(spake2p-params/share-size spake2p-params-obj)\n\n"
     "Return the size in bytes of a SPAKE2+ key share (shareP or shareV)."
    },
    {"spake2p-params/confirmation-size", spake2p_params_confirmation_size,
     "(spake2p-params/confirmation-size spake2p-params-obj)\n\n"
     "Return the size in bytes of a SPAKE2+ key confirmation message "
     "(confirmP or confirmV)."
    },
    {"spake2p-derive-secret", spake2p_derive_secret,
     "(spake2p-derive-secret spake2p-params-obj "
     "password prover-id verifier-id salt)\n\n"
     "Derive a SPAKE2+ (RFC 9383) prover secret from a password, "
     "using Argon2id. The returned secret is password equivalent, "
     "and must be protected accordingly. It is used with "
     "`spake2p-registration-record` and `spake2p-prover/new`."
    },
    {"spake2p-registration-record", spake2p_registration_record,
     "(spake2p-registration-record spake2p-params-obj "
     "secret &opt rng)\n\n"
     "Compute a SPAKE2+ registration record from a prover secret. "
     "The registration record is provided to the verifier during "
     "registration. New rng is used by default, if `rng` is not provided."
    },
    {NULL, NULL, NULL}
};

static void submod_spake2p_params(JanetTable *env) {
    janet_cfuns(env, "botan", spake2p_params_cfuns);
    janet_register_abstract_type(get_spake2p_params_obj_type());
}

#endif /* BOTAN_SPAKE2P_PARAMS_H */
