/*
 * Copyright (c) 2026, Janet-botan Seungki Kim
 *
 * Janet-botan is released under the MIT License, see the LICENSE file.
 */

#ifndef BOTAN_SPAKE2P_VERIFIER_H
#define BOTAN_SPAKE2P_VERIFIER_H

typedef struct botan_spake2p_verifier_obj {
    botan_spake2p_verifier_t spake2p_verifier;
} botan_spake2p_verifier_obj_t;

/* Abstract Object functions */
static int spake2p_verifier_gc_fn(void *data, size_t len);
static int spake2p_verifier_get_fn(void *data, Janet key, Janet *out);

/* Janet functions */
static Janet spake2p_verifier_new(int32_t argc, Janet *argv);
static Janet spake2p_verifier_process_message(int32_t argc, Janet *argv);
static Janet spake2p_verifier_verify_confirmation(int32_t argc, Janet *argv);
static Janet spake2p_verifier_skip_confirmation(int32_t argc, Janet *argv);
static Janet spake2p_verifier_shared_secret(int32_t argc, Janet *argv);

static JanetAbstractType spake2p_verifier_obj_type = {
    "botan/spake2p-verifier",
    spake2p_verifier_gc_fn,
    NULL,
    spake2p_verifier_get_fn,
    JANET_ATEND_GET
};

static JanetMethod spake2p_verifier_methods[] = {
    {"process-message", spake2p_verifier_process_message},
    {"verify-confirmation", spake2p_verifier_verify_confirmation},
    {"skip-confirmation", spake2p_verifier_skip_confirmation},
    {"shared-secret", spake2p_verifier_shared_secret},
    {NULL, NULL},
};

static JanetAbstractType *get_spake2p_verifier_obj_type() {
    return &spake2p_verifier_obj_type;
}

/* Abstract Object functions */
static int spake2p_verifier_gc_fn(void *data, size_t len) {
    botan_spake2p_verifier_obj_t *obj = (botan_spake2p_verifier_obj_t *)data;

    int ret = botan_spake2p_verifier_destroy(obj->spake2p_verifier);
    JANET_BOTAN_ASSERT(ret);

    return 0;
}

static int spake2p_verifier_get_fn(void *data, Janet key, Janet *out) {
    (void)data;
    if (!janet_checktype(key, JANET_KEYWORD)) {
        return 0;
    }

    return janet_getmethod(janet_unwrap_keyword(key), spake2p_verifier_methods, out);
}

/* Janet functions */
static Janet spake2p_verifier_new(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 5);
    botan_spake2p_verifier_obj_t *obj = janet_abstract(&spake2p_verifier_obj_type, sizeof(botan_spake2p_verifier_obj_t));
    memset(obj, 0, sizeof(botan_spake2p_verifier_obj_t));

    botan_spake2p_params_obj_t *obj2 = janet_getabstract(argv, 0, get_spake2p_params_obj_type());
    botan_spake2p_params_t params = obj2->spake2p_params;
    JanetByteView record = janet_getbytes(argv, 1);
    JanetByteView prover_id = janet_getbytes(argv, 2);
    JanetByteView verifier_id = janet_getbytes(argv, 3);
    JanetByteView context = janet_getbytes(argv, 4);

    int ret = botan_spake2p_verifier_init(&obj->spake2p_verifier, params,
                                          (const uint8_t *)record.bytes, record.len,
                                          (const uint8_t *)prover_id.bytes, prover_id.len,
                                          (const uint8_t *)verifier_id.bytes, verifier_id.len,
                                          (const uint8_t *)context.bytes, context.len);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_abstract(obj);
}

static Janet spake2p_verifier_process_message(int32_t argc, Janet *argv) {
    janet_arity(argc, 2, 3);

    botan_spake2p_verifier_obj_t *obj = janet_getabstract(argv, 0, get_spake2p_verifier_obj_type());
    botan_spake2p_verifier_t verifier = obj->spake2p_verifier;
    JanetByteView peer_msg = janet_getbytes(argv, 1);

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
    ret = botan_spake2p_verifier_process_message(verifier, rng,
                                                 (const uint8_t *)peer_msg.bytes, peer_msg.len,
                                                 &data, (botan_view_bin_fn)view_bin_func);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_string(janet_string(data.data, data.len));
}

static Janet spake2p_verifier_verify_confirmation(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 2);

    botan_spake2p_verifier_obj_t *obj = janet_getabstract(argv, 0, get_spake2p_verifier_obj_type());
    botan_spake2p_verifier_t verifier = obj->spake2p_verifier;
    JanetByteView confirmation = janet_getbytes(argv, 1);

    int ret = botan_spake2p_verifier_verify_confirmation(
        verifier, (const uint8_t *)confirmation.bytes, confirmation.len);
    if (ret == BOTAN_FFI_ERROR_BAD_MAC) {
        return janet_wrap_boolean(false);
    }

    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_boolean(true);
}

static Janet spake2p_verifier_skip_confirmation(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 1);

    botan_spake2p_verifier_obj_t *obj = janet_getabstract(argv, 0, get_spake2p_verifier_obj_type());
    botan_spake2p_verifier_t verifier = obj->spake2p_verifier;

    int ret = botan_spake2p_verifier_skip_confirmation(verifier);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_abstract(obj);
}

static Janet spake2p_verifier_shared_secret(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 1);

    botan_spake2p_verifier_obj_t *obj = janet_getabstract(argv, 0, get_spake2p_verifier_obj_type());
    botan_spake2p_verifier_t verifier = obj->spake2p_verifier;

    view_data_t data;
    int ret = botan_spake2p_verifier_shared_secret(verifier, &data, (botan_view_bin_fn)view_bin_func);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_string(janet_string(data.data, data.len));
}

static JanetReg spake2p_verifier_cfuns[] = {
    {"spake2p-verifier/new", spake2p_verifier_new,
     "(spake2p-verifier/new spake2p-params-obj record "
     "prover-id verifier-id context)\n\n"
     "Creates a SPAKE2+ verifier, the side which stores only the "
     "registration record derived from the password. `record` is the "
     "registration record from `spake2p-registration-record`. The identities "
     "and context must be agreed upon by both parties. "
     "Returns `spake2p-verifier-obj`."
    },
    {"spake2p-verifier/process-message", spake2p_verifier_process_message,
     "(spake2p-verifier/process-message spake2p-verifier-obj "
     "peer-message &opt rng)\n\n"
     "Consume the prover's key share and return the verifier's "
     "response (its own key share followed by a key confirmation), "
     "which is sent to the prover. Can be called only once."
    },
    {"spake2p-verifier/verify-confirmation", spake2p_verifier_verify_confirmation,
     "(spake2p-verifier/verify-confirmation spake2p-verifier-obj "
     "confirmation)\n\n"
     "Check the prover's key confirmation. Returns false if the confirmation "
     "is wrong, meaning the prover does not know the password."
    },
    {"spake2p-verifier/skip-confirmation", spake2p_verifier_skip_confirmation,
     "(spake2p-verifier/skip-confirmation spake2p-verifier-obj)\n\n"
     "Skip checking the prover's key confirmation, allowing "
     "`spake2p-verifier/shared-secret` to be called without "
     "`spake2p-verifier/verify-confirmation`. After calling this, "
     "no evidence has been received that the peer knows the password; "
     "it is intended solely for protocols which embed SPAKE2+ and perform "
     "the prover's key confirmation themselves. "
     "Returns `spake2p-verifier-obj`."
    },
    {"spake2p-verifier/shared-secret", spake2p_verifier_shared_secret,
     "(spake2p-verifier/shared-secret spake2p-verifier-obj)\n\n"
     "Return the shared secret. Only valid after "
     "`spake2p-verifier/verify-confirmation` succeeded, "
     "or after `spake2p-verifier/skip-confirmation`."
    },
    {NULL, NULL, NULL}
};

static void submod_spake2p_verifier(JanetTable *env) {
    janet_cfuns(env, "botan", spake2p_verifier_cfuns);
    janet_register_abstract_type(get_spake2p_verifier_obj_type());
}

#endif /* BOTAN_SPAKE2P_VERIFIER_H */
