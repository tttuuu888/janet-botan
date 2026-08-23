/*
 * Copyright (c) 2026, Janet-botan Seungki Kim
 *
 * Janet-botan is released under the MIT License, see the LICENSE file.
 */

#ifndef BOTAN_SPAKE2P_PROVER_H
#define BOTAN_SPAKE2P_PROVER_H

typedef struct botan_spake2p_prover_obj {
    botan_spake2p_prover_t spake2p_prover;
} botan_spake2p_prover_obj_t;

/* Abstract Object functions */
static int spake2p_prover_gc_fn(void *data, size_t len);
static int spake2p_prover_get_fn(void *data, Janet key, Janet *out);

/* Janet functions */
static Janet spake2p_prover_new(int32_t argc, Janet *argv);
static Janet spake2p_prover_generate_message(int32_t argc, Janet *argv);
static Janet spake2p_prover_process_message(int32_t argc, Janet *argv);
static Janet spake2p_prover_shared_secret(int32_t argc, Janet *argv);

static JanetAbstractType spake2p_prover_obj_type = {
    "botan/spake2p-prover",
    spake2p_prover_gc_fn,
    NULL,
    spake2p_prover_get_fn,
    JANET_ATEND_GET
};

static JanetMethod spake2p_prover_methods[] = {
    {"generate-message", spake2p_prover_generate_message},
    {"process-message", spake2p_prover_process_message},
    {"shared-secret", spake2p_prover_shared_secret},
    {NULL, NULL},
};

static JanetAbstractType *get_spake2p_prover_obj_type() {
    return &spake2p_prover_obj_type;
}

/* Abstract Object functions */
static int spake2p_prover_gc_fn(void *data, size_t len) {
    botan_spake2p_prover_obj_t *obj = (botan_spake2p_prover_obj_t *)data;

    int ret = botan_spake2p_prover_destroy(obj->spake2p_prover);
    JANET_BOTAN_ASSERT(ret);

    return 0;
}

static int spake2p_prover_get_fn(void *data, Janet key, Janet *out) {
    (void)data;
    if (!janet_checktype(key, JANET_KEYWORD)) {
        return 0;
    }

    return janet_getmethod(janet_unwrap_keyword(key), spake2p_prover_methods, out);
}

/* Janet functions */
static Janet spake2p_prover_new(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 5);
    botan_spake2p_prover_obj_t *obj = janet_abstract(&spake2p_prover_obj_type, sizeof(botan_spake2p_prover_obj_t));
    memset(obj, 0, sizeof(botan_spake2p_prover_obj_t));

    botan_spake2p_params_obj_t *obj2 = janet_getabstract(argv, 0, get_spake2p_params_obj_type());
    botan_spake2p_params_t params = obj2->spake2p_params;
    JanetByteView secret = janet_getbytes(argv, 1);
    JanetByteView prover_id = janet_getbytes(argv, 2);
    JanetByteView verifier_id = janet_getbytes(argv, 3);
    JanetByteView context = janet_getbytes(argv, 4);

    int ret = botan_spake2p_prover_init(&obj->spake2p_prover, params,
                                        (const uint8_t *)secret.bytes, secret.len,
                                        (const uint8_t *)prover_id.bytes, prover_id.len,
                                        (const uint8_t *)verifier_id.bytes, verifier_id.len,
                                        (const uint8_t *)context.bytes, context.len);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_abstract(obj);
}

static Janet spake2p_prover_generate_message(int32_t argc, Janet *argv) {
    janet_arity(argc, 1, 2);

    botan_spake2p_prover_obj_t *obj = janet_getabstract(argv, 0, get_spake2p_prover_obj_type());
    botan_spake2p_prover_t prover = obj->spake2p_prover;

    int ret;
    botan_rng_t rng;
    botan_rng_obj_t *obj2 = janet_optabstract(argv, argc, 1, get_rng_obj_type(), NULL);
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
    ret = botan_spake2p_prover_generate_message(prover, rng,
                                                &data, (botan_view_bin_fn)view_bin_func);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_string(janet_string(data.data, data.len));
}

static Janet spake2p_prover_process_message(int32_t argc, Janet *argv) {
    janet_arity(argc, 2, 3);

    botan_spake2p_prover_obj_t *obj = janet_getabstract(argv, 0, get_spake2p_prover_obj_type());
    botan_spake2p_prover_t prover = obj->spake2p_prover;
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
    ret = botan_spake2p_prover_process_message(prover, rng,
                                               (const uint8_t *)peer_msg.bytes, peer_msg.len,
                                               &data, (botan_view_bin_fn)view_bin_func);
    if (ret == BOTAN_FFI_ERROR_BAD_MAC) {
        return janet_wrap_nil();
    }

    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_string(janet_string(data.data, data.len));
}

static Janet spake2p_prover_shared_secret(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 1);

    botan_spake2p_prover_obj_t *obj = janet_getabstract(argv, 0, get_spake2p_prover_obj_type());
    botan_spake2p_prover_t prover = obj->spake2p_prover;

    view_data_t data;
    int ret = botan_spake2p_prover_shared_secret(prover, &data, (botan_view_bin_fn)view_bin_func);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_string(janet_string(data.data, data.len));
}

static JanetReg spake2p_prover_cfuns[] = {
    {"spake2p-prover/new", spake2p_prover_new,
     "(spake2p-prover/new spake2p-params-obj secret "
     "prover-id verifier-id context)\n\n"
     "Creates a SPAKE2+ prover, the side which knows the password. `secret` "
     "is the prover secret from `spake2p-derive-secret`. The identities and "
     "context must be agreed upon by both parties. "
     "Returns `spake2p-prover-obj`."
    },
    {"spake2p-prover/generate-message", spake2p_prover_generate_message,
     "(spake2p-prover/generate-message spake2p-prover-obj &opt rng)\n\n"
     "Generate the prover's key share, which is sent to the verifier. "
     "Can be called only once."
    },
    {"spake2p-prover/process-message", spake2p_prover_process_message,
     "(spake2p-prover/process-message spake2p-prover-obj "
     "peer-message &opt rng)\n\n"
     "Consume the verifier's response and return the prover's "
     "key confirmation, which is sent to the verifier. "
     "Returns nil if the verifier's key confirmation is wrong, "
     "typically meaning the passwords do not match."
    },
    {"spake2p-prover/shared-secret", spake2p_prover_shared_secret,
     "(spake2p-prover/shared-secret spake2p-prover-obj)\n\n"
     "Returns the shared secret. Only valid after "
     "`spake2p-prover/process-message` succeeded."
    },
    {NULL, NULL, NULL}
};

static void submod_spake2p_prover(JanetTable *env) {
    janet_cfuns(env, "botan", spake2p_prover_cfuns);
    janet_register_abstract_type(get_spake2p_prover_obj_type());
}

#endif /* BOTAN_SPAKE2P_PROVER_H */
