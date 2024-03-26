/*
 * Copyright (c) 2024, Janet-botan Seungki Kim
 *
 * Janet-botan is released under the MIT License, see the LICENSE file.
 */

#ifndef BOTAN_PK_SIGN_H
#define BOTAN_PK_SIGN_H

typedef struct botan_pk_sign_obj {
    botan_pk_op_sign_t pk_sign;
} botan_pk_sign_obj_t;

/* Abstract Object functions */
static int pk_sign_gc_fn(void *data, size_t len);
static int pk_sign_get_fn(void *data, Janet key, Janet *out);

/* Janet functions */
static Janet pk_sign_new(int32_t argc, Janet *argv);
static Janet pk_sign_update(int32_t argc, Janet *argv);
static Janet pk_sign_finish(int32_t argc, Janet *argv);

static JanetAbstractType pk_sign_obj_type = {
    "botan/pk-sign",
    pk_sign_gc_fn,
    NULL,
    pk_sign_get_fn,
    JANET_ATEND_GET
};

static JanetMethod pk_sign_methods[] = {
    {"update", pk_sign_update},
    {"finish", pk_sign_finish},
    {NULL, NULL},
};

static JanetAbstractType *get_pk_sign_obj_type() {
    return &pk_sign_obj_type;
}

/* Abstract Object functions */
static int pk_sign_gc_fn(void *data, size_t len) {
    botan_pk_sign_obj_t *obj = (botan_pk_sign_obj_t *)data;

    int ret = botan_pk_op_sign_destroy(obj->pk_sign);
    JANET_BOTAN_ASSERT(ret);

    return 0;
}

static int pk_sign_get_fn(void *data, Janet key, Janet *out) {
    (void)data;
    if (!janet_checktype(key, JANET_KEYWORD)) {
        return 0;
    }

    return janet_getmethod(janet_unwrap_keyword(key), pk_sign_methods, out);
}

/* Janet functions */
static Janet pk_sign_new(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 2);
    botan_pk_sign_obj_t *obj = janet_abstract(&pk_sign_obj_type, sizeof(botan_pk_sign_obj_t));
    memset(obj, 0, sizeof(botan_pk_sign_obj_t));

    botan_private_key_obj_t *obj2 = janet_getabstract(argv, 0, get_private_key_obj_type());
    botan_privkey_t key = obj2->private_key;

    const char *padding = janet_getcstring(argv, 1);

    int ret = botan_pk_op_sign_create(&obj->pk_sign, key, padding, 0);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_abstract(obj);
}

static Janet pk_sign_update(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 2);

    int ret;
    botan_pk_sign_obj_t *obj = janet_getabstract(argv, 0, get_pk_sign_obj_type());
    botan_pk_op_sign_t op = obj->pk_sign;

    JanetByteView msg = janet_getbytes(argv, 1);
    ret = botan_pk_op_sign_update(op, msg.bytes, msg.len);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_abstract(obj);
}

static Janet pk_sign_finish(int32_t argc, Janet *argv) {
    janet_arity(argc, 1, 2);

    int ret;
    botan_pk_sign_obj_t *obj = janet_getabstract(argv, 0, get_pk_sign_obj_type());
    botan_pk_op_sign_t op = obj->pk_sign;

    botan_rng_t rng;

    if (argc == 2) {
        botan_rng_obj_t *obj2 = janet_getabstract(argv, 1, get_rng_obj_type());
        rng = obj2->rng;
    } else {
        botan_rng_obj_t *obj2 = janet_abstract(&rng_obj_type, sizeof(botan_rng_obj_t));
        memset(obj2, 0, sizeof(botan_rng_obj_t));

        ret = botan_rng_init(&obj2->rng, "system");
        JANET_BOTAN_ASSERT(ret);
        rng = obj2->rng;
    }

    size_t out_len = 0;
    ret = botan_pk_op_sign_output_length(op, &out_len);
    JANET_BOTAN_ASSERT(ret);

    JanetBuffer *out = janet_buffer(out_len);
    ret = botan_pk_op_sign_finish(op, rng, out->data, &out_len);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_string(janet_string(out->data, out_len));
}

static JanetReg pk_sign_cfuns[] = {
    {"pk-sign/new", pk_sign_new,
     "(pk-sign/new privkey hash-and-padding)\n\n"
     "Create a signature operator for the provided key. The padding string "
     "specifies what hash function and padding should be used, for example "
     "\"PKCS1v15(SHA-256)\" for PKCS #1 v1.5 padding (used with RSA) or "
     "\"SHA-384\". Generally speaking only RSA has special padding modes; "
     "for other algorithms like ECDSA one just names the hash."
    },
    {"pk-sign/update", pk_sign_update,
     "(pk-sign/update op message)\n\n"
     "Add the message to be signed. Return the self object."
    },
    {"pk-sign/finish", pk_sign_finish,
     "(pk-sign/finish op &opt rng)\n\n"
     "Return a signature over all of the messages provided. Afterwards, "
     "the sign operator is reset and may be used to sign a new message."
     "New rng is used by default, if `rng` is not provided."
    },

    {NULL, NULL, NULL}
};

static void submod_pk_sign(JanetTable *env) {
    janet_cfuns(env, "botan", pk_sign_cfuns);
    janet_register_abstract_type(get_pk_sign_obj_type());
}

#endif /* BOTAN_PK_SIGN_H */
