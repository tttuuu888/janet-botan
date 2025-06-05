/*
 * Copyright (c) 2024, Janet-botan Seungki Kim
 *
 * Janet-botan is released under the MIT License, see the LICENSE file.
 */

#ifndef BOTAN_PK_KEM_ENCRYPT_H
#define BOTAN_PK_KEM_ENCRYPT_H

typedef struct botan_pk_kem_encrypt_obj {
    botan_pk_op_kem_encrypt_t pk_kem_encrypt;
} botan_pk_kem_encrypt_obj_t;

/* Abstract Object functions */
static int pk_kem_encrypt_gc_fn(void *data, size_t len);
static int pk_kem_encrypt_get_fn(void *data, Janet key, Janet *out);

/* Janet functions */
static Janet pk_kem_encrypt_new(int32_t argc, Janet *argv);
static Janet pk_kem_encrypt_kem_shared_key_length(int32_t argc, Janet *argv);
static Janet pk_kem_encrypt_kem_encapsulated_key_length(int32_t argc, Janet *argv);
static Janet pk_kem_encrypt_kem_create_shared_key(int32_t argc, Janet *argv);

static JanetAbstractType pk_kem_encrypt_obj_type = {
    "botan/pk-kem-encrypt",
    pk_kem_encrypt_gc_fn,
    NULL,
    pk_kem_encrypt_get_fn,
    JANET_ATEND_GET
};

static JanetMethod pk_kem_encrypt_methods[] = {
    {"shared-key-length", pk_kem_encrypt_kem_shared_key_length},
    {"encapsulated-key-length", pk_kem_encrypt_kem_encapsulated_key_length},
    {"create-shared-key", pk_kem_encrypt_kem_create_shared_key},
    {NULL, NULL},
};

static JanetAbstractType *get_pk_kem_encrypt_obj_type() {
    return &pk_kem_encrypt_obj_type;
}

/* Abstract Object functions */
static int pk_kem_encrypt_gc_fn(void *data, size_t len) {
    botan_pk_kem_encrypt_obj_t *obj = (botan_pk_kem_encrypt_obj_t *)data;

    int ret = botan_pk_op_kem_encrypt_destroy(obj->pk_kem_encrypt);
    JANET_BOTAN_ASSERT(ret);

    return 0;
}

static int pk_kem_encrypt_get_fn(void *data, Janet key, Janet *out) {
    (void)data;
    if (!janet_checktype(key, JANET_KEYWORD)) {
        return 0;
    }

    return janet_getmethod(janet_unwrap_keyword(key), pk_kem_encrypt_methods, out);
}

/* Janet functions */
static Janet pk_kem_encrypt_new(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 2);
    botan_pk_kem_encrypt_obj_t *obj = janet_abstract(&pk_kem_encrypt_obj_type, sizeof(botan_pk_kem_encrypt_obj_t));
    memset(obj, 0, sizeof(botan_pk_kem_encrypt_obj_t));

    botan_public_key_obj_t *obj2 = janet_getabstract(argv, 0, get_public_key_obj_type());
    botan_pubkey_t key = obj2->public_key;

    const char *kdf = janet_getcstring(argv, 1);

    int ret = botan_pk_op_kem_encrypt_create(&obj->pk_kem_encrypt, key, kdf);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_abstract(obj);
}

static Janet pk_kem_encrypt_kem_shared_key_length(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 2);

    int ret;
    botan_pk_kem_encrypt_obj_t *obj = janet_getabstract(argv, 0, get_pk_kem_encrypt_obj_type());
    botan_pk_op_kem_encrypt_t op = obj->pk_kem_encrypt;

    size_t desired_len = janet_getsize(argv, 1);
    size_t out_len = 0;
    ret = botan_pk_op_kem_encrypt_shared_key_length(op, desired_len, &out_len);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_number((double)out_len);
}

static Janet pk_kem_encrypt_kem_encapsulated_key_length(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 1);

    int ret;
    botan_pk_kem_encrypt_obj_t *obj = janet_getabstract(argv, 0, get_pk_kem_encrypt_obj_type());
    botan_pk_op_kem_encrypt_t op = obj->pk_kem_encrypt;

    size_t out_len = 0;
    ret = botan_pk_op_kem_encrypt_encapsulated_key_length(op, &out_len);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_number((double)out_len);
}

static Janet pk_kem_encrypt_kem_create_shared_key(int32_t argc, Janet *argv) {
    janet_arity(argc, 3, 4);

    int ret;
    botan_pk_kem_encrypt_obj_t *obj = janet_getabstract(argv, 0, get_pk_kem_encrypt_obj_type());
    botan_pk_op_kem_encrypt_t op = obj->pk_kem_encrypt;

    JanetByteView salt = janet_getbytes(argv, 1);
    size_t desired_len = janet_getsize(argv, 2);

    botan_rng_obj_t *obj2;
    botan_rng_t rng;

    if (argc == 4) {
        obj2 = janet_getabstract(argv, 3, get_rng_obj_type());
        rng = obj2->rng;
    } else {
        obj2 = janet_abstract(&rng_obj_type, sizeof(botan_rng_obj_t));
        memset(obj2, 0, sizeof(botan_rng_obj_t));

        ret = botan_rng_init(&obj2->rng, "system");
        JANET_BOTAN_ASSERT(ret);
        rng = obj2->rng;
    }

    size_t shared_key_len = 0;
    ret = botan_pk_op_kem_encrypt_shared_key_length(op, desired_len, &shared_key_len);
    JANET_BOTAN_ASSERT(ret);

    JanetBuffer *shared_key_buf = janet_buffer(shared_key_len);

    size_t encapsulated_key_len = 0;
    ret = botan_pk_op_kem_encrypt_encapsulated_key_length(op, &encapsulated_key_len);
    JANET_BOTAN_ASSERT(ret);

    JanetBuffer *encapsulated_key_buf = janet_buffer(encapsulated_key_len);

    ret = botan_pk_op_kem_encrypt_create_shared_key(
        op, rng, salt.bytes, salt.len, desired_len,
        shared_key_buf->data, &shared_key_len,
        encapsulated_key_buf->data, &encapsulated_key_len);
    JANET_BOTAN_ASSERT(ret);

    Janet keys[2] = {
        janet_wrap_string(janet_string(shared_key_buf->data, shared_key_len)),
        janet_wrap_string(janet_string(encapsulated_key_buf->data, encapsulated_key_len)),
    };
    return janet_wrap_tuple(janet_tuple_n(keys, 2));
}


static JanetReg pk_kem_encrypt_cfuns[] = {
    {"pk-kem-encrypt/new", pk_kem_encrypt_new,
     "(pk-kem-encrypt/new pubkey kdf)\n\n"
     "Create a KEM operation, encrypt version."
    },
    {"pk-kem-encrypt/shared-key-length", pk_kem_encrypt_kem_shared_key_length,
     "(pk-kem-encrypt/shared-key-length op desired-shared-key-length)\n\n"
     "Return the output shared key length, assuming desired-shared-key-length "
     "is provided."
    },
    {"pk-kem-encrypt/encapsulated-key-length", pk_kem_encrypt_kem_encapsulated_key_length,
     "(pk-kem-encrypt/encapsulated-key-length op)\n\n"
     "Return the length of the encapsulated key."
    },
    {"pk-kem-encrypt/create-shared-key", pk_kem_encrypt_kem_create_shared_key,
     "(pk-kem-encrypt/create-shared-key op salt desired-key-len &opt rng)\n\n"
     "Create a new encapsulated key. If `rng` is not provided, new rng is "
     "used by default. Return the tuple of (shared-key, encapsulated-key)"
    },

    {NULL, NULL, NULL}
};

static void submod_pk_kem_encrypt(JanetTable *env) {
    janet_cfuns(env, "botan", pk_kem_encrypt_cfuns);
    janet_register_abstract_type(get_pk_kem_encrypt_obj_type());
}

#endif /* BOTAN_PK_KEM_ENCRYPT_H */
