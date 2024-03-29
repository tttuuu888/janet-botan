/*
 * Copyright (c) 2024, Janet-botan Seungki Kim
 *
 * Janet-botan is released under the MIT License, see the LICENSE file.
 */

#ifndef BOTAN_PK_KEM_DECRYPT_H
#define BOTAN_PK_KEM_DECRYPT_H

typedef struct botan_pk_kem_decrypt_obj {
    botan_pk_op_kem_decrypt_t pk_kem_decrypt;
} botan_pk_kem_decrypt_obj_t;

/* Abstract Object functions */
static int pk_kem_decrypt_gc_fn(void *data, size_t len);
static int pk_kem_decrypt_get_fn(void *data, Janet key, Janet *out);

/* Janet functions */
static Janet pk_kem_decrypt_new(int32_t argc, Janet *argv);
static Janet pk_kem_decrypt_kem_shared_key_length(int32_t argc, Janet *argv);
static Janet pk_kem_decrypt_kem_decrypt_shared_key(int32_t argc, Janet *argv);

static JanetAbstractType pk_kem_decrypt_obj_type = {
    "botan/pk-kem-decrypt",
    pk_kem_decrypt_gc_fn,
    NULL,
    pk_kem_decrypt_get_fn,
    JANET_ATEND_GET
};

static JanetMethod pk_kem_decrypt_methods[] = {
    {"shared-key-length", pk_kem_decrypt_kem_shared_key_length},
    {"decrypt-shared-key", pk_kem_decrypt_kem_decrypt_shared_key},
    {NULL, NULL},
};

static JanetAbstractType *get_pk_kem_decrypt_obj_type() {
    return &pk_kem_decrypt_obj_type;
}

/* Abstract Object functions */
static int pk_kem_decrypt_gc_fn(void *data, size_t len) {
    botan_pk_kem_decrypt_obj_t *obj = (botan_pk_kem_decrypt_obj_t *)data;

    int ret = botan_pk_op_kem_decrypt_destroy(obj->pk_kem_decrypt);
    JANET_BOTAN_ASSERT(ret);

    return 0;
}

static int pk_kem_decrypt_get_fn(void *data, Janet key, Janet *out) {
    (void)data;
    if (!janet_checktype(key, JANET_KEYWORD)) {
        return 0;
    }

    return janet_getmethod(janet_unwrap_keyword(key), pk_kem_decrypt_methods, out);
}

/* Janet functions */
static Janet pk_kem_decrypt_new(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 2);
    botan_pk_kem_decrypt_obj_t *obj = janet_abstract(&pk_kem_decrypt_obj_type, sizeof(botan_pk_kem_decrypt_obj_t));
    memset(obj, 0, sizeof(botan_pk_kem_decrypt_obj_t));

    botan_private_key_obj_t *obj2 = janet_getabstract(argv, 0, get_private_key_obj_type());
    botan_privkey_t key = obj2->private_key;

    const char *kdf = janet_getcstring(argv, 1);

    int ret = botan_pk_op_kem_decrypt_create(&obj->pk_kem_decrypt, key, kdf);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_abstract(obj);
}

static Janet pk_kem_decrypt_kem_shared_key_length(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 2);

    int ret;
    botan_pk_kem_decrypt_obj_t *obj = janet_getabstract(argv, 0, get_pk_kem_decrypt_obj_type());
    botan_pk_op_kem_decrypt_t op = obj->pk_kem_decrypt;

    size_t desired_len = janet_getsize(argv, 1);
    size_t out_len = 0;
    ret = botan_pk_op_kem_decrypt_shared_key_length(op, desired_len, &out_len);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_number((double)out_len);
}

static Janet pk_kem_decrypt_kem_decrypt_shared_key(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 4);

    int ret;
    botan_pk_kem_decrypt_obj_t *obj = janet_getabstract(argv, 0, get_pk_kem_decrypt_obj_type());
    botan_pk_op_kem_decrypt_t op = obj->pk_kem_decrypt;

    JanetByteView salt = janet_getbytes(argv, 1);
    size_t desired_len = janet_getsize(argv, 2);
    JanetByteView encap_key = janet_getbytes(argv, 3);

    size_t shared_key_len = 0;
    ret = botan_pk_op_kem_decrypt_shared_key_length(op, desired_len, &shared_key_len);
    JANET_BOTAN_ASSERT(ret);

    JanetBuffer *shared_key_buf = janet_buffer(shared_key_len);
    ret = botan_pk_op_kem_decrypt_shared_key(op, salt.bytes, salt.len,
                                             encap_key.bytes, encap_key.len,
                                             desired_len,
                                             shared_key_buf->data, &shared_key_len);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_string(janet_string(shared_key_buf->data, shared_key_len));
}

static JanetReg pk_kem_decrypt_cfuns[] = {
    {"pk-kem-decrypt/new", pk_kem_decrypt_new,
     "(pk-kem-decrypt/new privkey kdf)\n\n"
     "Create a KEM operation, decrypt version."
    },
    {"pk-kem-decrypt/shared-key-length", pk_kem_decrypt_kem_shared_key_length,
     "(pk-kem-decrypt/shared-key-length op desired-shared-key-length)\n\n"
     "Return the output shared key length, assuming desired-shared-key-length "
     "is provided."
    },
    {"pk-kem-decrypt/decrypt-shared-key", pk_kem_decrypt_kem_decrypt_shared_key,
     "pk-kem-decrypt/decrypt-shared-key op salt desired-key-len encapsulated-key)\n\n"
     "Decrypt an encapsulated key and return the shared secret."
    },

    {NULL, NULL, NULL}
};

static void submod_pk_kem_decrypt(JanetTable *env) {
    janet_cfuns(env, "botan", pk_kem_decrypt_cfuns);
    janet_register_abstract_type(get_pk_kem_decrypt_obj_type());
}

#endif /* BOTAN_PK_KEM_DECRYPT_H */
