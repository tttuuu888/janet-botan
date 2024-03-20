/*
 * Copyright (c) 2024, Janet-botan Seungki Kim
 *
 * Janet-botan is released under the MIT License, see the LICENSE file.
 */

#ifndef BOTAN_PRIVATE_KEY_H
#define BOTAN_PRIVATE_KEY_H

typedef struct botan_private_key_obj {
    botan_privkey_t private_key;
} botan_private_key_obj_t;

/* Abstract Object functions */
static int private_key_gc_fn(void *data, size_t len);
static int private_key_get_fn(void *data, Janet key, Janet *out);

/* Janet functions */
static Janet private_key_new(int32_t argc, Janet *argv);

static JanetAbstractType private_key_obj_type = {
    "botan/private-key",
    private_key_gc_fn,
    NULL,
    private_key_get_fn,
    JANET_ATEND_GET
};

static JanetMethod private_key_methods[] = {
    {NULL, NULL},
};

static JanetAbstractType *get_private_key_obj_type() {
    return &private_key_obj_type;
}

/* Abstract Object functions */
static int private_key_gc_fn(void *data, size_t len) {
    botan_private_key_obj_t *obj = (botan_private_key_obj_t *)data;

    int ret = botan_privkey_destroy(obj->private_key);
    JANET_BOTAN_ASSERT(ret);

    return 0;
}

static int private_key_get_fn(void *data, Janet key, Janet *out) {
    (void)data;
    if (!janet_checktype(key, JANET_KEYWORD)) {
        return 0;
    }

    return janet_getmethod(janet_unwrap_keyword(key), private_key_methods, out);
}

/* Janet functions */
static Janet private_key_new(int32_t argc, Janet *argv) {
    janet_arity(argc, 2, 3);

    int ret;
    botan_private_key_obj_t *obj = janet_abstract(&private_key_obj_type, sizeof(botan_private_key_obj_t));
    memset(obj, 0, sizeof(botan_private_key_obj_t));

    botan_rng_t rng;
    const char *algo = janet_getcstring(argv, 0);
    const char *param = janet_getcstring(argv, 1);

    if (argc == 3) {
        botan_rng_obj_t *obj2 = janet_getabstract(argv, 2, get_rng_obj_type());
        rng = obj2->rng;
    } else {
        botan_rng_obj_t *obj2 = janet_abstract(&rng_obj_type, sizeof(botan_rng_obj_t));
        memset(obj2, 0, sizeof(botan_rng_obj_t));

        ret = botan_rng_init(&obj2->rng, "system");
        JANET_BOTAN_ASSERT(ret);
        rng = obj2->rng;
    }

    ret = botan_privkey_create(&obj->private_key, algo, param, rng);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_abstract(obj);
}

static Janet private_key_load(int32_t argc, Janet *argv) {
    janet_arity(argc, 1, 2);

    int ret;
    botan_private_key_obj_t *obj = janet_abstract(&private_key_obj_type, sizeof(botan_private_key_obj_t));
    memset(obj, 0, sizeof(botan_private_key_obj_t));

    JanetByteView blob = janet_getbytes(argv, 0);
    char *pass = "";

    if (argc == 2) {
        pass = (char *)janet_getcstring(argv, 1);
    }

    ret = botan_privkey_load(&obj->private_key, (botan_rng_t)NULL, blob.bytes, blob.len, (const char*)pass);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_abstract(obj);
}

static Janet private_key_get_public_key(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 0);

    botan_private_key_obj_t *obj = janet_getabstract(argv, 0, get_private_key_obj_type());
    botan_privkey_t key = obj->private_key;

#if 0
    int ret = botan_privkey_export_pubkey(key, (botan_rng_t)NULL, blob.bytes, blob.len, (const char*)pass);
    JANET_BOTAN_ASSERT(ret);
#endif

    return janet_wrap_nil();
}

static JanetReg private_key_cfuns[] = {
    {"privkey/new", private_key_new,
     "(privkey/new algo param &opt rng)\n\n"
     "Creates a new private key. The parameter type/value depends on the "
     "algorithm. For \"rsa\" it is the size of the key in bits. For \"ecdsa\" "
     "and \"ecdh\" it is a group name (for instance \"secp256r1\"). For "
     "\"ecdh\" there is also a special case for group \"curve25519\" (which "
     "is actually a completely distinct key type with a non-standard encoding)."
     " Use `rng` if provided."
    },
    {"privkey/load", private_key_load,
     "(privkey/load blob &opt password)\n\n"
     "Return a private key (DER or PEM formats accepted). No `password` "
     "indicate no encryption expected."
    },
    {"privkey/get-pubkey", private_key_get_public_key,
     "(privkey/get-pubkey privkey)\n\n"
     "Return a `pubkey` object."
    },
    {NULL, NULL, NULL}
};

static void submod_private_key(JanetTable *env) {
    janet_cfuns(env, "botan", private_key_cfuns);
    janet_register_abstract_type(get_private_key_obj_type());
}


#endif /* BOTAN_PRIVATE_KEY_H */
