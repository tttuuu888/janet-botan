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
static Janet private_key_get_public_key(int32_t argc, Janet *argv);
static Janet private_key_to_pem(int32_t argc, Janet *argv);
static Janet private_key_to_der(int32_t argc, Janet *argv);
static Janet private_key_check_key(int32_t argc, Janet *argv);
static Janet private_key_algo_name(int32_t argc, Janet *argv);
static Janet private_key_export(int32_t argc, Janet *argv);
static Janet private_key_get_field(int32_t argc, Janet *argv);

static JanetAbstractType private_key_obj_type = {
    "botan/private-key",
    private_key_gc_fn,
    NULL,
    private_key_get_fn,
    JANET_ATEND_GET
};

static JanetMethod private_key_methods[] = {
    {"get-pubkey", private_key_get_public_key},
    {"to-pem", private_key_to_pem},
    {"to-der", private_key_to_der},
    {"check-key", private_key_check_key},
    {"algo-name", private_key_algo_name},
    {"export", private_key_export},
    {"get-field", private_key_get_field},

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
    char *pass = NULL;

    if (argc == 2) {
        pass = (char *)janet_getcstring(argv, 1);
    }

    ret = botan_privkey_load(&obj->private_key, (botan_rng_t)NULL, blob.bytes, blob.len, (const char*)pass);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_abstract(obj);
}

static Janet private_key_load_rsa(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 3);

    int ret;
    botan_private_key_obj_t *obj = janet_abstract(&private_key_obj_type, sizeof(botan_private_key_obj_t));
    memset(obj, 0, sizeof(botan_private_key_obj_t));

    botan_mpi_obj_t *obj_p = janet_getabstract(argv, 0, get_mpi_obj_type());
    botan_mp_t mpi_p = obj_p->mpi;

    botan_mpi_obj_t *obj_q = janet_getabstract(argv, 1, get_mpi_obj_type());
    botan_mp_t mpi_q = obj_q->mpi;

    botan_mpi_obj_t *obj_e = janet_getabstract(argv, 2, get_mpi_obj_type());
    botan_mp_t mpi_e = obj_e->mpi;

    ret = botan_privkey_load_rsa(&obj->private_key, mpi_p, mpi_q, mpi_e);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_abstract(obj);
}

static Janet private_key_load_dsa(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 4);

    int ret;
    botan_private_key_obj_t *obj = janet_abstract(&private_key_obj_type, sizeof(botan_private_key_obj_t));
    memset(obj, 0, sizeof(botan_private_key_obj_t));

    botan_mpi_obj_t *obj_p = janet_getabstract(argv, 0, get_mpi_obj_type());
    botan_mp_t mpi_p = obj_p->mpi;

    botan_mpi_obj_t *obj_q = janet_getabstract(argv, 1, get_mpi_obj_type());
    botan_mp_t mpi_q = obj_q->mpi;

    botan_mpi_obj_t *obj_g = janet_getabstract(argv, 2, get_mpi_obj_type());
    botan_mp_t mpi_g = obj_g->mpi;

    botan_mpi_obj_t *obj_x = janet_getabstract(argv, 3, get_mpi_obj_type());
    botan_mp_t mpi_x = obj_x->mpi;

    ret = botan_privkey_load_dsa(&obj->private_key, mpi_p, mpi_q, mpi_g, mpi_x);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_abstract(obj);
}

static Janet private_key_load_dh(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 3);

    int ret;
    botan_private_key_obj_t *obj = janet_abstract(&private_key_obj_type, sizeof(botan_private_key_obj_t));
    memset(obj, 0, sizeof(botan_private_key_obj_t));

    botan_mpi_obj_t *obj_p = janet_getabstract(argv, 0, get_mpi_obj_type());
    botan_mp_t mpi_p = obj_p->mpi;

    botan_mpi_obj_t *obj_g = janet_getabstract(argv, 1, get_mpi_obj_type());
    botan_mp_t mpi_g = obj_g->mpi;

    botan_mpi_obj_t *obj_x = janet_getabstract(argv, 2, get_mpi_obj_type());
    botan_mp_t mpi_x = obj_x->mpi;

    ret = botan_privkey_load_dh(&obj->private_key, mpi_p, mpi_g, mpi_x);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_abstract(obj);
}

static Janet private_key_load_elgamal(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 3);

    int ret;
    botan_private_key_obj_t *obj = janet_abstract(&private_key_obj_type, sizeof(botan_private_key_obj_t));
    memset(obj, 0, sizeof(botan_private_key_obj_t));

    botan_mpi_obj_t *obj_p = janet_getabstract(argv, 0, get_mpi_obj_type());
    botan_mp_t mpi_p = obj_p->mpi;

    botan_mpi_obj_t *obj_g = janet_getabstract(argv, 1, get_mpi_obj_type());
    botan_mp_t mpi_g = obj_g->mpi;

    botan_mpi_obj_t *obj_x = janet_getabstract(argv, 2, get_mpi_obj_type());
    botan_mp_t mpi_x = obj_x->mpi;

    ret = botan_privkey_load_elgamal(&obj->private_key, mpi_p, mpi_g, mpi_x);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_abstract(obj);
}

static Janet private_key_load_ecdsa(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 2);

    int ret;
    botan_private_key_obj_t *obj = janet_abstract(&private_key_obj_type, sizeof(botan_private_key_obj_t));
    memset(obj, 0, sizeof(botan_private_key_obj_t));

    const char *curve = janet_getcstring(argv, 0);
    botan_mpi_obj_t *obj_x = janet_getabstract(argv, 1, get_mpi_obj_type());
    botan_mp_t mpi_x = obj_x->mpi;

    ret = botan_privkey_load_ecdsa(&obj->private_key, mpi_x, curve);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_abstract(obj);
}

static Janet private_key_load_ecdh(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 2);

    int ret;
    botan_private_key_obj_t *obj = janet_abstract(&private_key_obj_type, sizeof(botan_private_key_obj_t));
    memset(obj, 0, sizeof(botan_private_key_obj_t));

    const char *curve = janet_getcstring(argv, 0);
    botan_mpi_obj_t *obj_x = janet_getabstract(argv, 1, get_mpi_obj_type());
    botan_mp_t mpi_x = obj_x->mpi;

    ret = botan_privkey_load_ecdh(&obj->private_key, mpi_x, curve);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_abstract(obj);
}

static Janet private_key_load_sm2(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 2);

    int ret;
    botan_private_key_obj_t *obj = janet_abstract(&private_key_obj_type, sizeof(botan_private_key_obj_t));
    memset(obj, 0, sizeof(botan_private_key_obj_t));

    const char *curve = janet_getcstring(argv, 0);
    botan_mpi_obj_t *obj_x = janet_getabstract(argv, 1, get_mpi_obj_type());
    botan_mp_t mpi_x = obj_x->mpi;

    ret = botan_privkey_load_sm2(&obj->private_key, mpi_x, curve);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_abstract(obj);
}

static Janet private_key_load_kyber(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 1);

    int ret;
    botan_private_key_obj_t *obj = janet_abstract(&private_key_obj_type, sizeof(botan_private_key_obj_t));
    memset(obj, 0, sizeof(botan_private_key_obj_t));

    JanetByteView key = janet_getbytes(argv, 0);

    ret = botan_privkey_load_kyber(&obj->private_key, key.bytes, key.len);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_abstract(obj);
}

static Janet private_key_get_public_key(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 1);

    botan_public_key_obj_t *obj_pub = janet_abstract(&public_key_obj_type, sizeof(botan_public_key_obj_t));
    memset(obj_pub, 0, sizeof(botan_public_key_obj_t));

    botan_private_key_obj_t *obj_pri = janet_getabstract(argv, 0, get_private_key_obj_type());
    botan_privkey_t pri_key = obj_pri->private_key;

    int ret = botan_privkey_export_pubkey(&obj_pub->public_key, pri_key);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_abstract(obj_pub);
}

static Janet private_key_to_pem(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 1);

    botan_private_key_obj_t *obj = janet_getabstract(argv, 0, get_private_key_obj_type());
    botan_privkey_t key = obj->private_key;

    size_t key_len = 0;
    int ret = botan_privkey_export(key, NULL, &key_len, BOTAN_PRIVKEY_EXPORT_FLAG_PEM);
    if (ret != BOTAN_FFI_ERROR_INSUFFICIENT_BUFFER_SPACE) {
        janet_panic(getBotanError(ret));
    }

    JanetBuffer *output = janet_buffer(key_len);
    ret = botan_privkey_export(key, output->data, &key_len, BOTAN_PRIVKEY_EXPORT_FLAG_PEM);
    JANET_BOTAN_ASSERT(ret);
    if (output->data[key_len - 1] == 0) {
        key_len -= 1;
    }

    return janet_wrap_string(janet_string(output->data, key_len));
}

static Janet private_key_to_der(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 1);

    botan_private_key_obj_t *obj = janet_getabstract(argv, 0, get_private_key_obj_type());
    botan_privkey_t key = obj->private_key;

    size_t key_len = 0;
    int ret = botan_privkey_export(key, NULL, &key_len, BOTAN_PRIVKEY_EXPORT_FLAG_DER);
    if (ret != BOTAN_FFI_ERROR_INSUFFICIENT_BUFFER_SPACE) {
        janet_panic(getBotanError(ret));
    }

    JanetBuffer *output = janet_buffer(key_len);
    ret = botan_privkey_export(key, output->data, &key_len, BOTAN_PRIVKEY_EXPORT_FLAG_DER);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_string(janet_string(output->data, key_len));
}

static Janet private_key_check_key(int32_t argc, Janet *argv) {
    janet_arity(argc, 2, 3);

    botan_private_key_obj_t *obj = janet_getabstract(argv, 0, get_private_key_obj_type());
    botan_privkey_t key = obj->private_key;
    botan_rng_obj_t *obj_rng = janet_getabstract(argv, 1, get_rng_obj_type());
    botan_rng_t rng = obj_rng->rng;
    uint32_t flag = 1;

    if (argc == 3) {
        flag = 0;
    }

    int ret = botan_privkey_check_key(key, rng, flag);
    return janet_wrap_boolean(ret == 0);
}

static Janet private_key_algo_name(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 1);

    botan_private_key_obj_t *obj = janet_getabstract(argv, 0, get_private_key_obj_type());
    botan_privkey_t key = obj->private_key;

    size_t algo_len = 0;
    int ret = botan_privkey_algo_name(key, NULL, &algo_len);
    if (ret != BOTAN_FFI_ERROR_INSUFFICIENT_BUFFER_SPACE) {
        janet_panic(getBotanError(ret));
    }

    JanetBuffer *output = janet_buffer(algo_len);
    ret = botan_privkey_algo_name(key, (char *)output->data, &algo_len);
    JANET_BOTAN_ASSERT(ret);

    if (output->data[algo_len - 1] == 0) {
        algo_len -= 1;
    }

    return janet_wrap_string(janet_string(output->data, algo_len));
}

static Janet private_key_export(int32_t argc, Janet *argv) {
    janet_arity(argc, 1, 2);

    if (argc == 2) {
        return private_key_to_pem(1, argv);
    } else {
        return private_key_to_der(1, argv);
    }
}

static Janet private_key_get_field(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 2);

    botan_private_key_obj_t *obj = janet_getabstract(argv, 0, get_private_key_obj_type());
    botan_privkey_t key = obj->private_key;
    const char *field = (const char *)janet_getstring(argv, 1);

    botan_mpi_obj_t *obj_mpi = janet_abstract(&mpi_obj_type, sizeof(botan_mpi_obj_t));
    memset(obj_mpi, 0, sizeof(botan_mpi_obj_t));

    int ret = botan_mp_init(&obj_mpi->mpi);
    JANET_BOTAN_ASSERT(ret);

    ret = botan_privkey_get_field(obj_mpi->mpi, key, field);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_abstract(obj_mpi);
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
    {"privkey/load-rsa", private_key_load_rsa,
     "(privkey/load-rsa p q e)\n\n"
     "Return a private RSA key."
    },
    {"privkey/load-dsa", private_key_load_dsa,
     "(privkey/load-dsa p q g x)\n\n"
     "Return a private DSA key."
    },
    {"privkey/load-dh", private_key_load_dh,
     "(privkey/load-dh p g x)\n\n"
     "Return a private DH key."
    },
    {"privkey/load-elgamal", private_key_load_elgamal,
     "(privkey/load-elgamal p g x)\n\n"
     "Return a private ElGamal key."
    },
    {"privkey/load-ecdsa", private_key_load_ecdsa,
     "(privkey/load-ecdsa curve x)\n\n"
     "Return a private ECDSA key."
    },
    {"privkey/load-ecdh", private_key_load_ecdh,
     "(privkey/load-ecdh curve x)\n\n"
     "Return a private ECDH key."
    },
    {"privkey/load-sm2", private_key_load_sm2,
     "(privkey/load-sm2 curve x)\n\n"
     "Return a private SM2 key."
    },
    {"privkey/load-kyber", private_key_load_kyber,
     "(privkey/load-kyber key)\n\n"
     "Return a private Kyber key."
    },
    {"privkey/get-pubkey", private_key_get_public_key,
     "(privkey/get-pubkey privkey)\n\n"
     "Return a `pubkey` object."
    },
    {"privkey/to-pem", private_key_to_pem,
     "(privkey/to-pem privkey)\n\n"
     "Return the PEM encoded private key (unencrypted)."
    },
    {"privkey/to-der", private_key_to_der,
     "(privkey/to-pem privkey)\n\n"
     "Return the DER encoded private key (unencrypted)."
    },
    {"privkey/check-key", private_key_check_key,
     "(privkey/check-key privkey rng &opt weak)\n\n"
     "Test the key for consistency. If weak is provided then less expensive "
     "tests are performed."
    },
    {"privkey/algo-name", private_key_check_key,
     "(privkey/algo-name privkey)\n\n"
     "Returns the algorithm name."
    },
    {"privkey/export", private_key_export,
     "(privkey/export &opt pem)\n\n"
     "Exports the private key in PKCS8 format. If `pem` is provided, the "
     "result is a PEM encoded string. Otherwise it is a binary DER value. "
     "The key will not be encrypted."
    },
    {"privkey/get-field", private_key_get_field,
     "(privkey/get-field filed-name)\n\n"
     "Return an integer field related to the private key. The valid field "
     "names vary depending on the algorithm. For example first RSA secret "
     "prime can be extracted with `(privkey/get-field key \"p\")`. This "
     "function can also be used to extract the public parameters."
    },

    {NULL, NULL, NULL}
};

static void submod_private_key(JanetTable *env) {
    janet_cfuns(env, "botan", private_key_cfuns);
    janet_register_abstract_type(get_private_key_obj_type());
}


#endif /* BOTAN_PRIVATE_KEY_H */
