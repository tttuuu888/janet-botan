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
static Janet private_key_to_raw(int32_t argc, Janet *argv);
static Janet private_key_check_key(int32_t argc, Janet *argv);
static Janet private_key_algo_name(int32_t argc, Janet *argv);
static Janet private_key_export(int32_t argc, Janet *argv);
static Janet private_key_get_field(int32_t argc, Janet *argv);
static Janet private_key_stateful_operation(int32_t argc, Janet *argv);
static Janet private_key_remaining_operations(int32_t argc, Janet *argv);
static Janet private_key_oid(int32_t argc, Janet *argv);

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
    {"to-raw", private_key_to_raw},
    {"check-key", private_key_check_key},
    {"algo-name", private_key_algo_name},
    {"export", private_key_export},
    {"get-field", private_key_get_field},
    {"stateful-operation", private_key_stateful_operation},
    {"remaining-operations", private_key_remaining_operations},
    {"oid", private_key_oid},

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

static Janet private_key_new_ec(int32_t argc, Janet *argv) {
    janet_arity(argc, 2, 3);

    int ret;
    botan_private_key_obj_t *obj = janet_abstract(&private_key_obj_type, sizeof(botan_private_key_obj_t));
    memset(obj, 0, sizeof(botan_private_key_obj_t));

    botan_rng_t rng;
    const char *algo = janet_getcstring(argv, 0);

    botan_ec_group_obj_t *obj1 = janet_getabstract(argv, 1, get_ec_group_obj_type());
    botan_ec_group_t ec_group = obj1->ec_group;

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

    ret = botan_ec_privkey_create(&obj->private_key, algo, ec_group, rng);
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

static Janet private_key_load_ml_kem(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 2);

    int ret;
    botan_private_key_obj_t *obj = janet_abstract(&private_key_obj_type, sizeof(botan_private_key_obj_t));
    memset(obj, 0, sizeof(botan_private_key_obj_t));

    JanetByteView key = janet_getbytes(argv, 0);
    const char *mode = janet_getcstring(argv, 1);

    ret = botan_privkey_load_ml_kem(&obj->private_key, key.bytes, key.len, mode);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_abstract(obj);
}

static Janet private_key_load_ed25519(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 1);

    int ret;
    botan_private_key_obj_t *obj = janet_abstract(&private_key_obj_type, sizeof(botan_private_key_obj_t));
    memset(obj, 0, sizeof(botan_private_key_obj_t));

    JanetByteView key = janet_getbytes(argv, 0);
    if (key.len != 32) {
        janet_panic(getBotanError(BOTAN_FFI_ERROR_INVALID_KEY_LENGTH));
    }

    ret = botan_privkey_load_ed25519(&obj->private_key, key.bytes);
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

    view_data_t data;
    int ret = botan_privkey_view_pem(key, &data, (botan_view_str_fn)view_str_func);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_string(janet_string(data.data, data.len));
}

static Janet private_key_to_der(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 1);

    botan_private_key_obj_t *obj = janet_getabstract(argv, 0, get_private_key_obj_type());
    botan_privkey_t key = obj->private_key;

    view_data_t data;
    int ret = botan_privkey_view_der(key, &data, (botan_view_bin_fn)view_bin_func);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_string(janet_string(data.data, data.len));
}

static Janet private_key_to_raw(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 1);

    botan_private_key_obj_t *obj = janet_getabstract(argv, 0, get_private_key_obj_type());
    botan_privkey_t key = obj->private_key;

    view_data_t data;
    int ret = botan_privkey_view_raw(key, &data, (botan_view_bin_fn)view_bin_func);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_string(janet_string(data.data, data.len));
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

static Janet private_key_stateful_operation(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 1);

    botan_private_key_obj_t *obj = janet_getabstract(argv, 0, get_private_key_obj_type());
    botan_privkey_t key = obj->private_key;

    int r = 0;
    int ret = botan_privkey_stateful_operation(key, &r);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_boolean(r != 0);
}

static Janet private_key_remaining_operations(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 1);

    botan_private_key_obj_t *obj = janet_getabstract(argv, 0, get_private_key_obj_type());
    botan_privkey_t key = obj->private_key;

    uint64_t r = 0;
    int ret = botan_privkey_remaining_operations(key, &r);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_number((double)r);
}

static Janet private_key_oid(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 1);

    botan_private_key_obj_t *obj = janet_getabstract(argv, 0, get_private_key_obj_type());
    botan_privkey_t key = obj->private_key;

    botan_oid_obj_t *obj1 = janet_abstract(&oid_obj_type, sizeof(botan_oid_obj_t));
    memset(obj1, 0, sizeof(botan_oid_obj_t));

    int ret = botan_privkey_oid(&obj1->oid, key);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_abstract(obj1);
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
    {"privkey/new-ec", private_key_new_ec,
     "(privkey/new-ec algo ec-group &opt rng)\n\n"
     "Creates a new EC Group private key. Use `rng` if provided."
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
    {"privkey/load-ml-kem", private_key_load_ml_kem,
     "(privkey/load-ml-kem key mode)\n\n"
     "Return a private ML-KEM key based on the given mode."
    },
    {"privkey/load-ed25519", private_key_load_ed25519,
     "(privkey/load-ed25519 key)\n\n"
     "Return a private ed25519 key created from a 32-byte raw key value."
    },
    {"privkey/get-pubkey", private_key_get_public_key,
     "(privkey/get-pubkey privkey)\n\n"
     "Return a `pubkey` object."
    },
    {"privkey/to-pem", private_key_to_pem,
     "(privkey/to-pem privkey)\n\n"
     "Return the unencrypted PEM encoding of the private key."
    },
    {"privkey/to-der", private_key_to_der,
     "(privkey/to-der privkey)\n\n"
     "Return the unencrypted DER encoding of the private key."
    },
    {"privkey/to-raw", private_key_to_raw,
     "(privkey/to-raw privkey)\n\n"
     "Return the unencrypted canonical raw encoding of the private key. "
     "This might not be defined for all key types."
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
    {"privkey/stateful-operation", private_key_stateful_operation,
     "(privkey/stateful-operation privkey)\n\n"
     "Checks whether a key is stateful. Return a boolean."
    },
    {"privkey/remaining-operations", private_key_remaining_operations,
     "(privkey/remaining-operations privkey)\n\n"
     "Return the number of remaining operations. If the key is not stateful, "
     "an error will be occurred."
    },
    {"privkey/oid", private_key_oid,
     "(privkey/oid pubkey)\n\n"
     "Return the key's associated OID."
    },

    {NULL, NULL, NULL}
};

static void submod_private_key(JanetTable *env) {
    janet_cfuns(env, "botan", private_key_cfuns);
    janet_register_abstract_type(get_private_key_obj_type());
}


#endif /* BOTAN_PRIVATE_KEY_H */
