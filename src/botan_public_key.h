/*
 * Copyright (c) 2024, Janet-botan Seungki Kim
 *
 * Janet-botan is released under the MIT License. (see LICENSE)
 */

#ifndef BOTAN_PUBLIC_KEY_H
#define BOTAN_PUBLIC_KEY_H

typedef struct botan_public_key_obj {
    botan_pubkey_t public_key;
} botan_public_key_obj_t;

/* Abstract Object functions */
static int public_key_gc_fn(void *data, size_t len);
static int public_key_get_fn(void *data, Janet key, Janet *out);

/* Janet functions */
static Janet public_key_to_pem(int32_t argc, Janet *argv);
static Janet public_key_to_der(int32_t argc, Janet *argv);
static Janet public_key_to_raw(int32_t argc, Janet *argv);
static Janet public_key_export(int32_t argc, Janet *argv);
static Janet public_key_check_key(int32_t argc, Janet *argv);
static Janet public_key_get_field(int32_t argc, Janet *argv);
static Janet public_key_algo_name(int32_t argc, Janet *argv);
static Janet public_key_get_public_point(int32_t argc, Janet *argv);
static Janet public_key_fingerprint(int32_t argc, Janet *argv);
static Janet public_key_estimated_strength(int32_t argc, Janet *argv);
static Janet public_key_oid(int32_t argc, Janet *argv);

static JanetAbstractType public_key_obj_type = {
    "botan/public-key",
    public_key_gc_fn,
    NULL,
    public_key_get_fn,
    JANET_ATEND_GET
};

static JanetMethod public_key_methods[] = {
    {"to-pem", public_key_to_pem},
    {"to-der", public_key_to_der},
    {"to-raw", public_key_to_raw},
    {"check-key", public_key_check_key},
    {"algo-name", public_key_algo_name},
    {"export", public_key_export},
    {"get-field", public_key_get_field},
    {"get-public-point", public_key_get_public_point},
    {"fingerprint", public_key_fingerprint},
    {"estimated-strength", public_key_estimated_strength},
    {"oid", public_key_oid},

    {NULL, NULL},
};

static JanetAbstractType *get_public_key_obj_type() {
    return &public_key_obj_type;
}

/* Abstract Object functions */
static int public_key_gc_fn(void *data, size_t len) {
    botan_public_key_obj_t *obj = (botan_public_key_obj_t *)data;

    int ret = botan_pubkey_destroy(obj->public_key);
    JANET_BOTAN_ASSERT(ret);

    return 0;
}

static int public_key_get_fn(void *data, Janet key, Janet *out) {
    (void)data;
    if (!janet_checktype(key, JANET_KEYWORD)) {
        return 0;
    }

    return janet_getmethod(janet_unwrap_keyword(key), public_key_methods, out);
}

/* Janet functions */
static Janet public_key_load(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 1);

    int ret;
    botan_public_key_obj_t *obj = janet_abstract(&public_key_obj_type, sizeof(botan_public_key_obj_t));
    memset(obj, 0, sizeof(botan_public_key_obj_t));

    JanetByteView blob = janet_getbytes(argv, 0);
    ret = botan_pubkey_load(&obj->public_key, blob.bytes, blob.len);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_abstract(obj);
}

static Janet public_key_load_rsa(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 2);
    botan_public_key_obj_t *obj = janet_abstract(&public_key_obj_type, sizeof(botan_public_key_obj_t));
    memset(obj, 0, sizeof(botan_public_key_obj_t));

    botan_mpi_obj_t *obj_n = janet_getabstract(argv, 0, get_mpi_obj_type());
    botan_mp_t mpi_n = obj_n->mpi;

    botan_mpi_obj_t *obj_e = janet_getabstract(argv, 1, get_mpi_obj_type());
    botan_mp_t mpi_e = obj_e->mpi;

    int ret = botan_pubkey_load_rsa(&obj->public_key, mpi_n, mpi_e);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_abstract(obj);
}

static Janet public_key_load_dsa(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 4);

    int ret;
    botan_public_key_obj_t *obj = janet_abstract(&public_key_obj_type, sizeof(botan_public_key_obj_t));
    memset(obj, 0, sizeof(botan_public_key_obj_t));

    botan_mpi_obj_t *obj_p = janet_getabstract(argv, 0, get_mpi_obj_type());
    botan_mp_t mpi_p = obj_p->mpi;

    botan_mpi_obj_t *obj_q = janet_getabstract(argv, 1, get_mpi_obj_type());
    botan_mp_t mpi_q = obj_q->mpi;

    botan_mpi_obj_t *obj_g = janet_getabstract(argv, 2, get_mpi_obj_type());
    botan_mp_t mpi_g = obj_g->mpi;

    botan_mpi_obj_t *obj_y = janet_getabstract(argv, 3, get_mpi_obj_type());
    botan_mp_t mpi_y = obj_y->mpi;

    ret = botan_pubkey_load_dsa(&obj->public_key, mpi_p, mpi_q, mpi_g, mpi_y);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_abstract(obj);
}

static Janet public_key_load_dh(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 3);

    int ret;
    botan_public_key_obj_t *obj = janet_abstract(&public_key_obj_type, sizeof(botan_public_key_obj_t));
    memset(obj, 0, sizeof(botan_public_key_obj_t));

    botan_mpi_obj_t *obj_p = janet_getabstract(argv, 0, get_mpi_obj_type());
    botan_mp_t mpi_p = obj_p->mpi;

    botan_mpi_obj_t *obj_g = janet_getabstract(argv, 1, get_mpi_obj_type());
    botan_mp_t mpi_g = obj_g->mpi;

    botan_mpi_obj_t *obj_y = janet_getabstract(argv, 2, get_mpi_obj_type());
    botan_mp_t mpi_y = obj_y->mpi;

    ret = botan_pubkey_load_dh(&obj->public_key, mpi_p, mpi_g, mpi_y);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_abstract(obj);
}

static Janet public_key_load_elgamal(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 3);

    int ret;
    botan_public_key_obj_t *obj = janet_abstract(&public_key_obj_type, sizeof(botan_public_key_obj_t));
    memset(obj, 0, sizeof(botan_public_key_obj_t));

    botan_mpi_obj_t *obj_p = janet_getabstract(argv, 0, get_mpi_obj_type());
    botan_mp_t mpi_p = obj_p->mpi;

    botan_mpi_obj_t *obj_g = janet_getabstract(argv, 1, get_mpi_obj_type());
    botan_mp_t mpi_g = obj_g->mpi;

    botan_mpi_obj_t *obj_y = janet_getabstract(argv, 2, get_mpi_obj_type());
    botan_mp_t mpi_y = obj_y->mpi;

    ret = botan_pubkey_load_elgamal(&obj->public_key, mpi_p, mpi_g, mpi_y);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_abstract(obj);
}

static Janet public_key_load_ecdsa(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 3);

    int ret;
    botan_public_key_obj_t *obj = janet_abstract(&public_key_obj_type, sizeof(botan_public_key_obj_t));
    memset(obj, 0, sizeof(botan_public_key_obj_t));

    const char *curve = janet_getcstring(argv, 0);
    botan_mpi_obj_t *obj_x = janet_getabstract(argv, 1, get_mpi_obj_type());
    botan_mp_t mpi_x = obj_x->mpi;

    botan_mpi_obj_t *obj_y = janet_getabstract(argv, 2, get_mpi_obj_type());
    botan_mp_t mpi_y = obj_y->mpi;

    ret = botan_pubkey_load_ecdsa(&obj->public_key, mpi_x, mpi_y, curve);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_abstract(obj);
}

static Janet public_key_load_ecdsa_sec1(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 2);

    int ret;
    botan_public_key_obj_t *obj = janet_abstract(&public_key_obj_type, sizeof(botan_public_key_obj_t));
    memset(obj, 0, sizeof(botan_public_key_obj_t));

    const char *curve = janet_getcstring(argv, 0);
    JanetByteView sec1 = janet_getbytes(argv, 1);

    ret = botan_pubkey_load_ecdsa_sec1(&obj->public_key, sec1.bytes, sec1.len, curve);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_abstract(obj);
}

static Janet public_key_load_ecdh(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 3);

    int ret;
    botan_public_key_obj_t *obj = janet_abstract(&public_key_obj_type, sizeof(botan_public_key_obj_t));
    memset(obj, 0, sizeof(botan_public_key_obj_t));

    const char *curve = janet_getcstring(argv, 0);
    botan_mpi_obj_t *obj_x = janet_getabstract(argv, 1, get_mpi_obj_type());
    botan_mp_t mpi_x = obj_x->mpi;

    botan_mpi_obj_t *obj_y = janet_getabstract(argv, 2, get_mpi_obj_type());
    botan_mp_t mpi_y = obj_y->mpi;

    ret = botan_pubkey_load_ecdh(&obj->public_key, mpi_x, mpi_y, curve);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_abstract(obj);
}

static Janet public_key_load_ecdh_sec1(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 2);

    int ret;
    botan_public_key_obj_t *obj = janet_abstract(&public_key_obj_type, sizeof(botan_public_key_obj_t));
    memset(obj, 0, sizeof(botan_public_key_obj_t));

    const char *curve = janet_getcstring(argv, 0);
    JanetByteView sec1 = janet_getbytes(argv, 1);

    ret = botan_pubkey_load_ecdh_sec1(&obj->public_key, sec1.bytes, sec1.len, curve);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_abstract(obj);
}

static Janet public_key_load_sm2(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 3);

    int ret;
    botan_public_key_obj_t *obj = janet_abstract(&public_key_obj_type, sizeof(botan_public_key_obj_t));
    memset(obj, 0, sizeof(botan_public_key_obj_t));

    const char *curve = janet_getcstring(argv, 0);
    botan_mpi_obj_t *obj_x = janet_getabstract(argv, 1, get_mpi_obj_type());
    botan_mp_t mpi_x = obj_x->mpi;
    botan_mpi_obj_t *obj_y = janet_getabstract(argv, 2, get_mpi_obj_type());
    botan_mp_t mpi_y = obj_y->mpi;

    ret = botan_pubkey_load_sm2(&obj->public_key, mpi_x, mpi_y, curve);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_abstract(obj);
}

static Janet public_key_load_sm2_sec1(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 2);

    int ret;
    botan_public_key_obj_t *obj = janet_abstract(&public_key_obj_type, sizeof(botan_public_key_obj_t));
    memset(obj, 0, sizeof(botan_public_key_obj_t));

    const char *curve = janet_getcstring(argv, 0);
    JanetByteView sec1 = janet_getbytes(argv, 1);

    ret = botan_pubkey_load_sm2_sec1(&obj->public_key, sec1.bytes, sec1.len, curve);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_abstract(obj);
}

static Janet public_key_load_ml_kem(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 2);

    int ret;
    botan_public_key_obj_t *obj = janet_abstract(&public_key_obj_type, sizeof(botan_public_key_obj_t));
    memset(obj, 0, sizeof(botan_public_key_obj_t));

    JanetByteView key = janet_getbytes(argv, 0);
    const char *mode = janet_getcstring(argv, 1);

    ret = botan_pubkey_load_ml_kem(&obj->public_key, key.bytes, key.len, mode);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_abstract(obj);
}

static Janet public_key_load_ed25519(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 1);

    int ret;
    botan_public_key_obj_t *obj = janet_abstract(&public_key_obj_type, sizeof(botan_public_key_obj_t));
    memset(obj, 0, sizeof(botan_public_key_obj_t));

    JanetByteView key = janet_getbytes(argv, 0);
    if (key.len != 32) {
        janet_panic(getBotanError(BOTAN_FFI_ERROR_INVALID_KEY_LENGTH));
    }

    ret = botan_pubkey_load_ed25519(&obj->public_key, key.bytes);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_abstract(obj);
}

static Janet public_key_to_pem(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 1);

    botan_public_key_obj_t *obj = janet_getabstract(argv, 0, get_public_key_obj_type());
    botan_pubkey_t key = obj->public_key;

    view_data_t data;
    int ret = botan_pubkey_view_pem(key, &data, (botan_view_str_fn)view_str_func);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_string(janet_string(data.data, data.len));
}

static Janet public_key_to_der(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 1);

    botan_public_key_obj_t *obj = janet_getabstract(argv, 0, get_public_key_obj_type());
    botan_pubkey_t key = obj->public_key;

    view_data_t data;
    int ret = botan_pubkey_view_der(key, &data, (botan_view_bin_fn)view_bin_func);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_string(janet_string(data.data, data.len));
}

static Janet public_key_to_raw(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 1);

    botan_public_key_obj_t *obj = janet_getabstract(argv, 0, get_public_key_obj_type());
    botan_pubkey_t key = obj->public_key;

    view_data_t data;
    int ret = botan_pubkey_view_raw(key, &data, (botan_view_bin_fn)view_bin_func);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_string(janet_string(data.data, data.len));
}

static Janet public_key_export(int32_t argc, Janet *argv) {
    janet_arity(argc, 1, 2);

    if (argc == 2) {
        return public_key_to_pem(1, argv);
    } else {
        return public_key_to_der(1, argv);
    }
}

static Janet public_key_check_key(int32_t argc, Janet *argv) {
    janet_arity(argc, 2, 3);

    botan_public_key_obj_t *obj = janet_getabstract(argv, 0, get_public_key_obj_type());
    botan_pubkey_t key = obj->public_key;
    botan_rng_obj_t *obj_rng = janet_getabstract(argv, 1, get_rng_obj_type());
    botan_rng_t rng = obj_rng->rng;
    uint32_t flag = 1;

    if (argc == 3) {
        flag = 0;
    }

    int ret = botan_pubkey_check_key(key, rng, flag);
    return janet_wrap_boolean(ret == 0);
}

static Janet public_key_get_field(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 2);

    botan_public_key_obj_t *obj = janet_getabstract(argv, 0, get_public_key_obj_type());
    botan_pubkey_t key = obj->public_key;
    const char *field = (const char *)janet_getstring(argv, 1);

    botan_mpi_obj_t *obj_mpi = janet_abstract(&mpi_obj_type, sizeof(botan_mpi_obj_t));
    memset(obj_mpi, 0, sizeof(botan_mpi_obj_t));

    int ret = botan_mp_init(&obj_mpi->mpi);
    JANET_BOTAN_ASSERT(ret);

    ret = botan_pubkey_get_field(obj_mpi->mpi, key, field);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_abstract(obj_mpi);
}

static Janet public_key_algo_name(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 1);

    botan_public_key_obj_t *obj = janet_getabstract(argv, 0, get_public_key_obj_type());
    botan_pubkey_t key = obj->public_key;

    size_t algo_len = 0;
    int ret = botan_pubkey_algo_name(key, NULL, &algo_len);
    if (ret != BOTAN_FFI_ERROR_INSUFFICIENT_BUFFER_SPACE) {
        janet_panic(getBotanError(ret));
    }

    JanetBuffer *output = janet_buffer(algo_len);
    ret = botan_pubkey_algo_name(key, (char *)output->data, &algo_len);
    JANET_BOTAN_ASSERT(ret);

    if (output->data[algo_len - 1] == 0) {
        algo_len -= 1;
    }

    return janet_wrap_string(janet_string(output->data, algo_len));
}

static Janet public_key_get_public_point(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 1);

    botan_public_key_obj_t *obj = janet_getabstract(argv, 0, get_public_key_obj_type());
    botan_pubkey_t key = obj->public_key;

    view_data_t data;
    int ret = botan_pubkey_view_ec_public_point(key, &data, (botan_view_bin_fn)view_bin_func);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_string(janet_string(data.data, data.len));
}

static Janet public_key_fingerprint(int32_t argc, Janet *argv) {
    janet_arity(argc, 1, 2);

    botan_public_key_obj_t *obj = janet_getabstract(argv, 0, get_public_key_obj_type());
    botan_pubkey_t key = obj->public_key;

    const char *hash_name = "SHA-256";
    if (argc == 2) {
        hash_name = janet_getcstring(argv, 1);
    }

    botan_hash_obj_t *obj_hash = janet_abstract(&hash_obj_type, sizeof(botan_hash_obj_t));
    memset(obj_hash, 0, sizeof(botan_hash_obj_t));

    int ret = botan_hash_init(&obj_hash->hash, hash_name, 0);
    JANET_BOTAN_ASSERT(ret);

    size_t out_len;
    ret = botan_hash_output_length(obj_hash->hash, &out_len);
    JANET_BOTAN_ASSERT(ret);

    JanetBuffer *out = janet_buffer(out_len);
    ret = botan_pubkey_fingerprint(key, hash_name, out->data, &out_len);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_string(janet_string(out->data, out_len));
}

static Janet public_key_estimated_strength(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 1);

    botan_public_key_obj_t *obj = janet_getabstract(argv, 0, get_public_key_obj_type());
    botan_pubkey_t key = obj->public_key;

    size_t estimate;
    int ret = botan_pubkey_estimated_strength(key, &estimate);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_number((double)estimate);
}

static Janet public_key_oid(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 1);

    botan_public_key_obj_t *obj = janet_getabstract(argv, 0, get_public_key_obj_type());
    botan_pubkey_t key = obj->public_key;

    botan_oid_obj_t *obj1 = janet_abstract(&oid_obj_type, sizeof(botan_oid_obj_t));
    memset(obj1, 0, sizeof(botan_oid_obj_t));

    int ret = botan_pubkey_oid(&obj1->oid, key);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_abstract(obj1);
}

static JanetReg public_key_cfuns[] = {
    {"pubkey/load", public_key_load,
     "(pubkey/load value)\n\n"
     "Load a public key. The value should be a PEM or DER blob."
    },
    {"pubkey/load-rsa", public_key_load_rsa,
     "(pubkey/load-rsa n e)\n\n"
     "Load an RSA public key giving the modulus and public exponent as "
     "integers."
    },
    {"pubkey/load-dsa", public_key_load_dsa,
     "(pubkey/load-dsa p q g y)\n\n"
     "`p`, `q`, `g`, `y` are MPI objects.\n"
     "Return a public DSA key."
    },
    {"pubkey/load-dh", public_key_load_dh,
     "(pubkey/load-dh p g y)\n\n"
     "`p`, `g`, `y` are MPI objects.\n"
     "Return a public DH key."
    },
    {"pubkey/load-elgamal", public_key_load_elgamal,
     "(pubkey/load-elgamal p g y)\n\n"
     "`p`, `g`, `y` are MPI objects.\n"
     "Return a public ElGamal key."
    },
    {"pubkey/load-ecdsa", public_key_load_ecdsa,
     "(pubkey/load-ecdsa curve x y)\n\n"
     "`x`, `y` are MPI objects.\n"
     "Return a public ECDSA key."
    },
    {"pubkey/load-ecdsa-sec1", public_key_load_ecdsa_sec1,
     "(pubkey/load-ecdsa-sec1 curve sec1)\n\n"
     "`sec1` is a byte string.\n"
     "Return a public ECDSA key."
    },
    {"pubkey/load-ecdh", public_key_load_ecdh,
     "(pubkey/load-ecdh curve x y)\n\n"
     "`x`, `y` are MPI objects.\n"
     "Return a public ECDH key."
    },
    {"pubkey/load-ecdh-sec1", public_key_load_ecdh_sec1,
     "(pubkey/load-ecdh-sec1 curve sec1)\n\n"
     "`sec1` is a byte string.\n"
     "Return a public ECDH key."
    },
    {"pubkey/load-sm2", public_key_load_sm2,
     "(pubkey/load-sm2 curve x y)\n\n"
     "`x`, `y` are MPI objects.\n"
     "Return a public SM2 key."
    },
    {"pubkey/load-sm2-sec1", public_key_load_sm2_sec1,
     "(pubkey/load-sm2-sec1 curve sec1)\n\n"
     "`sec1` is a byte string.\n"
     "Return a public SM2 key."
    },
    {"pubkey/load-ml-kem", public_key_load_ml_kem,
     "(pubkey/load-ml-kem key mode)\n\n"
     "Return a public ML-KEM key based on the given mode."
    },
    {"pubkey/load-ed25519", public_key_load_ed25519,
     "(pubkey/load-ed25519 key)\n\n"
     "Return a public ed25519 key created from a 32-byte raw key value."
    },
    {"pubkey/export", public_key_export,
     "(pubkey/export pubkey &opt pem)\n\n"
     "Exports the public key using the usual X.509 SPKI representation. "
     "If `pem` is provided, the result is a PEM encoded string. Otherwise "
     "it is a binary DER value."
    },
    {"pubkey/to-pem", public_key_to_pem,
     "(pubkey/to-pem pubkey)\n\n"
     "Return the unencrypted PEM encoding of the public key."
    },
    {"pubkey/to-der", public_key_to_der,
     "(pubkey/to-pem pubkey)\n\n"
     "Return the unencrypted DER encoding of the public key."
    },
    {"pubkey/to-raw", public_key_to_der,
     "(pubkey/to-raw pubkey)\n\n"
     "Return the unencrypted canonical raw encoding of the public key. "
     "This might not be defined for all key types."
    },
    {"pubkey/check-key", public_key_check_key,
     "(pubkey/check-key pubkey rng &opt weak)\n\n"
     "Test the key for consistency. If weak is provided then less expensive "
     "tests are performed."
    },
    {"pubkey/get-field", public_key_get_field,
     "(pubkey/get-field pubkey filed-name)\n\n"
     "Return an integer field related to the public key. The valid field "
     "names vary depending on the algorithm. For example RSA public modulus "
     "can be extracted with (pubkey/get-field \"n\")."
    },
    {"pubkey/algo-name", public_key_algo_name,
     "(pubkey/algo-name pubkey)\n\n"
     "Returns the algorithm name."
    },
    {"pubkey/get-public-point", public_key_get_public_point,
     "(pubkey/get-public-point pubkey)\n\n"
     "Return a public point of the key."
    },
    {"pubkey/fingerprint", public_key_fingerprint,
     "(pubkey/fingerprint pubkey &opt hash)\n\n"
     "Returns a hash of the public key. \"SHA-256\" is used as a default "
     "hash, if `hash` is not provided."
    },
    {"pubkey/estimated_strength", public_key_estimated_strength,
     "(pubkey/estimated_strength pubkey)\n\n"
     "Returns the estimated strength of this key against known attacks "
     "(NFS, Pollard’s rho, etc)"
    },
    {"pubkey/oid", public_key_oid,
     "(pubkey/oid pubkey)\n\n"
     "Return the key's associated OID."
    },
    {NULL, NULL, NULL}
};

static void submod_public_key(JanetTable *env) {
    janet_cfuns(env, "botan", public_key_cfuns);
}


#endif /* BOTAN_PUBLIC_KEY_H */
