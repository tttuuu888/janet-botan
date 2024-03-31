/*
 * Copyright (c) 2024, Janet-botan Seungki Kim
 *
 * Janet-botan is released under the MIT License, see the LICENSE file.
 */

#ifndef BOTAN_X509_CERT_H
#define BOTAN_X509_CERT_H

typedef struct botan_x509_cert_obj {
    botan_x509_cert_t x509_cert;
} botan_x509_cert_obj_t;

/* Abstract Object functions */
static int x509_cert_gc_fn(void *data, size_t len);
static int x509_cert_get_fn(void *data, Janet key, Janet *out);

/* Janet functions */
static Janet x509_cert_dup(int32_t argc, Janet *argv);
static Janet x509_cert_not_before(int32_t argc, Janet *argv);
static Janet x509_cert_not_after(int32_t argc, Janet *argv);
static Janet x509_cert_to_string(int32_t argc, Janet *argv);
static Janet x509_cert_fingerprint(int32_t argc, Janet *argv);
static Janet x509_cert_serial_number(int32_t argc, Janet *argv);
static Janet x509_cert_authority_key_id(int32_t argc, Janet *argv);
static Janet x509_cert_subject_key_id(int32_t argc, Janet *argv);
static Janet x509_cert_subject_public_key_bits(int32_t argc, Janet *argv);
static Janet x509_cert_subject_public_key(int32_t argc, Janet *argv);
static Janet x509_cert_subject_dn(int32_t argc, Janet *argv);
static Janet x509_cert_issuer_dn(int32_t argc, Janet *argv);
static Janet x509_cert_hostname_match(int32_t argc, Janet *argv);
static Janet x509_cert_allow_usage(int32_t argc, Janet *argv);

static JanetAbstractType x509_cert_obj_type = {
    "botan/x509_cert",
    x509_cert_gc_fn,
    NULL,
    x509_cert_get_fn,
    JANET_ATEND_GET
};

static JanetMethod x509_cert_methods[] = {
    {"dup", x509_cert_dup},
    {"not-before", x509_cert_not_before},
    {"not-after", x509_cert_not_after},
    {"to-string", x509_cert_to_string},
    {"fingerprint", x509_cert_fingerprint},
    {"serial-number", x509_cert_serial_number},
    {"authority-key-id", x509_cert_authority_key_id},
    {"subject-key-id", x509_cert_subject_key_id},
    {"subject-public-key-bits", x509_cert_subject_public_key_bits},
    {"subject-public-key", x509_cert_subject_public_key},
    {"subject-dn", x509_cert_subject_dn},
    {"issuer-dn", x509_cert_issuer_dn},
    {"hostname-match", x509_cert_hostname_match},
    {"allow-usage", x509_cert_allow_usage},
    {NULL, NULL},
};

static JanetAbstractType *get_x509_cert_obj_type() {
    return &x509_cert_obj_type;
}

/* Abstract Object functions */
static int x509_cert_gc_fn(void *data, size_t len) {
    botan_x509_cert_obj_t *obj = (botan_x509_cert_obj_t *)data;

    int ret = botan_x509_cert_destroy(obj->x509_cert);
    JANET_BOTAN_ASSERT(ret);

    return 0;
}

static int x509_cert_get_fn(void *data, Janet key, Janet *out) {
    (void)data;
    if (!janet_checktype(key, JANET_KEYWORD)) {
        return 0;
    }

    return janet_getmethod(janet_unwrap_keyword(key), x509_cert_methods, out);
}

/* Janet functions */
static Janet x509_cert_load(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 1);

    botan_x509_cert_obj_t *obj = janet_abstract(&x509_cert_obj_type, sizeof(botan_x509_cert_obj_t));
    memset(obj, 0, sizeof(botan_x509_cert_obj_t));

    JanetByteView cert = janet_getbytes(argv, 0);

    int ret = botan_x509_cert_load(&obj->x509_cert, cert.bytes, cert.len);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_abstract(obj);
}

static Janet x509_cert_load_file(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 1);

    botan_x509_cert_obj_t *obj = janet_abstract(&x509_cert_obj_type, sizeof(botan_x509_cert_obj_t));
    memset(obj, 0, sizeof(botan_x509_cert_obj_t));

    const char *filename = janet_getcstring(argv, 0);

    int ret = botan_x509_cert_load_file(&obj->x509_cert, filename);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_abstract(obj);
}

static Janet x509_cert_dup(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 2);

    botan_x509_cert_obj_t *obj = janet_getabstract(argv, 0, get_x509_cert_obj_type());
    botan_x509_cert_t cert = obj->x509_cert;

    botan_x509_cert_obj_t *obj2 = janet_abstract(&x509_cert_obj_type, sizeof(botan_x509_cert_obj_t));
    memset(obj2, 0, sizeof(botan_x509_cert_obj_t));

    int ret = botan_x509_cert_dup(&obj2->x509_cert, cert);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_abstract(obj2);
}

static Janet x509_cert_not_before(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 1);

    botan_x509_cert_obj_t *obj = janet_getabstract(argv, 0, get_x509_cert_obj_type());
    botan_x509_cert_t cert = obj->x509_cert;

    uint64_t time_since_epoch;
    int ret = botan_x509_cert_not_before(cert, &time_since_epoch);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_number((double)time_since_epoch);
}

static Janet x509_cert_not_after(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 1);

    botan_x509_cert_obj_t *obj = janet_getabstract(argv, 0, get_x509_cert_obj_type());
    botan_x509_cert_t cert = obj->x509_cert;

    uint64_t time_since_epoch;
    int ret = botan_x509_cert_not_after(cert, &time_since_epoch);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_number((double)time_since_epoch);
}

static Janet x509_cert_to_string(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 1);

    botan_x509_cert_obj_t *obj = janet_getabstract(argv, 0, get_x509_cert_obj_type());
    botan_x509_cert_t cert = obj->x509_cert;

    view_data_t data;
    int ret = botan_x509_cert_view_as_string(cert, &data, (botan_view_str_fn)view_str_func);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_string(janet_string(data.data, data.len));
}

static Janet x509_cert_fingerprint(int32_t argc, Janet *argv) {
    janet_arity(argc, 1, 2);

    int ret;
    botan_x509_cert_obj_t *obj = janet_getabstract(argv, 0, get_x509_cert_obj_type());
    botan_x509_cert_t cert = obj->x509_cert;

    const char *hash = "SHA-256";
    if (argc == 2) {
        hash = janet_getcstring(argv, 1);
    }

    size_t out_len = 128;
    JanetBuffer *out = janet_buffer(out_len);
    ret = botan_x509_cert_get_fingerprint(cert, hash, NULL, &out_len);
    if (!ret) {
        return janet_wrap_string(janet_string(out->data, out_len));
    } else if (ret != BOTAN_FFI_ERROR_INSUFFICIENT_BUFFER_SPACE) {
        JANET_BOTAN_ASSERT(ret);
    }

    out = janet_buffer(out_len);
    ret = botan_x509_cert_get_fingerprint(cert, hash, out->data, &out_len);
    JANET_BOTAN_ASSERT(ret);

    if (out->data[out_len - 1] == 0) {
        out_len -= 1;
    }

    return janet_wrap_string(janet_string(out->data, out_len));
}

static Janet x509_cert_serial_number(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 1);

    botan_x509_cert_obj_t *obj = janet_getabstract(argv, 0, get_x509_cert_obj_type());
    botan_x509_cert_t cert = obj->x509_cert;

    size_t out_len = 32;
    JanetBuffer *out = janet_buffer(out_len);

    int ret = botan_x509_cert_get_serial_number(cert, out->data, &out_len);
    if (!ret) {
        return janet_wrap_string(janet_string(out->data, out_len));
    } else if (ret != BOTAN_FFI_ERROR_INSUFFICIENT_BUFFER_SPACE) {
        JANET_BOTAN_ASSERT(ret);
    }

    out = janet_buffer(out_len);
    ret = botan_x509_cert_get_serial_number(cert, out->data, &out_len);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_string(janet_string(out->data, out_len));
}

static Janet x509_cert_authority_key_id(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 1);

    botan_x509_cert_obj_t *obj = janet_getabstract(argv, 0, get_x509_cert_obj_type());
    botan_x509_cert_t cert = obj->x509_cert;

    size_t out_len = 32;
    JanetBuffer *out = janet_buffer(out_len);

    int ret = botan_x509_cert_get_authority_key_id(cert, out->data, &out_len);
    if (!ret) {
        return janet_wrap_string(janet_string(out->data, out_len));
    } else if (ret != BOTAN_FFI_ERROR_INSUFFICIENT_BUFFER_SPACE) {
        JANET_BOTAN_ASSERT(ret);
    }

    out = janet_buffer(out_len);
    ret = botan_x509_cert_get_authority_key_id(cert, out->data, &out_len);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_string(janet_string(out->data, out_len));
}

static Janet x509_cert_subject_key_id(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 1);

    botan_x509_cert_obj_t *obj = janet_getabstract(argv, 0, get_x509_cert_obj_type());
    botan_x509_cert_t cert = obj->x509_cert;

    size_t out_len = 32;
    JanetBuffer *out = janet_buffer(out_len);

    int ret = botan_x509_cert_get_subject_key_id(cert, out->data, &out_len);
    if (!ret) {
        return janet_wrap_string(janet_string(out->data, out_len));
    } else if (ret != BOTAN_FFI_ERROR_INSUFFICIENT_BUFFER_SPACE) {
        JANET_BOTAN_ASSERT(ret);
    }

    out = janet_buffer(out_len);
    ret = botan_x509_cert_get_subject_key_id(cert, out->data, &out_len);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_string(janet_string(out->data, out_len));
}

static Janet x509_cert_subject_public_key_bits(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 1);

    botan_x509_cert_obj_t *obj = janet_getabstract(argv, 0, get_x509_cert_obj_type());
    botan_x509_cert_t cert = obj->x509_cert;

    view_data_t data;
    int ret = botan_x509_cert_view_public_key_bits(cert, &data, (botan_view_bin_fn)view_bin_func);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_string(janet_string(data.data, data.len));
}

static Janet x509_cert_subject_public_key(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 1);

    botan_x509_cert_obj_t *obj = janet_getabstract(argv, 0, get_x509_cert_obj_type());
    botan_x509_cert_t cert = obj->x509_cert;

    botan_public_key_obj_t *obj2 = janet_abstract(&public_key_obj_type, sizeof(botan_public_key_obj_t));
    memset(obj2, 0, sizeof(botan_public_key_obj_t));

    int ret = botan_x509_cert_get_public_key(cert, &obj2->public_key);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_abstract(obj2);
}

static Janet x509_cert_subject_dn(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 3);

    botan_x509_cert_obj_t *obj = janet_getabstract(argv, 0, get_x509_cert_obj_type());
    botan_x509_cert_t cert = obj->x509_cert;

    const char *key = janet_getcstring(argv, 1);
    size_t index = janet_getsize(argv, 2);

    size_t out_len = 0;

    int ret = botan_x509_cert_get_subject_dn(cert, key, index, NULL, &out_len);
    if (ret != BOTAN_FFI_ERROR_INSUFFICIENT_BUFFER_SPACE) {
        JANET_BOTAN_ASSERT(ret);
    }

    JanetBuffer *out = janet_buffer(out_len);
    ret = botan_x509_cert_get_subject_dn(cert, key, index, out->data, &out_len);
    JANET_BOTAN_ASSERT(ret);

    if (out->data[out_len - 1] == 0) {
        out_len -= 1;
    }

    return janet_wrap_string(janet_string(out->data, out_len));
}

static Janet x509_cert_issuer_dn(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 3);

    botan_x509_cert_obj_t *obj = janet_getabstract(argv, 0, get_x509_cert_obj_type());
    botan_x509_cert_t cert = obj->x509_cert;

    const char *key = janet_getcstring(argv, 1);
    size_t index = janet_getsize(argv, 2);

    size_t out_len = 0;

    int ret = botan_x509_cert_get_subject_dn(cert, key, index, NULL, &out_len);
    if (ret != BOTAN_FFI_ERROR_INSUFFICIENT_BUFFER_SPACE) {
        JANET_BOTAN_ASSERT(ret);
    }

    JanetBuffer *out = janet_buffer(out_len);
    ret = botan_x509_cert_get_subject_dn(cert, key, index, out->data, &out_len);
    JANET_BOTAN_ASSERT(ret);

    if (out->data[out_len - 1] == 0) {
        out_len -= 1;
    }

    return janet_wrap_string(janet_string(out->data, out_len));
}

static Janet x509_cert_hostname_match(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 2);

    botan_x509_cert_obj_t *obj = janet_getabstract(argv, 0, get_x509_cert_obj_type());
    botan_x509_cert_t cert = obj->x509_cert;
    const char *hostname = janet_getcstring(argv, 1);

    int ret = botan_x509_cert_hostname_match(cert, hostname);
    if (ret != 0 && ret != -1) {
        JANET_BOTAN_ASSERT(ret);
    }

    return janet_wrap_boolean(ret == 0);
}

static Janet x509_cert_allow_usage(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 2);

    botan_x509_cert_obj_t *obj = janet_getabstract(argv, 0, get_x509_cert_obj_type());
    botan_x509_cert_t cert = obj->x509_cert;
    const char *usage = janet_getcstring(argv, 1);

    struct usage_key_pair {
        const char *usuage;
        unsigned int key;
    };
    struct usage_key_pair pair_list[] = {
        {"NO-CONSTRAINTS", 0},
        {"DIGITAL-SIGNATURE", 32768},
        {"NON-REPUDIATION", 16384},
        {"KEY-ENCIPHERMENT", 8192},
        {"DATA-ENCIPHERMENT", 4096},
        {"KEY-AGREEMENT", 2048},
        {"KEY-CERT-SIGN", 1024},
        {"CRL-SIGN", 512},
        {"ENCIPHER-ONLY", 256},
        {"DECIPHER-ONLY", 128}
    };

    unsigned int key = 1;
    for(int i=0; i<(sizeof(pair_list)/sizeof(struct usage_key_pair)); i++) {
        if (strcmp(pair_list[i].usuage, usage) == 0) {
            key = pair_list[i].key;
            break;
        }
    }

    if (key == 1) {
        janet_panic("Invalid argument.");
    }

    int ret = botan_x509_cert_allowed_usage(cert, key);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_boolean(ret == 0);
}

static JanetReg x509_cert_cfuns[] = {
    {"x509-cert/load", x509_cert_load,
     "(x509-cert/load cert)\n\n"
     "Load a X.509 certificate from DER or PEM representation."
    },
    {"x509-cert/load-file", x509_cert_load_file,
     "(x509-cert/load-file file-name)\n\n"
     "Load an X.509 certificate from a file."
    },
    {"x509-cert/dup", x509_cert_dup,
     "(x509-cert/dup cert-obj)\n\n"
     "Create a new object that refers to the same certificate."
    },
    {"x509-cert/not-before", x509_cert_not_before,
     "(x509-cert/not-before cert-obj)\n\n"
     "Return the time the certificate becomes valid, as seconds since epoch."
    },
    {"x509-cert/not-after", x509_cert_not_after,
     "(x509-cert/not-after cert-obj)\n\n"
     "Return the time the certificate expires, as seconds since epoch."
    },
    {"x509-cert/to-string", x509_cert_to_string,
     "(x509-cert/to-string cert-obj)\n\n"
     "Return a free-form string representation of this certificate"
    },
    {"x509-cert/fingerprint", x509_cert_fingerprint,
     "(x509-cert/fingerprint cert-obj &opt hash-algo)\n\n"
     "Return a fingerprint for the certificate, which is basically just a "
     "hash of the binary contents. Normally \"SHA-1\" or \"SHA-256\" is "
     "used, but any hash function is allowed. If omitted, \"SHA-256\" is used."
    },
    {"x509-cert/serial-number", x509_cert_serial_number,
     "(x509-cert/serial-number cert-obj)\n\n"
     "Return the serial number of the certificate."
    },
    {"x509-cert/authority-key-id", x509_cert_authority_key_id,
     "(x509-cert/authority-key-id cert-obj)\n\n"
     "Return the authority key ID set in the certificate, which may be empty."
    },
    {"x509-cert/subject-key-id", x509_cert_subject_key_id,
     "(x509-cert/subject-key-id cert-obj)\n\n"
     "Return the subject key ID set in the certificate, which may be empty."
    },
    {"x509-cert/subject-public-key-bits", x509_cert_subject_public_key_bits,
     "(x509-cert/subject-public-key-bits cert-obj)\n\n"
     "Get the serialized representation of the public key included in this "
     "certificate."
    },
    {"x509-cert/subject-public-key", x509_cert_subject_public_key,
     "(x509-cert/subject-public-key cert-obj)\n\n"
     "Get the public key included in this certificate as an object of `pubkey`."
    },
    {"x509-cert/subject-dn", x509_cert_subject_dn,
     "(x509-cert/subject-dn cert-obj key index)\n\n"
     "Get a value from the subject DN field. `key` specifies a value to get, "
     "for instance \"Name\" or \"Country\"."
    },
    {"x509-cert/issuer-dn", x509_cert_issuer_dn,
     "(x509-cert/issuer-dn cert-obj key index)\n\n"
     "Get a value from the issuer DN field. `key` specifies a value to get, "
     "for instance \"Name\" or \"Country\"."
    },

    {NULL, NULL, NULL}
};

static void submod_x509_cert(JanetTable *env) {
    janet_cfuns(env, "botan", x509_cert_cfuns);
    janet_register_abstract_type(get_x509_cert_obj_type());
}

#endif /* BOTAN_X509_CERT_H */
