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

typedef struct botan_x509_crl_obj {
    botan_x509_crl_t x509_crl;
} botan_x509_crl_obj_t;

/* Abstract Object functions x509-cert */
static int x509_cert_gc_fn(void *data, size_t len);
static int x509_cert_get_fn(void *data, Janet key, Janet *out);

/* Abstract Object functions x509-crl */
static int x509_crl_gc_fn(void *data, size_t len);
static int x509_crl_get_fn(void *data, Janet key, Janet *out);

/* Janet functions x509-cert */
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
static Janet x509_cert_allowed_usage(int32_t argc, Janet *argv);
static Janet x509_cert_verify(int32_t argc, Janet *argv);
static Janet x509_cert_validation_status(int32_t argc, Janet *argv);

/* Janet functions x509-crl */
static Janet x509_crl_is_revoked(int32_t argc, Janet *argv);

static JanetAbstractType x509_cert_obj_type = {
    "botan/x509_cert",
    x509_cert_gc_fn,
    NULL,
    x509_cert_get_fn,
    JANET_ATEND_GET
};

static JanetAbstractType x509_crl_obj_type = {
    "botan/x509_crl",
    x509_crl_gc_fn,
    NULL,
    x509_crl_get_fn,
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
    {"allowed-usage", x509_cert_allowed_usage},
    {"verify", x509_cert_verify},
    {"validation-status", x509_cert_validation_status},
    {NULL, NULL},
};

static JanetMethod x509_crl_methods[] = {
    {"is-revoked", x509_crl_is_revoked},
    {NULL, NULL},
};

static JanetAbstractType *get_x509_cert_obj_type() {
    return &x509_cert_obj_type;
}

static JanetAbstractType *get_x509_crl_obj_type() {
    return &x509_crl_obj_type;
}

/* Abstract Object functions x509-cert */
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

/* Abstract Object functions x509-crl */
static int x509_crl_gc_fn(void *data, size_t len) {
    botan_x509_crl_obj_t *obj = (botan_x509_crl_obj_t *)data;

    int ret = botan_x509_crl_destroy(obj->x509_crl);
    JANET_BOTAN_ASSERT(ret);

    return 0;
}

static int x509_crl_get_fn(void *data, Janet key, Janet *out) {
    (void)data;
    if (!janet_checktype(key, JANET_KEYWORD)) {
        return 0;
    }

    return janet_getmethod(janet_unwrap_keyword(key), x509_crl_methods, out);
}

/* Janet functions x509-cert */
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
    const char *hash = janet_optcstring(argv, argc, 1, "SHA-256");

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

static Janet x509_cert_allowed_usage(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 2);

    botan_x509_cert_obj_t *obj = janet_getabstract(argv, 0, get_x509_cert_obj_type());
    botan_x509_cert_t cert = obj->x509_cert;
    JanetKeyword usage = janet_getkeyword(argv, 1);

    struct usage_key_pair {
        const char *usuage;
        unsigned int key;
    };
    static struct usage_key_pair pair_list[] = {
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
        if (janet_cstrcmp(usage, pair_list[i].usuage) == 0) {
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

static Janet x509_cert_verify(int32_t argc, Janet *argv) {
    janet_arity(argc, 1, 14);
    if ((argc & 1) == 0) {
        janet_panic("Invalid arguments number");
    }

    botan_x509_cert_obj_t *obj = janet_getabstract(argv, 0, get_x509_cert_obj_type());
    botan_x509_cert_t cert = obj->x509_cert;

    const char *trusted_path = NULL;
    size_t required_strength = 0;
    const char *hostname = NULL;
    uint64_t reference_time = 0;
    botan_x509_cert_t *intermediates = NULL;
    size_t intermediates_len = 0;
    botan_x509_cert_t *trusted = NULL;
    size_t trusted_len = 0;
    botan_x509_crl_t *crls = NULL;
    size_t crls_len = 0;

    for (int i=1; i<argc; i+=2) {
        if (!janet_checktype(argv[i], JANET_KEYWORD)) {
            janet_panicf("Argument #%d is not a keyword\n", i);
        }

        JanetKeyword keyword = janet_getkeyword(argv, i);
        if (!janet_cstrcmp(keyword, "intermediates")) {
            if (!janet_checktype(argv[i+1], JANET_TUPLE)) {
                janet_panic(":intermediates value is not a tuple");
            }

            JanetTuple tup = janet_gettuple(argv, i+1);
            int32_t tup_len = janet_tuple_length(tup);
            intermediates = janet_smalloc(sizeof(botan_x509_cert_obj_t) * tup_len);
            intermediates_len = tup_len;
            for (int j=0; j<tup_len; j++) {
                botan_x509_cert_obj_t *p = janet_getabstract(tup, j, get_x509_cert_obj_type());
                intermediates[j] = p->x509_cert;
            }

        } else if (!janet_cstrcmp(keyword, "trusted")) {
            if (!janet_checktype(argv[i+1], JANET_TUPLE)) {
                janet_panic(":trusted value is not a tuple");
            }

            JanetTuple tup = janet_gettuple(argv, i+1);
            int32_t tup_len = janet_tuple_length(tup);

            trusted = janet_smalloc(sizeof(botan_x509_cert_obj_t) * tup_len);
            trusted_len = tup_len;
            for (int j=0; j<tup_len; j++) {
                botan_x509_cert_obj_t *p = janet_getabstract(tup, j, get_x509_cert_obj_type());
                trusted[j] = p->x509_cert;
            }

        } else if (!janet_cstrcmp(keyword, "trusted-path")) {
            trusted_path = janet_getcstring(argv, i+1);

        } else if (!janet_cstrcmp(keyword, "required-strength")) {
            required_strength = janet_getsize(argv, i+1);

        } else if (!janet_cstrcmp(keyword, "hostname")) {
            hostname = janet_getcstring(argv, i+1);

        } else if (!janet_cstrcmp(keyword, "reference-time")) {
            reference_time = (uint64_t)janet_getnumber(argv, i+1);

        } else if (!janet_cstrcmp(keyword, "crls")) {
            if (!janet_checktype(argv[i+1], JANET_TUPLE)) {
                janet_panic(":crls value is not a tuple");
            }

            JanetTuple tup = janet_gettuple(argv, i+1);
            int32_t tup_len = janet_tuple_length(tup);

            crls = janet_smalloc(sizeof(botan_x509_cert_obj_t) * tup_len);
            crls_len = tup_len;
            for (int j=0; j<tup_len; j++) {
                botan_x509_crl_obj_t *p = janet_getabstract(tup, j, get_x509_crl_obj_type());
                crls[j] = p->x509_crl;
            }

        } else {
            janet_panicf("Argument #%d is not a valid keyword\n", i);
        }
    }

    int err_code = 0;
    int ret = botan_x509_cert_verify_with_crl(&err_code, cert,
                                              intermediates, intermediates_len,
                                              trusted, trusted_len,
                                              crls, crls_len,
                                              trusted_path,
                                              required_strength,
                                              hostname,
                                              reference_time);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_number((double)err_code);
}

static Janet x509_cert_validation_status(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 1);

    int code = janet_getinteger(argv, 0);

    const char *ret = botan_x509_cert_validation_status(code);

    return janet_wrap_string(janet_string((const uint8_t *)ret, strlen(ret)));
}

/* Janet functions x509-crl */
static Janet x509_crl_load(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 1);

    botan_x509_crl_obj_t *obj = janet_abstract(&x509_crl_obj_type, sizeof(botan_x509_crl_obj_t));
    memset(obj, 0, sizeof(botan_x509_crl_obj_t));

    JanetByteView crl = janet_getbytes(argv, 0);

    int ret = botan_x509_crl_load(&obj->x509_crl, crl.bytes, crl.len);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_abstract(obj);
}

static Janet x509_crl_load_file(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 1);

    botan_x509_crl_obj_t *obj = janet_abstract(&x509_crl_obj_type, sizeof(botan_x509_crl_obj_t));
    memset(obj, 0, sizeof(botan_x509_crl_obj_t));

    const char *filename = janet_getcstring(argv, 0);

    int ret = botan_x509_crl_load_file(&obj->x509_crl, filename);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_abstract(obj);
}

static Janet x509_crl_is_revoked(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 2);

    botan_x509_crl_obj_t *obj = janet_getabstract(argv, 0, get_x509_crl_obj_type());
    botan_x509_crl_t crl = obj->x509_crl;

    botan_x509_cert_obj_t *obj2 = janet_getabstract(argv, 1, get_x509_cert_obj_type());
    botan_x509_cert_t cert = obj2->x509_cert;

    int ret = botan_x509_is_revoked(crl, cert);
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
    {"x509-cert/hostname-match", x509_cert_hostname_match,
     "(x509-cert/hostname-match cert-obj hostname)\n\n"
     "Return true if the Common Name (CN) field of the certificate matches "
     "a given `hostname`."
    },
    {"x509-cert/hostname-match", x509_cert_hostname_match,
     "(x509-cert/hostname-match cert-obj hostname)\n\n"
     "Return true if the Common Name (CN) field of the certificate matches "
     "a given `hostname`."
    },
    {"x509-cert/allowed-usage", x509_cert_allowed_usage,
     "(x509-cert/allowed-usage cert-obj cert-usage)\n\n"
     "Test if the certificate is allowed for a particular usage. "
     "The cert-usage argument should be one of the following keywords:\n\n"
     "* :NO-CONSTRAINTS\n\n"
     "* :DIGITAL-SIGNATURE\n\n"
     "* :NON-REPUDIATION\n\n"
     "* :KEY-ENCIPHERMENT\n\n"
     "* :DATA-ENCIPHERMENT\n\n"
     "* :KEY-AGREEMENT\n\n"
     "* :KEY-CERT-SIGN\n\n"
     "* :CRL-SIGN\n\n"
     "* :ENCIPHER-ONLY\n\n"
     "* :DECIPHER-ONLY\n\n"
     "Returns true if the given X.509 certificate `cert-obj` is allowed for "
     "the specified cert-usage."
    },
    {"x509-cert/verify", x509_cert_verify,
     "(x509-cert/verify cert-obj &keys {:intermediates intermediates :trusted "
     "trusted :truste trusted-path :required-strength required-strength "
     ":hostname hostname :reference-time reference-time :crl crls})\n\n"
     "Verify a certificate. Returns 0 if validation was successful, returns a "
     " positive error code if the validation was unsuccesful.\n"
     "* `:intermediates` - A tuple of untrusted subauthorities.\n\n"
     "* `:trusted` - A tuple of trusted root CAs.\n\n"
     "* `:trusted-path` - A path refers to a directory where one or more "
     "trusted CA certificates are stored.\n\n"
     "* `:required-strength` - Indicates the minimum key and hash strength "
     "that is allowed. For instance setting to 80 allows 1024-bit RSA and "
     "SHA-1. Setting to 110 requires 2048-bit RSA and SHA-256 or higher. Set "
     "to zero to accept a default. Default value is 0, if omitted.\n\n"
     "* `:hostname` - Check against the certificates CN field.\n\n"
     "* `:reference-time` - Time value which the certificate chain is "
     "validated against. Use zero(default) to use the current system clock.\n\n"
     "* `crls` - A tuple of CRLs issued by either trusted or untrusted "
     "authorities."
    },
    {"x509-cert/validation-status", x509_cert_validation_status,
     "(x509-cert/validation-status error-code)\n\n"
     "Return an informative string explaining the verification return code."
    },

    {NULL, NULL, NULL}
};

static JanetReg x509_crl_cfuns[] = {
    {"x509-crl/load", x509_crl_load,
     "(x509-crl/load crl)\n\n"
     "Load a CRL from the DER or PEM representation."
    },
    {"x509-crl/load-file", x509_crl_load_file,
     "(x509-crl/load file-name)\n\n"
     "Load a CRL from a file."
    },
    {"x509-crl/is-revoked", x509_crl_is_revoked,
     "(x509-crl/load crl cert)\n\n"
     "Check whether a given `crl` contains a given `cert`. Return true when "
     "the certificate is revoked."
    },
    {NULL, NULL, NULL}
};


static void submod_x509_cert(JanetTable *env) {
    janet_cfuns(env, "botan", x509_cert_cfuns);
    janet_register_abstract_type(get_x509_cert_obj_type());
}

static void submod_x509_crl(JanetTable *env) {
    janet_cfuns(env, "botan", x509_crl_cfuns);
    janet_register_abstract_type(get_x509_crl_obj_type());
}

#endif /* BOTAN_X509_CERT_H */
