/*
 * Copyright (c) 2024, Janet-botan Seungki Kim
 *
 * Janet-botan is released under the MIT License, see the LICENSE file.
 */

#ifndef BOTAN_X509_CRL_H
#define BOTAN_X509_CRL_H

typedef struct botan_x509_crl_obj {
    botan_x509_crl_t x509_crl;
} botan_x509_crl_obj_t;

/* Abstract Object functions */
static int x509_crl_gc_fn(void *data, size_t len);
static int x509_crl_get_fn(void *data, Janet key, Janet *out);

/* Janet functions */
static Janet x509_crl_is_revoked(int32_t argc, Janet *argv);

static JanetAbstractType x509_crl_obj_type = {
    "botan/x509_crl",
    x509_crl_gc_fn,
    NULL,
    x509_crl_get_fn,
    JANET_ATEND_GET
};

static JanetMethod x509_crl_methods[] = {
    {"is-revoked", x509_crl_is_revoked},
    {NULL, NULL},
};

static JanetAbstractType *get_x509_crl_obj_type() {
    return &x509_crl_obj_type;
}

/* Abstract Object functions */
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

/* Janet functions */
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

static void submod_x509_crl(JanetTable *env) {
    janet_cfuns(env, "botan", x509_crl_cfuns);
    janet_register_abstract_type(get_x509_crl_obj_type());
}

#endif /* BOTAN_X509_CRL_H */
