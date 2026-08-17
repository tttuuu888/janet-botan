/*
 * Copyright (c) 2026, Janet-botan Seungki Kim
 *
 * Janet-botan is released under the MIT License, see the LICENSE file.
 */

#ifndef BOTAN_X509_COMMON_H
#define BOTAN_X509_COMMON_H

typedef struct botan_x509_cert_obj {
    botan_x509_cert_t x509_cert;
} botan_x509_cert_obj_t;

typedef struct botan_x509_crl_obj {
    botan_x509_crl_t x509_crl;
} botan_x509_crl_obj_t;

typedef struct botan_x509_crl_entry_obj {
    botan_x509_crl_entry_t entry;
} botan_x509_crl_entry_obj_t;

/* Abstract Object functions x509-cert */
static int x509_cert_gc_fn(void *data, size_t len);
static int x509_cert_get_fn(void *data, Janet key, Janet *out);
static void x509_cert_tostring_fn(void *p, JanetBuffer *buffer);

/* Abstract Object functions x509-crl */
static int x509_crl_gc_fn(void *data, size_t len);
static int x509_crl_get_fn(void *data, Janet key, Janet *out);
static void x509_crl_tostring_fn(void *p, JanetBuffer *buffer);

/* Abstract Object functions x509-crl-entry */
static int x509_crl_entry_gc_fn(void *data, size_t len);
static int x509_crl_entry_get_fn(void *data, Janet key, Janet *out);

static JanetAbstractType x509_cert_obj_type = {
    "botan/x509-cert",
    x509_cert_gc_fn,
    NULL,
    x509_cert_get_fn,
    NULL,                       /* put */
    NULL,                       /* marshal */
    NULL,                       /* unmarshal */
    x509_cert_tostring_fn,
    JANET_ATEND_TOSTRING
};

static JanetAbstractType x509_crl_obj_type = {
    "botan/x509-crl",
    x509_crl_gc_fn,
    NULL,
    x509_crl_get_fn,
    NULL,                       /* put */
    NULL,                       /* marshal */
    NULL,                       /* unmarshal */
    x509_crl_tostring_fn,
    JANET_ATEND_TOSTRING
};

static JanetAbstractType x509_crl_entry_obj_type = {
    "botan/x509-crl-entry",
    x509_crl_entry_gc_fn,
    NULL,
    x509_crl_entry_get_fn,
    JANET_ATEND_GET
};

static JanetAbstractType *get_x509_cert_obj_type() {
    return &x509_cert_obj_type;
}

static JanetAbstractType *get_x509_crl_obj_type() {
    return &x509_crl_obj_type;
}

static JanetAbstractType *get_x509_crl_entry_obj_type() {
    return &x509_crl_entry_obj_type;
}

#endif /* BOTAN_X509_COMMON_H */
