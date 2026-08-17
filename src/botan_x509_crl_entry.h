/*
 * Copyright (c) 2026, Janet-botan Seungki Kim
 *
 * Janet-botan is released under the MIT License, see the LICENSE file.
 */

#ifndef BOTAN_X509_CRL_ENTRY_H
#define BOTAN_X509_CRL_ENTRY_H

/* Janet functions x509-crl-entry */
static Janet x509_crl_entry_create(int32_t argc, Janet *argv);
static Janet x509_crl_entry_reason(int32_t argc, Janet *argv);
static Janet x509_crl_entry_revocation_date(int32_t argc, Janet *argv);
static Janet x509_crl_entry_serial_number(int32_t argc, Janet *argv);

static JanetMethod x509_crl_entry_methods[] = {
    {"reason", x509_crl_entry_reason},
    {"revocation-date", x509_crl_entry_revocation_date},
    {"serial-number", x509_crl_entry_serial_number},
    {NULL, NULL},
};

/* Abstract Object functions x509-crl-entry */
static int x509_crl_entry_gc_fn(void *data, size_t len) {
    botan_x509_crl_entry_obj_t *obj = (botan_x509_crl_entry_obj_t *)data;

    int ret = botan_x509_crl_entry_destroy(obj->entry);
    JANET_BOTAN_ASSERT(ret);

    return 0;
}

static int x509_crl_entry_get_fn(void *data, Janet key, Janet *out) {
    (void)data;
    if (!janet_checktype(key, JANET_KEYWORD)) {
        return 0;
    }

    return janet_getmethod(janet_unwrap_keyword(key), x509_crl_entry_methods, out);
}

struct crl_reason_pair {
    const char *name;
    int value;
};

static struct crl_reason_pair crl_reason_table[] = {
    {"unspecified",            0},
    {"key-compromise",         1},
    {"ca-compromise",          2},
    {"affiliation-changed",    3},
    {"superseded",             4},
    {"cessation-of-operation", 5},
    {"certificate-hold",       6},
    {"remove-from-crl",        8},
    {"privilege-withdrawn",    9},
    {"aa-compromise",          10}
};
static const size_t crl_reason_table_len = sizeof(crl_reason_table)/sizeof(crl_reason_table[0]);

static int crl_reason_from_janet(Janet val) {
    if (janet_checktype(val, JANET_NUMBER)) {
        return (int)janet_unwrap_number(val);
    }
    if (janet_checktype(val, JANET_KEYWORD)) {
        JanetKeyword kw = janet_unwrap_keyword(val);
        for (size_t i = 0; i < crl_reason_table_len; i++) {
            if (!janet_cstrcmp(kw, crl_reason_table[i].name))
                return crl_reason_table[i].value;
        }
        janet_panicf("unknown CRL reason keyword :%s, expected one of: "
                     ":unspecified, :key-compromise, :ca-compromise, "
                     ":affiliation-changed, :superseded, :cessation-of-operation, "
                     ":certificate-hold, :remove-from-crl, :privilege-withdrawn, "
                     ":aa-compromise", kw);
    }
    janet_panic("CRL reason must be a keyword or integer");
    return 0;
}

/* Janet functions x509-crl-entry */
static Janet x509_crl_entry_create(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 2);

    botan_x509_cert_obj_t *cert_obj = janet_getabstract(argv, 0, get_x509_cert_obj_type());
    int reason_code = crl_reason_from_janet(argv[1]);

    botan_x509_crl_entry_obj_t *entry_obj = janet_abstract(&x509_crl_entry_obj_type, sizeof(botan_x509_crl_entry_obj_t));
    memset(entry_obj, 0, sizeof(botan_x509_crl_entry_obj_t));

    int ret = botan_x509_crl_entry_create(&entry_obj->entry, cert_obj->x509_cert, reason_code);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_abstract(entry_obj);
}

static Janet x509_crl_entry_reason(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 1);

    botan_x509_crl_entry_obj_t *obj = janet_getabstract(argv, 0, get_x509_crl_entry_obj_type());
    int reason_code;

    int ret = botan_x509_crl_entry_reason(obj->entry, &reason_code);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_number((double)reason_code);
}

static Janet x509_crl_entry_revocation_date(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 1);

    botan_x509_crl_entry_obj_t *obj = janet_getabstract(argv, 0, get_x509_crl_entry_obj_type());
    uint64_t time_since_epoch;

    int ret = botan_x509_crl_entry_revocation_date(obj->entry, &time_since_epoch);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_number((double)time_since_epoch);
}

static Janet x509_crl_entry_serial_number(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 1);

    botan_x509_crl_entry_obj_t *obj = janet_getabstract(argv, 0, get_x509_crl_entry_obj_type());

    view_data_t data;
    int ret = botan_x509_crl_entry_view_serial_number(obj->entry, &data, (botan_view_bin_fn)view_bin_func);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_string(janet_string(data.data, data.len));
}

static JanetReg x509_crl_entry_cfuns[] = {
    {"x509-crl-entry/create", x509_crl_entry_create,
     "(x509-crl-entry/create cert reason)\n\n"
     "Create a CRL entry for the given certificate with a revocation reason.\n\n"
     "* `cert` - The certificate to mark as revoked.\n\n"
     "* `reason` - The revocation reason, either an integer or a keyword:\n\n"
     "  0: :unspecified\n\n"
     "  1: :key-compromise\n\n"
     "  2: :ca-compromise\n\n"
     "  3: :affiliation-changed\n\n"
     "  4: :superseded\n\n"
     "  5: :cessation-of-operation\n\n"
     "  6: :certificate-hold\n\n"
     "  8: :remove-from-crl\n\n"
     "  9: :privilege-withdrawn\n\n"
     "  10: :aa-compromise"
    },
    {"x509-crl-entry/reason", x509_crl_entry_reason,
     "(x509-crl-entry/reason crl-entry)\n\n"
     "Return the revocation reason code for the CRL entry.\n\n"
     "0: Unspecified\n\n"
     "1: Key Compromise\n\n"
     "2: CA Compromise\n\n"
     "3: Affiliation Changed\n\n"
     "4: Superseded\n\n"
     "5: Cessation of Operation\n\n"
     "6: Certificate Hold\n\n"
     "8: Remove from CRL\n\n"
     "9: Privilege Withdrawn\n\n"
     "10: AA Compromise"
    },
    {"x509-crl-entry/revocation-date", x509_crl_entry_revocation_date,
     "(x509-crl-entry/revocation-date crl-entry)\n\n"
     "Return the revocation date as seconds since epoch."
    },
    {"x509-crl-entry/serial-number", x509_crl_entry_serial_number,
     "(x509-crl-entry/serial-number crl-entry)\n\n"
     "Return the serial number of the revoked certificate."
    },
    {NULL, NULL, NULL}
};

static void submod_x509_crl_entry(JanetTable *env) {
    janet_cfuns(env, "botan", x509_crl_entry_cfuns);
    janet_register_abstract_type(get_x509_crl_entry_obj_type());
}

#endif /* BOTAN_X509_CRL_ENTRY_H */
