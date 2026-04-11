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

/* External C++ functions for x509 cert creation */
extern int jbotan_x509_crl_to_pem(
    botan_x509_crl_t crl, botan_view_ctx ctx, botan_view_str_fn view);
extern int jbotan_x509_crl_to_der(
    botan_x509_crl_t crl, botan_view_ctx ctx, botan_view_bin_fn view);
extern int jbotan_x509_cert_to_pem(
    botan_x509_cert_t cert, botan_view_ctx ctx, botan_view_str_fn view);
extern int jbotan_x509_cert_to_der(
    botan_x509_cert_t cert, botan_view_ctx ctx, botan_view_bin_fn view);
extern int jbotan_x509_create_self_signed(
    botan_x509_cert_t *cert_obj, botan_privkey_t key, botan_rng_t rng,
    const char *hash_fn, uint32_t expire_time, int is_ca,
    const char *cn, const char *country, const char *org, const char *org_unit,
    const char **more_org_units, size_t more_org_units_count,
    const char *locality, const char *state, const char *email,
    const char *dns, const char **more_dns, size_t more_dns_count,
    const char *ip, const char *uri, const char *serial_number,
    const unsigned int *constraints, size_t constraints_count,
    const char **ex_constraints, size_t ex_constraints_count);
extern int jbotan_x509_cert_issue(
    botan_x509_cert_t *cert_obj, botan_privkey_t subject_key,
    botan_x509_cert_t ca_cert, botan_privkey_t ca_key, botan_rng_t rng,
    const char *hash_fn, uint64_t not_before, uint64_t not_after, int is_ca,
    const char *cn, const char *country, const char *org, const char *org_unit,
    const char **more_org_units, size_t more_org_units_count,
    const char *locality, const char *state, const char *email,
    const char *dns, const char **more_dns, size_t more_dns_count,
    const char *ip, const char *uri, const char *serial_number,
    const unsigned int *constraints, size_t constraints_count,
    const char **ex_constraints, size_t ex_constraints_count);

/* Janet functions x509-cert */
static Janet x509_cert_create_self_signed(int32_t argc, Janet *argv);
static Janet x509_cert_issue(int32_t argc, Janet *argv);
static Janet x509_cert_to_pem(int32_t argc, Janet *argv);
static Janet x509_cert_to_der(int32_t argc, Janet *argv);
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
static Janet x509_cert_san(int32_t argc, Janet *argv);
static Janet x509_cert_issuer_dn(int32_t argc, Janet *argv);
static Janet x509_cert_is_ca(int32_t argc, Janet *argv);
static Janet x509_cert_hostname_match(int32_t argc, Janet *argv);
static Janet x509_cert_allowed_usage(int32_t argc, Janet *argv);
static Janet x509_cert_allowed_ext_usage(int32_t argc, Janet *argv);
static Janet x509_cert_verify(int32_t argc, Janet *argv);
static Janet x509_cert_validation_status(int32_t argc, Janet *argv);

/* Janet functions x509-crl */
static Janet x509_crl_create(int32_t argc, Janet *argv);
static Janet x509_crl_revoke(int32_t argc, Janet *argv);
static Janet x509_crl_verify(int32_t argc, Janet *argv);
static Janet x509_crl_to_pem(int32_t argc, Janet *argv);
static Janet x509_crl_to_der(int32_t argc, Janet *argv);
static Janet x509_crl_this_update(int32_t argc, Janet *argv);
static Janet x509_crl_next_update(int32_t argc, Janet *argv);
static Janet x509_crl_entries_count(int32_t argc, Janet *argv);
static Janet x509_crl_get_entry(int32_t argc, Janet *argv);
static Janet x509_crl_is_revoked(int32_t argc, Janet *argv);

/* Janet functions x509-crl-entry */
static Janet x509_crl_entry_create(int32_t argc, Janet *argv);
static Janet x509_crl_entry_reason(int32_t argc, Janet *argv);
static Janet x509_crl_entry_revocation_date(int32_t argc, Janet *argv);
static Janet x509_crl_entry_serial_number(int32_t argc, Janet *argv);

static JanetAbstractType x509_cert_obj_type = {
    "botan/x509_cert",
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
    "botan/x509_crl",
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
    "botan/x509_crl_entry",
    x509_crl_entry_gc_fn,
    NULL,
    x509_crl_entry_get_fn,
    JANET_ATEND_GET
};

static JanetMethod x509_cert_methods[] = {
    {"dup", x509_cert_dup},
    {"to-pem", x509_cert_to_pem},
    {"to-der", x509_cert_to_der},
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
    {"san", x509_cert_san},
    {"issuer-dn", x509_cert_issuer_dn},
    {"is-ca", x509_cert_is_ca},
    {"hostname-match", x509_cert_hostname_match},
    {"allowed-usage", x509_cert_allowed_usage},
    {"allowed-ext-usage", x509_cert_allowed_ext_usage},
    {"verify", x509_cert_verify},
    {"validation-status", x509_cert_validation_status},
    {NULL, NULL},
};

static JanetMethod x509_crl_entry_methods[] = {
    {"reason", x509_crl_entry_reason},
    {"revocation-date", x509_crl_entry_revocation_date},
    {"serial-number", x509_crl_entry_serial_number},
    {NULL, NULL},
};

static JanetMethod x509_crl_methods[] = {
    {"to-pem", x509_crl_to_pem},
    {"to-der", x509_crl_to_der},
    {"this-update", x509_crl_this_update},
    {"next-update", x509_crl_next_update},
    {"entries-count", x509_crl_entries_count},
    {"get-entry", x509_crl_get_entry},
    {"is-revoked", x509_crl_is_revoked},
    {"revoke", x509_crl_revoke},
    {"verify", x509_crl_verify},
    {NULL, NULL},
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

static const char *x509_general_name_type_str(unsigned int type) {
    switch (type) {
        case BOTAN_X509_EMAIL_ADDRESS:  return "Email";
        case BOTAN_X509_DNS_NAME:       return "DNS";
        case BOTAN_X509_URI:            return "URI";
        case BOTAN_X509_IP_ADDRESS:     return "IP";
        case BOTAN_X509_DIRECTORY_NAME: return "DirName";
        case BOTAN_X509_OTHER_NAME:     return "OtherName";
        default: return "Unknown";
    }
}

static void x509_cert_describe(botan_x509_cert_t cert, JanetBuffer *buffer) {
    view_data_t data;
    int ret = botan_x509_cert_view_as_string(cert, &data, (botan_view_str_fn)view_str_func);
    JANET_BOTAN_ASSERT(ret);

    janet_buffer_push_bytes(buffer, data.data, data.len);

    size_t san_count = 0;
    ret = botan_x509_cert_subject_alternative_names_count(cert, &san_count);
    if (ret == 0 && san_count > 0) {
        janet_formatb(buffer, "Subject Alternative Names:\n");
        for (size_t i = 0; i < san_count; i++) {
            botan_x509_general_name_t name = NULL;
            ret = botan_x509_cert_subject_alternative_names(cert, i, &name);
            if (ret != 0) continue;

            unsigned int type = 0;
            ret = botan_x509_general_name_get_type(name, &type);
            if (ret == 0) {
                view_data_t val;
                ret = botan_x509_general_name_view_string_value(name, &val, (botan_view_str_fn)view_str_func);
                if (ret == 0) {
                    janet_formatb(buffer, "  %s: %s\n",
                                  x509_general_name_type_str(type),
                                  janet_string(val.data, val.len));
                }
            }
            ret = botan_x509_general_name_destroy(name);
            JANET_BOTAN_ASSERT(ret);
        }
    }
}

static void x509_cert_tostring_fn(void *p, JanetBuffer *buffer) {
    botan_x509_cert_obj_t *obj = (botan_x509_cert_obj_t *)p;
    janet_buffer_push_u8(buffer, '\n');
    x509_cert_describe(obj->x509_cert, buffer);
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

static const char *x509_crl_reason_str(int code) {
    switch (code) {
        case 0:  return "Unspecified";
        case 1:  return "Key Compromise";
        case 2:  return "CA Compromise";
        case 3:  return "Affiliation Changed";
        case 4:  return "Superseded";
        case 5:  return "Cessation of Operation";
        case 6:  return "Certificate Hold";
        case 8:  return "Remove from CRL";
        case 9:  return "Privilege Withdrawn";
        case 10: return "AA Compromise";
        default: return "Unknown";
    }
}

static void x509_crl_format_time(uint64_t epoch, char *out, size_t out_len) {
    time_t t = (time_t)epoch;
    struct tm *tm_ptr = gmtime(&t);
    if (tm_ptr) {
        strftime(out, out_len, "%Y-%m-%d %H:%M:%S UTC", tm_ptr);
    } else {
        out[0] = '\0';
    }
}

static void x509_crl_format_hex_bytes(JanetBuffer *buffer, const uint8_t *bytes,
                                      size_t len, const char *indent,
                                      size_t bytes_per_line) {
    char hex[4];
    for (size_t i = 0; i < len; i++) {
        if (i % bytes_per_line == 0) {
            if (i > 0) janet_buffer_push_u8(buffer, '\n');
            janet_buffer_push_cstring(buffer, indent);
        } else {
            janet_buffer_push_u8(buffer, ':');
        }
        snprintf(hex, sizeof(hex), "%02x", bytes[i]);
        janet_buffer_push_cstring(buffer, hex);
    }
    janet_buffer_push_u8(buffer, '\n');
}

static void x509_crl_describe(botan_x509_crl_t crl, JanetBuffer *buffer) {
    char timebuf[32];
    char numbuf[32];
    char hex[4];
    int ret;
    int reason_code;
    uint64_t epoch;
    size_t count;
    view_data_t data;

    janet_buffer_push_cstring(buffer, "X.509 CRL\n");

    /* This Update */
    ret = botan_x509_crl_this_update(crl, &epoch);
    JANET_BOTAN_ASSERT(ret);

    x509_crl_format_time(epoch, timebuf, sizeof(timebuf));
    janet_formatb(buffer, "    This Update: %s\n", timebuf);

    /* Next Update (optional in spec) */
    ret = botan_x509_crl_next_update(crl, &epoch);
    if (ret == 0) {
        x509_crl_format_time(epoch, timebuf, sizeof(timebuf));
        janet_formatb(buffer, "    Next Update: %s\n", timebuf);
    }

    /* CRL Number (optional, big-endian integer) */
    ret = botan_x509_crl_view_binary_values(crl, BOTAN_X509_SERIAL_NUMBER, 0, &data,
                                            (botan_view_bin_fn)view_bin_func);
    if (ret == 0 && data.len > 0) {
        uint64_t n = 0;
        for (size_t i = 0; i < data.len && i < 8; i++) {
            n = (n << 8) | data.data[i];
        }
        snprintf(numbuf, sizeof(numbuf), "%llu", (unsigned long long)n);
        janet_buffer_push_cstring(buffer, "    CRL Number: ");
        janet_buffer_push_cstring(buffer, numbuf);
        janet_buffer_push_u8(buffer, '\n');
    }

    /* Authority Key Identifier (optional) */
    ret = botan_x509_crl_view_binary_values(crl, BOTAN_X509_AUTHORITY_KEY_IDENTIFIER, 0,
                                            &data, (botan_view_bin_fn)view_bin_func);
    if (ret == 0 && data.len > 0) {
        janet_buffer_push_cstring(buffer, "    Authority Key Identifier:\n");
        x509_crl_format_hex_bytes(buffer, data.data, data.len, "        ", 16);
    }

    /* Revoked Certificates */
    ret = botan_x509_crl_entries_count(crl, &count);
    JANET_BOTAN_ASSERT(ret);

    snprintf(numbuf, sizeof(numbuf), "%llu", (unsigned long long)count);
    janet_buffer_push_cstring(buffer, "Revoked Certificates: ");
    janet_buffer_push_cstring(buffer, numbuf);
    janet_buffer_push_u8(buffer, '\n');
    for (size_t i = 0; i < count; i++) {
        botan_x509_crl_entry_t entry = NULL;
        ret = botan_x509_crl_entries(crl, i, &entry);
        JANET_BOTAN_ASSERT(ret);

        ret = botan_x509_crl_entry_view_serial_number(entry, &data, (botan_view_bin_fn)view_bin_func);
        JANET_BOTAN_ASSERT(ret);

        janet_buffer_push_cstring(buffer, "    Serial Number: ");
        for (size_t j = 0; j < data.len; j++) {
            snprintf(hex, sizeof(hex), "%02x", data.data[j]);
            janet_buffer_push_cstring(buffer, hex);
        }
        janet_buffer_push_u8(buffer, '\n');

        ret = botan_x509_crl_entry_revocation_date(entry, &epoch);
        JANET_BOTAN_ASSERT(ret);

        x509_crl_format_time(epoch, timebuf, sizeof(timebuf));
        janet_formatb(buffer, "        Revocation Date: %s\n", timebuf);

        ret = botan_x509_crl_entry_reason(entry, &reason_code);
        JANET_BOTAN_ASSERT(ret);
        janet_formatb(buffer, "        Reason: %s\n", x509_crl_reason_str(reason_code));

        ret = botan_x509_crl_entry_destroy(entry);
        JANET_BOTAN_ASSERT(ret);
    }

    /* Signature */
    ret = botan_x509_crl_view_binary_values(crl, BOTAN_X509_SIGNATURE_BITS, 0, &data,
                                            (botan_view_bin_fn)view_bin_func);
    JANET_BOTAN_ASSERT(ret);

    janet_buffer_push_cstring(buffer, "Signature:\n");
    x509_crl_format_hex_bytes(buffer, data.data, data.len, "    ", 16);
}

static void x509_crl_tostring_fn(void *p, JanetBuffer *buffer) {
    botan_x509_crl_obj_t *obj = (botan_x509_crl_obj_t *)p;
    janet_buffer_push_u8(buffer, '\n');
    x509_crl_describe(obj->x509_crl, buffer);
}

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

struct key_usage_pair {
    const char *name;
    unsigned int value;
};

static struct key_usage_pair key_usage_table[] = {
    {"no-constraints",    0},
    {"digital-signature", 32768},
    {"non-repudiation",   16384},
    {"key-encipherment",  8192},
    {"data-encipherment", 4096},
    {"key-agreement",     2048},
    {"key-cert-sign",     1024},
    {"crl-sign",          512},
    {"encipher-only",     256},
    {"decipher-only",     128}
};
static const size_t key_usage_table_len = sizeof(key_usage_table)/sizeof(key_usage_table[0]);

static unsigned int key_usage_from_keyword(JanetKeyword kw) {
    for (size_t i = 0; i < key_usage_table_len; i++) {
        if (!janet_cstrcmp(kw, key_usage_table[i].name))
            return key_usage_table[i].value;
    }
    janet_panicf("unknown key-usage keyword :%s, expected one of: "
                 ":no-constraints, :digital-signature, :non-repudiation, "
                 ":key-encipherment, :data-encipherment, :key-agreement, "
                 ":key-cert-sign, :crl-sign, :encipher-only, :decipher-only", kw);
    return 0;
}

/* Janet functions x509-cert */
static Janet x509_cert_create_self_signed(int32_t argc, Janet *argv) {
    janet_arity(argc, 1, -1);

    botan_private_key_obj_t *key_obj = janet_getabstract(argv, 0, get_private_key_obj_type());

    botan_rng_t rng = 0;
    botan_rng_obj_t *rng_obj = NULL;
    const char *hash_fn = "SHA-256";
    uint32_t expire_time = 365 * 24 * 60 * 60;
    int is_ca = 0;
    int rng_created = 0;
    const char *cn = NULL;
    const char *country = NULL;
    const char *org = NULL;
    const char *org_unit = NULL;
    const char *locality = NULL;
    const char *state = NULL;
    const char *email = NULL;
    const char *dns = NULL;
    const char *ip = NULL;
    const char *uri = NULL;
    const char *serial_number = NULL;
    const char *more_org_units[32];
    size_t more_org_units_count = 0;
    const char *more_dns[32];
    size_t more_dns_count = 0;
    unsigned int constraints[16];
    size_t constraints_count = 0;
    const char *ex_constraints[16];
    size_t ex_constraints_count = 0;

    for (int i = 1; i < argc; i += 2) {
        JanetKeyword keyword = janet_getkeyword(argv, i);
        if (!janet_cstrcmp(keyword, "rng")) {
            rng_obj = janet_getabstract(argv, i + 1, get_rng_obj_type());
        } else if (!janet_cstrcmp(keyword, "hash")) {
            hash_fn = janet_getcstring(argv, i + 1);
        } else if (!janet_cstrcmp(keyword, "expire-time")) {
            expire_time = (uint32_t)janet_getinteger(argv, i + 1);
        } else if (!janet_cstrcmp(keyword, "is-ca")) {
            is_ca = janet_getboolean(argv, i + 1);
        } else if (!janet_cstrcmp(keyword, "CN")) {
            cn = janet_getcstring(argv, i + 1);
        } else if (!janet_cstrcmp(keyword, "C")) {
            country = janet_getcstring(argv, i + 1);
        } else if (!janet_cstrcmp(keyword, "O")) {
            org = janet_getcstring(argv, i + 1);
        } else if (!janet_cstrcmp(keyword, "OU")) {
            Janet val = argv[i + 1];
            if (janet_checktype(val, JANET_TUPLE) || janet_checktype(val, JANET_ARRAY)) {
                const Janet *items;
                int32_t len;
                janet_indexed_view(val, &items, &len);
                if (len > 0) {
                    org_unit = janet_getcstring(items, 0);
                    for (int32_t j = 1; j < len && more_org_units_count < 32; j++)
                        more_org_units[more_org_units_count++] = janet_getcstring(items, j);
                }
            } else {
                org_unit = janet_getcstring(argv, i + 1);
            }
        } else if (!janet_cstrcmp(keyword, "L")) {
            locality = janet_getcstring(argv, i + 1);
        } else if (!janet_cstrcmp(keyword, "ST")) {
            state = janet_getcstring(argv, i + 1);
        } else if (!janet_cstrcmp(keyword, "email")) {
            email = janet_getcstring(argv, i + 1);
        } else if (!janet_cstrcmp(keyword, "dns")) {
            Janet val = argv[i + 1];
            if (janet_checktype(val, JANET_TUPLE) || janet_checktype(val, JANET_ARRAY)) {
                const Janet *items;
                int32_t len;
                janet_indexed_view(val, &items, &len);
                if (len > 0) {
                    dns = janet_getcstring(items, 0);
                    for (int32_t j = 1; j < len && more_dns_count < 32; j++)
                        more_dns[more_dns_count++] = janet_getcstring(items, j);
                }
            } else {
                dns = janet_getcstring(argv, i + 1);
            }
        } else if (!janet_cstrcmp(keyword, "ip")) {
            ip = janet_getcstring(argv, i + 1);
        } else if (!janet_cstrcmp(keyword, "uri")) {
            uri = janet_getcstring(argv, i + 1);
        } else if (!janet_cstrcmp(keyword, "serial-number")) {
            serial_number = janet_getcstring(argv, i + 1);
        } else if (!janet_cstrcmp(keyword, "key-usage")) {
            Janet val = argv[i + 1];
            if (janet_checktype(val, JANET_TUPLE) || janet_checktype(val, JANET_ARRAY)) {
                const Janet *items;
                int32_t len;
                janet_indexed_view(val, &items, &len);
                for (int32_t j = 0; j < len && constraints_count < 16; j++)
                    constraints[constraints_count++] = key_usage_from_keyword(janet_getkeyword(items, j));
            } else {
                constraints[constraints_count++] = key_usage_from_keyword(janet_getkeyword(argv, i + 1));
            }
        } else if (!janet_cstrcmp(keyword, "ext-key-usage")) {
            Janet val = argv[i + 1];
            if (janet_checktype(val, JANET_TUPLE) || janet_checktype(val, JANET_ARRAY)) {
                const Janet *items;
                int32_t len;
                janet_indexed_view(val, &items, &len);
                for (int32_t j = 0; j < len && ex_constraints_count < 16; j++)
                    ex_constraints[ex_constraints_count++] = janet_getcstring(items, j);
            } else {
                ex_constraints[ex_constraints_count++] = janet_getcstring(argv, i + 1);
            }
        } else {
            janet_panicf("unknown keyword %v", argv[i]);
        }
    }

    if (rng_obj) {
        rng = rng_obj->rng;
    } else {
        int ret = botan_rng_init(&rng, "system");
        JANET_BOTAN_ASSERT(ret);
        rng_created = 1;
    }

    botan_x509_cert_obj_t *obj = janet_abstract(&x509_cert_obj_type, sizeof(botan_x509_cert_obj_t));
    memset(obj, 0, sizeof(botan_x509_cert_obj_t));

    int ret = jbotan_x509_create_self_signed(
        &obj->x509_cert, key_obj->private_key, rng,
        hash_fn, expire_time, is_ca,
        cn, country, org, org_unit,
        more_org_units, more_org_units_count,
        locality, state, email, dns,
        more_dns, more_dns_count,
        ip, uri, serial_number,
        constraints, constraints_count,
        ex_constraints, ex_constraints_count);

    if (rng_created) botan_rng_destroy(rng);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_abstract(obj);
}

static Janet x509_cert_issue(int32_t argc, Janet *argv) {
    janet_arity(argc, 5, -1);

    botan_private_key_obj_t *subject_key_obj = janet_getabstract(argv, 0, get_private_key_obj_type());
    botan_x509_cert_obj_t *ca_cert_obj = janet_getabstract(argv, 1, get_x509_cert_obj_type());
    botan_private_key_obj_t *ca_key_obj = janet_getabstract(argv, 2, get_private_key_obj_type());
    uint64_t not_before = (uint64_t)janet_getinteger64(argv, 3);
    uint64_t not_after = (uint64_t)janet_getinteger64(argv, 4);

    botan_rng_t rng = 0;
    botan_rng_obj_t *rng_obj = NULL;
    const char *hash_fn = "SHA-256";
    int is_ca = 0;
    int rng_created = 0;
    const char *cn = NULL;
    const char *country = NULL;
    const char *org = NULL;
    const char *org_unit = NULL;
    const char *locality = NULL;
    const char *state = NULL;
    const char *email = NULL;
    const char *dns = NULL;
    const char *ip = NULL;
    const char *uri = NULL;
    const char *serial_number = NULL;
    const char *more_org_units[32];
    size_t more_org_units_count = 0;
    const char *more_dns[32];
    size_t more_dns_count = 0;
    unsigned int constraints[16];
    size_t constraints_count = 0;
    const char *ex_constraints[16];
    size_t ex_constraints_count = 0;

    for (int i = 5; i < argc; i += 2) {
        JanetKeyword keyword = janet_getkeyword(argv, i);
        if (!janet_cstrcmp(keyword, "rng")) {
            rng_obj = janet_getabstract(argv, i + 1, get_rng_obj_type());
        } else if (!janet_cstrcmp(keyword, "hash")) {
            hash_fn = janet_getcstring(argv, i + 1);
        } else if (!janet_cstrcmp(keyword, "is-ca")) {
            is_ca = janet_getboolean(argv, i + 1);
        } else if (!janet_cstrcmp(keyword, "CN")) {
            cn = janet_getcstring(argv, i + 1);
        } else if (!janet_cstrcmp(keyword, "C")) {
            country = janet_getcstring(argv, i + 1);
        } else if (!janet_cstrcmp(keyword, "O")) {
            org = janet_getcstring(argv, i + 1);
        } else if (!janet_cstrcmp(keyword, "OU")) {
            Janet val = argv[i + 1];
            if (janet_checktype(val, JANET_TUPLE) || janet_checktype(val, JANET_ARRAY)) {
                const Janet *items;
                int32_t len;
                janet_indexed_view(val, &items, &len);
                if (len > 0) {
                    org_unit = janet_getcstring(items, 0);
                    for (int32_t j = 1; j < len && more_org_units_count < 32; j++)
                        more_org_units[more_org_units_count++] = janet_getcstring(items, j);
                }
            } else {
                org_unit = janet_getcstring(argv, i + 1);
            }
        } else if (!janet_cstrcmp(keyword, "L")) {
            locality = janet_getcstring(argv, i + 1);
        } else if (!janet_cstrcmp(keyword, "ST")) {
            state = janet_getcstring(argv, i + 1);
        } else if (!janet_cstrcmp(keyword, "email")) {
            email = janet_getcstring(argv, i + 1);
        } else if (!janet_cstrcmp(keyword, "dns")) {
            Janet val = argv[i + 1];
            if (janet_checktype(val, JANET_TUPLE) || janet_checktype(val, JANET_ARRAY)) {
                const Janet *items;
                int32_t len;
                janet_indexed_view(val, &items, &len);
                if (len > 0) {
                    dns = janet_getcstring(items, 0);
                    for (int32_t j = 1; j < len && more_dns_count < 32; j++)
                        more_dns[more_dns_count++] = janet_getcstring(items, j);
                }
            } else {
                dns = janet_getcstring(argv, i + 1);
            }
        } else if (!janet_cstrcmp(keyword, "ip")) {
            ip = janet_getcstring(argv, i + 1);
        } else if (!janet_cstrcmp(keyword, "uri")) {
            uri = janet_getcstring(argv, i + 1);
        } else if (!janet_cstrcmp(keyword, "serial-number")) {
            serial_number = janet_getcstring(argv, i + 1);
        } else if (!janet_cstrcmp(keyword, "key-usage")) {
            Janet val = argv[i + 1];
            if (janet_checktype(val, JANET_TUPLE) || janet_checktype(val, JANET_ARRAY)) {
                const Janet *items;
                int32_t len;
                janet_indexed_view(val, &items, &len);
                for (int32_t j = 0; j < len && constraints_count < 16; j++)
                    constraints[constraints_count++] = key_usage_from_keyword(janet_getkeyword(items, j));
            } else {
                constraints[constraints_count++] = key_usage_from_keyword(janet_getkeyword(argv, i + 1));
            }
        } else if (!janet_cstrcmp(keyword, "ext-key-usage")) {
            Janet val = argv[i + 1];
            if (janet_checktype(val, JANET_TUPLE) || janet_checktype(val, JANET_ARRAY)) {
                const Janet *items;
                int32_t len;
                janet_indexed_view(val, &items, &len);
                for (int32_t j = 0; j < len && ex_constraints_count < 16; j++)
                    ex_constraints[ex_constraints_count++] = janet_getcstring(items, j);
            } else {
                ex_constraints[ex_constraints_count++] = janet_getcstring(argv, i + 1);
            }
        } else {
            janet_panicf("unknown keyword %v", argv[i]);
        }
    }

    if (rng_obj) {
        rng = rng_obj->rng;
    } else {
        int ret = botan_rng_init(&rng, "system");
        JANET_BOTAN_ASSERT(ret);
        rng_created = 1;
    }

    botan_x509_cert_obj_t *obj = janet_abstract(&x509_cert_obj_type, sizeof(botan_x509_cert_obj_t));
    memset(obj, 0, sizeof(botan_x509_cert_obj_t));

    int ret = jbotan_x509_cert_issue(
        &obj->x509_cert, subject_key_obj->private_key,
        ca_cert_obj->x509_cert, ca_key_obj->private_key,
        rng, hash_fn, not_before, not_after, is_ca,
        cn, country, org, org_unit,
        more_org_units, more_org_units_count,
        locality, state, email, dns,
        more_dns, more_dns_count,
        ip, uri, serial_number,
        constraints, constraints_count,
        ex_constraints, ex_constraints_count);

    if (rng_created) botan_rng_destroy(rng);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_abstract(obj);
}

static Janet x509_cert_to_pem(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 1);

    botan_x509_cert_obj_t *obj = janet_getabstract(argv, 0, get_x509_cert_obj_type());
    botan_x509_cert_t cert = obj->x509_cert;

    view_data_t data;
    int ret = jbotan_x509_cert_to_pem(cert, &data, (botan_view_str_fn)view_str_func);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_string(janet_string(data.data, data.len));
}

static Janet x509_cert_to_der(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 1);

    botan_x509_cert_obj_t *obj = janet_getabstract(argv, 0, get_x509_cert_obj_type());
    botan_x509_cert_t cert = obj->x509_cert;

    view_data_t data;
    int ret = jbotan_x509_cert_to_der(cert, &data, (botan_view_bin_fn)view_bin_func);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_string(janet_string(data.data, data.len));
}

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
    janet_fixarity(argc, 1);

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

    JanetBuffer *buffer = janet_buffer(1024);
    x509_cert_describe(obj->x509_cert, buffer);

    return janet_wrap_string(janet_string(buffer->data, buffer->count));
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

    if (out_len > 0 && out->data[out_len - 1] == 0) {
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

static const char *x509_dn_key_from_keyword(JanetKeyword kw) {
    if (!janet_cstrcmp(kw, "CN")) return "CN";
    if (!janet_cstrcmp(kw, "C"))  return "C";
    if (!janet_cstrcmp(kw, "O"))  return "O";
    if (!janet_cstrcmp(kw, "OU")) return "OU";
    if (!janet_cstrcmp(kw, "ST")) return "ST";
    if (!janet_cstrcmp(kw, "L"))  return "L";
    if (!janet_cstrcmp(kw, "serial-number")) return "SerialNumber";
    return NULL;
}

static Janet x509_cert_get_dn_one(botan_x509_cert_t cert, const char *key, size_t index,
    int (*get_fn)(botan_x509_cert_t, const char *, size_t, uint8_t *, size_t *)) {
    size_t out_len = 0;

    int ret = get_fn(cert, key, index, NULL, &out_len);
    if (ret != BOTAN_FFI_ERROR_INSUFFICIENT_BUFFER_SPACE) {
        JANET_BOTAN_ASSERT(ret);
    }

    JanetBuffer *out = janet_buffer(out_len);
    ret = get_fn(cert, key, index, out->data, &out_len);
    JANET_BOTAN_ASSERT(ret);

    if (out_len > 0 && out->data[out_len - 1] == 0) {
        out_len -= 1;
    }

    return janet_wrap_string(janet_string(out->data, out_len));
}

static Janet x509_cert_get_dn_all(botan_x509_cert_t cert, const char *key,
    int (*get_fn)(botan_x509_cert_t, const char *, size_t, uint8_t *, size_t *)) {
    JanetArray *arr = janet_array(4);
    for (size_t i = 0; ; i++) {
        size_t out_len = 0;
        int ret = get_fn(cert, key, i, NULL, &out_len);
        if (ret != BOTAN_FFI_ERROR_INSUFFICIENT_BUFFER_SPACE) break;

        JanetBuffer *out = janet_buffer(out_len);
        ret = get_fn(cert, key, i, out->data, &out_len);
        if (ret != 0) break;

        if (out_len > 0 && out->data[out_len - 1] == 0) out_len -= 1;
        janet_array_push(arr, janet_wrap_string(janet_string(out->data, out_len)));
    }
    return janet_wrap_tuple(janet_tuple_n(arr->data, arr->count));
}

static Janet x509_cert_subject_dn(int32_t argc, Janet *argv) {
    janet_arity(argc, 2, 3);

    botan_x509_cert_obj_t *obj = janet_getabstract(argv, 0, get_x509_cert_obj_type());
    JanetKeyword kw = janet_getkeyword(argv, 1);

    const char *key = x509_dn_key_from_keyword(kw);
    if (!key) janet_panicf("unknown DN keyword :%s, expected one of: :CN, :C, :O, :OU, :ST, :L, :serial-number", kw);

    if (argc == 3) {
        size_t index = janet_getsize(argv, 2);
        return x509_cert_get_dn_one(obj->x509_cert, key, index, botan_x509_cert_get_subject_dn);
    }
    return x509_cert_get_dn_all(obj->x509_cert, key, botan_x509_cert_get_subject_dn);
}

static Janet x509_cert_issuer_dn(int32_t argc, Janet *argv) {
    janet_arity(argc, 2, 3);

    botan_x509_cert_obj_t *obj = janet_getabstract(argv, 0, get_x509_cert_obj_type());
    JanetKeyword kw = janet_getkeyword(argv, 1);

    const char *key = x509_dn_key_from_keyword(kw);
    if (!key) janet_panicf("unknown DN keyword :%s, expected one of: :CN, :C, :O, :OU, :ST, :L, :serial-number", kw);

    if (argc == 3) {
        size_t index = janet_getsize(argv, 2);
        return x509_cert_get_dn_one(obj->x509_cert, key, index, botan_x509_cert_get_issuer_dn);
    }
    return x509_cert_get_dn_all(obj->x509_cert, key, botan_x509_cert_get_issuer_dn);
}

static unsigned int x509_san_type_from_keyword(JanetKeyword kw) {
    if (!janet_cstrcmp(kw, "dns"))   return BOTAN_X509_DNS_NAME;
    if (!janet_cstrcmp(kw, "email")) return BOTAN_X509_EMAIL_ADDRESS;
    if (!janet_cstrcmp(kw, "uri"))   return BOTAN_X509_URI;
    if (!janet_cstrcmp(kw, "ip"))    return BOTAN_X509_IP_ADDRESS;
    return (unsigned int)-1;
}

static Janet x509_cert_san(int32_t argc, Janet *argv) {
    janet_arity(argc, 2, 3);

    botan_x509_cert_obj_t *obj = janet_getabstract(argv, 0, get_x509_cert_obj_type());
    botan_x509_cert_t cert = obj->x509_cert;
    JanetKeyword kw = janet_getkeyword(argv, 1);
    int has_index = (argc == 3);
    size_t target_index = has_index ? janet_getsize(argv, 2) : 0;

    unsigned int target_type = x509_san_type_from_keyword(kw);
    if (target_type == (unsigned int)-1) {
        janet_panicf("unknown SAN keyword :%s, expected one of: :dns, :email, :uri, :ip", kw);
    }

    size_t san_count = 0;
    int ret = botan_x509_cert_subject_alternative_names_count(cert, &san_count);
    if (ret != 0) {
        return has_index ? janet_wrap_nil() : janet_wrap_tuple(janet_tuple_n(NULL, 0));
    }

    JanetArray *arr = has_index ? NULL : janet_array(4);
    size_t match_index = 0;
    for (size_t i = 0; i < san_count; i++) {
        botan_x509_general_name_t name = NULL;
        ret = botan_x509_cert_subject_alternative_names(cert, i, &name);
        if (ret != 0) continue;

        unsigned int type = 0;
        ret = botan_x509_general_name_get_type(name, &type);
        if (ret == 0 && type == target_type) {
            view_data_t val;
            ret = botan_x509_general_name_view_string_value(name, &val, (botan_view_str_fn)view_str_func);
            if (ret == 0) {
                Janet str = janet_wrap_string(janet_string(val.data, val.len));
                if (has_index) {
                    if (match_index == target_index) {
                        ret = botan_x509_general_name_destroy(name);
                        JANET_BOTAN_ASSERT(ret);
                        return str;
                    }
                } else {
                    janet_array_push(arr, str);
                }
            }
            match_index++;
        }
        ret = botan_x509_general_name_destroy(name);
        JANET_BOTAN_ASSERT(ret);
    }

    if (has_index) return janet_wrap_nil();
    return janet_wrap_tuple(janet_tuple_n(arr->data, arr->count));
}

static Janet x509_cert_is_ca(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 1);

    botan_x509_cert_obj_t *obj = janet_getabstract(argv, 0, get_x509_cert_obj_type());
    botan_x509_cert_t cert = obj->x509_cert;

    int ret = botan_x509_cert_is_ca(cert);
    if (ret != 0 && ret != 1) {
        JANET_BOTAN_ASSERT(ret);
    }

    return janet_wrap_boolean(ret == 1);
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
    unsigned int key = key_usage_from_keyword(usage);

    int ret = botan_x509_cert_allowed_usage(cert, key);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_boolean(ret == 0);
}

static Janet x509_cert_allowed_ext_usage(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 2);

    botan_x509_cert_obj_t *obj = janet_getabstract(argv, 0, get_x509_cert_obj_type());
    botan_x509_cert_t cert = obj->x509_cert;
    const char *oid = janet_getcstring(argv, 1);

    int ret = botan_x509_cert_allowed_extended_usage_str(cert, oid);
    if (ret != 0 && ret != 1) {
        JANET_BOTAN_ASSERT(ret);
    }

    return janet_wrap_boolean(ret == 1);
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
    if (ret != 0 && ret != 1) {
        JANET_BOTAN_ASSERT(ret);
    }

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

static Janet x509_crl_to_pem(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 1);

    botan_x509_crl_obj_t *obj = janet_getabstract(argv, 0, get_x509_crl_obj_type());
    botan_x509_crl_t crl = obj->x509_crl;

    view_data_t data;
    int ret = jbotan_x509_crl_to_pem(crl, &data, (botan_view_str_fn)view_str_func);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_string(janet_string(data.data, data.len));
}

static Janet x509_crl_to_der(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 1);

    botan_x509_crl_obj_t *obj = janet_getabstract(argv, 0, get_x509_crl_obj_type());
    botan_x509_crl_t crl = obj->x509_crl;

    view_data_t data;
    int ret = jbotan_x509_crl_to_der(crl, &data, (botan_view_bin_fn)view_bin_func);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_string(janet_string(data.data, data.len));
}

static Janet x509_crl_this_update(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 1);

    botan_x509_crl_obj_t *obj = janet_getabstract(argv, 0, get_x509_crl_obj_type());
    botan_x509_crl_t crl = obj->x509_crl;

    uint64_t time_since_epoch;
    int ret = botan_x509_crl_this_update(crl, &time_since_epoch);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_number((double)time_since_epoch);
}

static Janet x509_crl_next_update(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 1);

    botan_x509_crl_obj_t *obj = janet_getabstract(argv, 0, get_x509_crl_obj_type());
    botan_x509_crl_t crl = obj->x509_crl;

    uint64_t time_since_epoch;
    int ret = botan_x509_crl_next_update(crl, &time_since_epoch);
    if (ret == BOTAN_FFI_ERROR_NO_VALUE) {
        return janet_wrap_nil();
    }

    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_number((double)time_since_epoch);
}

static Janet x509_crl_entries_count(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 1);

    botan_x509_crl_obj_t *obj = janet_getabstract(argv, 0, get_x509_crl_obj_type());
    botan_x509_crl_t crl = obj->x509_crl;

    size_t count;
    int ret = botan_x509_crl_entries_count(crl, &count);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_number((double)count);
}

static Janet x509_crl_get_entry(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 2);

    botan_x509_crl_obj_t *obj = janet_getabstract(argv, 0, get_x509_crl_obj_type());
    botan_x509_crl_t crl = obj->x509_crl;
    size_t index = janet_getsize(argv, 1);

    botan_x509_crl_entry_obj_t *entry_obj = janet_abstract(&x509_crl_entry_obj_type, sizeof(botan_x509_crl_entry_obj_t));
    memset(entry_obj, 0, sizeof(botan_x509_crl_entry_obj_t));

    int ret = botan_x509_crl_entries(crl, index, &entry_obj->entry);
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

static Janet x509_crl_is_revoked(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 2);

    botan_x509_crl_obj_t *obj = janet_getabstract(argv, 0, get_x509_crl_obj_type());
    botan_x509_crl_t crl = obj->x509_crl;

    botan_x509_cert_obj_t *obj2 = janet_getabstract(argv, 1, get_x509_cert_obj_type());
    botan_x509_cert_t cert = obj2->x509_cert;

    int ret = botan_x509_is_revoked(crl, cert);
    /* ret: 0 = revoked, -1 = not revoked */
    if (ret != 0 && ret != -1) {
        JANET_BOTAN_ASSERT(ret);
    }

    return janet_wrap_boolean(ret == 0);
}

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

static Janet x509_crl_create(int32_t argc, Janet *argv) {
    janet_arity(argc, 4, -1);

    botan_x509_cert_obj_t *ca_cert_obj = janet_getabstract(argv, 0, get_x509_cert_obj_type());
    botan_private_key_obj_t *ca_key_obj = janet_getabstract(argv, 1, get_private_key_obj_type());
    uint64_t issue_time = (uint64_t)janet_getnumber(argv, 2);
    uint32_t next_update = (uint32_t)janet_getnumber(argv, 3);

    botan_rng_t rng = 0;
    botan_rng_obj_t *rng_obj = NULL;
    const char *hash_fn = NULL;
    const char *padding = NULL;
    int rng_created = 0;

    for (int i = 4; i < argc; i += 2) {
        JanetKeyword keyword = janet_getkeyword(argv, i);
        if (!janet_cstrcmp(keyword, "rng")) {
            rng_obj = janet_getabstract(argv, i + 1, get_rng_obj_type());
        } else if (!janet_cstrcmp(keyword, "hash")) {
            hash_fn = janet_getcstring(argv, i + 1);
        } else if (!janet_cstrcmp(keyword, "padding")) {
            padding = janet_getcstring(argv, i + 1);
        } else {
            janet_panicf("unknown keyword :%s", keyword);
        }
    }

    if (rng_obj) {
        rng = rng_obj->rng;
    } else {
        int ret = botan_rng_init(&rng, "system");
        JANET_BOTAN_ASSERT(ret);
        rng_created = 1;
    }

    botan_x509_crl_obj_t *obj = janet_abstract(&x509_crl_obj_type, sizeof(botan_x509_crl_obj_t));
    memset(obj, 0, sizeof(botan_x509_crl_obj_t));

    int ret = botan_x509_crl_create(&obj->x509_crl, rng,
                                    ca_cert_obj->x509_cert, ca_key_obj->private_key,
                                    issue_time, next_update,
                                    hash_fn, padding);

    if (rng_created) botan_rng_destroy(rng);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_abstract(obj);
}

static Janet x509_crl_revoke(int32_t argc, Janet *argv) {
    janet_arity(argc, 6, -1);

    botan_x509_crl_obj_t *crl_obj = janet_getabstract(argv, 0, get_x509_crl_obj_type());
    botan_x509_cert_obj_t *ca_cert_obj = janet_getabstract(argv, 1, get_x509_cert_obj_type());
    botan_private_key_obj_t *ca_key_obj = janet_getabstract(argv, 2, get_private_key_obj_type());
    uint64_t issue_time = (uint64_t)janet_getnumber(argv, 3);
    uint32_t next_update = (uint32_t)janet_getnumber(argv, 4);

    /* entries: tuple of crl-entry objects */
    JanetView entries = janet_getindexed(argv, 5);

    botan_rng_t rng = 0;
    botan_rng_obj_t *rng_obj = NULL;
    const char *hash_fn = NULL;
    const char *padding = NULL;
    int rng_created = 0;

    for (int i = 6; i < argc; i += 2) {
        JanetKeyword keyword = janet_getkeyword(argv, i);
        if (!janet_cstrcmp(keyword, "rng")) {
            rng_obj = janet_getabstract(argv, i + 1, get_rng_obj_type());
        } else if (!janet_cstrcmp(keyword, "hash")) {
            hash_fn = janet_getcstring(argv, i + 1);
        } else if (!janet_cstrcmp(keyword, "padding")) {
            padding = janet_getcstring(argv, i + 1);
        } else {
            janet_panicf("unknown keyword :%s", keyword);
        }
    }

    botan_x509_crl_entry_t *entry_arr = janet_smalloc(sizeof(botan_x509_crl_entry_t) * entries.len);
    for (int32_t j = 0; j < entries.len; j++) {
        botan_x509_crl_entry_obj_t *e = janet_getabstract(entries.items, j, get_x509_crl_entry_obj_type());
        entry_arr[j] = e->entry;
    }

    if (rng_obj) {
        rng = rng_obj->rng;
    } else {
        int ret = botan_rng_init(&rng, "system");
        JANET_BOTAN_ASSERT(ret);
        rng_created = 1;
    }

    botan_x509_crl_obj_t *obj = janet_abstract(&x509_crl_obj_type, sizeof(botan_x509_crl_obj_t));
    memset(obj, 0, sizeof(botan_x509_crl_obj_t));

    int ret = botan_x509_crl_update(&obj->x509_crl, crl_obj->x509_crl, rng,
                                    ca_cert_obj->x509_cert, ca_key_obj->private_key,
                                    issue_time, next_update,
                                    entry_arr, (size_t)entries.len,
                                    hash_fn, padding);

    janet_sfree(entry_arr);
    if (rng_created) botan_rng_destroy(rng);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_abstract(obj);
}

static Janet x509_crl_verify(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 2);

    botan_x509_crl_obj_t *obj = janet_getabstract(argv, 0, get_x509_crl_obj_type());
    botan_public_key_obj_t *key_obj = janet_getabstract(argv, 1, get_public_key_obj_type());

    int ret = botan_x509_crl_verify_signature(obj->x509_crl, key_obj->public_key);
    if (ret != 0 && ret != 1) {
        JANET_BOTAN_ASSERT(ret);
    }

    return janet_wrap_boolean(ret == 1);
}

static JanetReg x509_cert_cfuns[] = {
    {"x509-cert/create-self-signed", x509_cert_create_self_signed,
     "(x509-cert/create-self-signed key &keys {:rng rng :hash hash "
     ":expire-time expire-time :is-ca is-ca "
     ":CN cn :C c :O o :OU ou :ST st :L l "
     ":email email :dns dns :ip ip :uri uri :serial-number serial-number "
     ":key-usage key-usage :ext-key-usage ext-key-usage})\n\n"
     "Create a self-signed X.509 certificate.\n\n"
     "* `key` - A private key object.\n\n"
     "* `:rng` - A random number generator object. "
     "Default is system RNG.\n\n"
     "* `:hash` - Hash algorithm name, e.g. \"SHA-256\". "
     "Default is \"SHA-256\".\n\n"
     "* `:expire-time` - Expiration time in seconds from now. "
     "Default is 365 days.\n\n"
     "* `:is-ca` - If true, mark certificate as a CA certificate. "
     "Default is false.\n\n"
     "* `:CN` - Common Name.\n\n"
     "* `:C` - Country.\n\n"
     "* `:O` - Organization.\n\n"
     "* `:OU` - Organizational Unit. "
     "Can be a tuple/array of strings for multiple values.\n\n"
     "* `:ST` - State or Province.\n\n"
     "* `:L` - Locality.\n\n"
     "* `:email` - Email address.\n\n"
     "* `:dns` - DNS name for Subject Alternative Name. "
     "Can be a tuple/array of strings for multiple values.\n\n"
     "* `:ip` - IP address for Subject Alternative Name.\n\n"
     "* `:uri` - URI for Subject Alternative Name.\n\n"
     "* `:serial-number` - Serial number field of the DN.\n\n"
     "* `:key-usage` - KeyUsage constraint. A keyword or tuple/array of keywords. "
     "Possible values: :digital-signature, :non-repudiation, :key-encipherment, "
     ":data-encipherment, :key-agreement, :key-cert-sign, :crl-sign, "
     ":encipher-only, :decipher-only.\n\n"
     "* `:ext-key-usage` - ExtendedKeyUsage constraint. A string or tuple/array of strings. "
     "e.g. \"PKIX.ServerAuth\", \"PKIX.ClientAuth\", \"PKIX.CodeSigning\", "
     "\"PKIX.EmailProtection\", \"PKIX.TimeStamping\", \"PKIX.OCSPSigning\"."
    },
    {"x509-cert/issue", x509_cert_issue,
     "(x509-cert/issue subject-key ca-cert ca-key "
     "not-before not-after &keys {:rng rng :hash hash "
     ":is-ca is-ca :CN cn :C c :O o :OU ou :ST st :L l "
     ":email email :dns dns :ip ip :uri uri :serial-number serial-number "
     ":key-usage key-usage :ext-key-usage ext-key-usage})\n\n"
     "Issue a new X.509 certificate signed by a CA.\n\n"
     "* `subject-key` - The subject's private key object.\n\n"
     "* `ca-cert` - The CA's certificate object.\n\n"
     "* `ca-key` - The CA's private key object.\n\n"
     "* `not-before` - Certificate validity start time, as seconds "
     "since epoch.\n\n"
     "* `not-after` - Certificate validity end time, as seconds "
     "since epoch.\n\n"
     "* `:rng` - A random number generator object. "
     "Default is system RNG.\n\n"
     "* `:hash` - Hash algorithm name, e.g. \"SHA-256\". "
     "Default is \"SHA-256\".\n\n"
     "* `:is-ca` - If true, mark certificate as a CA certificate. "
     "Default is false.\n\n"
     "* `:CN` - Common Name.\n\n"
     "* `:C` - Country.\n\n"
     "* `:O` - Organization.\n\n"
     "* `:OU` - Organizational Unit. "
     "Can be a tuple/array of strings for multiple values.\n\n"
     "* `:ST` - State or Province.\n\n"
     "* `:L` - Locality.\n\n"
     "* `:email` - Email address.\n\n"
     "* `:dns` - DNS name for Subject Alternative Name. "
     "Can be a tuple/array of strings for multiple values.\n\n"
     "* `:ip` - IP address for Subject Alternative Name.\n\n"
     "* `:uri` - URI for Subject Alternative Name.\n\n"
     "* `:serial-number` - Serial number field of the DN.\n\n"
     "* `:key-usage` - KeyUsage constraint. A keyword or tuple/array of keywords. "
     "Possible values: :digital-signature, :non-repudiation, :key-encipherment, "
     ":data-encipherment, :key-agreement, :key-cert-sign, :crl-sign, "
     ":encipher-only, :decipher-only.\n\n"
     "* `:ext-key-usage` - ExtendedKeyUsage constraint. A string or tuple/array of strings. "
     "e.g. \"PKIX.ServerAuth\", \"PKIX.ClientAuth\", \"PKIX.CodeSigning\", "
     "\"PKIX.EmailProtection\", \"PKIX.TimeStamping\", \"PKIX.OCSPSigning\"."
    },
    {"x509-cert/to-pem", x509_cert_to_pem,
     "(x509-cert/to-pem cert)\n\n"
     "Encode the certificate as a PEM string."
    },
    {"x509-cert/to-der", x509_cert_to_der,
     "(x509-cert/to-der cert)\n\n"
     "Encode the certificate as DER binary data."
    },
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
     "(x509-cert/subject-dn cert-obj key &opt index)\n\n"
     "Get a value from the subject DN field. "
     "`key` is one of :CN, :C, :O, :OU, :ST, :L, :serial-number. "
     "If `index` is given, returns the value at that zero-based index. "
     "If omitted, returns a tuple of all values for that field."
    },
    {"x509-cert/issuer-dn", x509_cert_issuer_dn,
     "(x509-cert/issuer-dn cert-obj key &opt index)\n\n"
     "Get a value from the issuer DN field. "
     "`key` is one of :CN, :C, :O, :OU, :ST, :L, :serial-number. "
     "If `index` is given, returns the value at that zero-based index. "
     "If omitted, returns a tuple of all values for that field."
    },
    {"x509-cert/san", x509_cert_san,
     "(x509-cert/san cert-obj type &opt index)\n\n"
     "Get a value from the Subject Alternative Name extension. "
     "`type` is one of :dns, :email, :uri, :ip. "
     "If `index` is given, returns the value at that zero-based index "
     "(nil if not found). "
     "If omitted, returns a tuple of all values for that type."
    },
    {"x509-cert/is-ca", x509_cert_is_ca,
     "(x509-cert/is-ca cert-obj)\n\n"
     "Return true if the certificate is a CA certificate."
    },
    {"x509-cert/hostname-match", x509_cert_hostname_match,
     "(x509-cert/hostname-match cert-obj hostname)\n\n"
     "Return true if the certificate matches a given `hostname`. "
     "If SAN DNS entries are present, only those are checked. "
     "Otherwise falls back to Common Name (CN). Supports wildcard matching."
    },
    {"x509-cert/allowed-ext-usage", x509_cert_allowed_ext_usage,
     "(x509-cert/allowed-ext-usage cert-obj oid)\n\n"
     "Check if the certificate allows the specified extended usage OID. "
     "The `oid` parameter can be either a canonical OID string or identifiers "
     "like \"PKIX.ServerAuth\", \"PKIX.ClientAuth\", \"PKIX.CodeSigning\", "
     "\"PKIX.OCSPSigning\". Returns true if the certificate allows the usage."
    },
    {"x509-cert/allowed-usage", x509_cert_allowed_usage,
     "(x509-cert/allowed-usage cert-obj cert-usage)\n\n"
     "Test if the certificate is allowed for a particular usage. "
     "The cert-usage argument should be one of the following keywords:\n\n"
     "* :no-constraints\n\n"
     "* :digital-signature\n\n"
     "* :non-repudiation\n\n"
     "* :key-encipherment\n\n"
     "* :data-encipherment\n\n"
     "* :key-agreement\n\n"
     "* :key-cert-sign\n\n"
     "* :crl-sign\n\n"
     "* :encipher-only\n\n"
     "* :decipher-only\n\n"
     "Returns true if the given X.509 certificate `cert-obj` is allowed for "
     "the specified cert-usage."
    },
    {"x509-cert/verify", x509_cert_verify,
     "(x509-cert/verify cert-obj &keys {:intermediates intermediates :trusted "
     "trusted :truste trusted-path :required-strength required-strength "
     ":hostname hostname :reference-time reference-time :crl crls})\n\n"
     "Verify a certificate. Returns 0 if validation was successful, returns a "
     " positive error code if the validation was unsuccesful.\n\n"
     "* :intermediates - A tuple of untrusted subauthorities.\n\n"
     "* :trusted - A tuple of trusted root CAs.\n\n"
     "* :trusted-path - A path refers to a directory where one or more "
     "trusted CA certificates are stored.\n\n"
     "* :required-strength - Indicates the minimum key and hash strength "
     "that is allowed. For instance setting to 80 allows 1024-bit RSA and "
     "SHA-1. Setting to 110 requires 2048-bit RSA and SHA-256 or higher. Set "
     "to zero to accept a default. Default value is 0, if omitted.\n\n"
     "* :hostname - Check against the certificates CN field.\n\n"
     "* :reference-time - Time value which the certificate chain is "
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
    {"x509-crl/to-pem", x509_crl_to_pem,
     "(x509-crl/to-pem crl)\n\n"
     "Encode the CRL as a PEM string."
    },
    {"x509-crl/to-der", x509_crl_to_der,
     "(x509-crl/to-der crl)\n\n"
     "Encode the CRL as DER binary data."
    },
    {"x509-crl/load", x509_crl_load,
     "(x509-crl/load crl)\n\n"
     "Load a CRL from the DER or PEM representation."
    },
    {"x509-crl/load-file", x509_crl_load_file,
     "(x509-crl/load file-name)\n\n"
     "Load a CRL from a file."
    },
    {"x509-crl/this-update", x509_crl_this_update,
     "(x509-crl/this-update crl-obj)\n\n"
     "Return the time the CRL was issued, as seconds since epoch."
    },
    {"x509-crl/next-update", x509_crl_next_update,
     "(x509-crl/next-update crl-obj)\n\n"
     "Return the time the next CRL update is expected, as seconds since epoch. "
     "Return `nil` if the CRL has no nextUpdate field, which is optional."
    },
    {"x509-crl/entries-count", x509_crl_entries_count,
     "(x509-crl/entries-count crl-obj)\n\n"
     "Return the number of entries in the CRL."
    },
    {"x509-crl/get-entry", x509_crl_get_entry,
     "(x509-crl/get-entry crl-obj index)\n\n"
     "Return the CRL entry at the given `index`. Use `x509-crl/entries-count` "
     "to get the number of entries."
    },
    {"x509-crl/is-revoked", x509_crl_is_revoked,
     "(x509-crl/is-revoked crl cert)\n\n"
     "Check if the given `cert` is revoked on the given `crl`. "
     "Return true when the certificate is revoked."
    },
    {"x509-crl/create", x509_crl_create,
     "(x509-crl/create ca-cert ca-key issue-time next-update "
     "&keys {:rng rng :hash hash :padding padding})\n\n"
     "Create a new empty CRL signed by the given CA.\n\n"
     "* `ca-cert` - The CA certificate object.\n\n"
     "* `ca-key` - The CA's private key object.\n\n"
     "* `issue-time` - The time when the CRL becomes valid, as seconds "
     "since epoch.\n\n"
     "* `next-update` - The number of seconds after issue-time until the "
     "CRL expires.\n\n"
     "* `:rng` - A random number generator object. Default is system RNG.\n\n"
     "* `:hash` - Hash algorithm name. Default is \"SHA-256\".\n\n"
     "* `:padding` - Padding scheme. Default depends on key type: "
     "\"PKCS1v15\" for RSA, hash name for DSA/ECDSA, \"Pure\" for Ed25519/Ed448."
    },
    {"x509-crl/revoke", x509_crl_revoke,
     "(x509-crl/revoke crl ca-cert ca-key issue-time next-update entries "
     "&keys {:rng rng :hash hash :padding padding})\n\n"
     "Update a CRL with new revoked entries, creating a new CRL. "
     "The original CRL is not modified.\n\n"
     "* `crl` - The existing CRL to update.\n\n"
     "* `ca-cert` - The CA certificate object.\n\n"
     "* `ca-key` - The CA's private key object.\n\n"
     "* `issue-time` - The time when the new CRL becomes valid, as seconds "
     "since epoch.\n\n"
     "* `next-update` - The number of seconds after issue-time until the "
     "CRL expires.\n\n"
     "* `entries` - A tuple/array of CRL entry objects created with "
     "`x509-crl-entry/create`.\n\n"
     "* `:rng` - A random number generator object. Default is system RNG.\n\n"
     "* `:hash` - Hash algorithm name. Default is \"SHA-256\".\n\n"
     "* `:padding` - Padding scheme. Default depends on key type: "
     "\"PKCS1v15\" for RSA, hash name for DSA/ECDSA, \"Pure\" for Ed25519/Ed448."
    },
    {"x509-crl/verify", x509_crl_verify,
     "(x509-crl/verify crl pubkey)\n\n"
     "Verify the CRL signature against the given public key. "
     "Returns true if the signature is valid."
    },
    {NULL, NULL, NULL}
};

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

static void submod_x509_cert(JanetTable *env) {
    janet_cfuns(env, "botan", x509_cert_cfuns);
    janet_register_abstract_type(get_x509_cert_obj_type());
}

static void submod_x509_crl(JanetTable *env) {
    janet_cfuns(env, "botan", x509_crl_cfuns);
    janet_cfuns(env, "botan", x509_crl_entry_cfuns);
    janet_register_abstract_type(get_x509_crl_obj_type());
    janet_register_abstract_type(get_x509_crl_entry_obj_type());
}

#endif /* BOTAN_X509_CERT_H */
