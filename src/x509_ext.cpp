/*
 * Copyright (c) 2026, Janet-botan Seungki Kim
 *
 * Janet-botan is released under the MIT License, see the LICENSE file.
 */

#include <botan/x509self.h>
#include <botan/x509_ca.h>
#include <botan/x509_crl.h>
#include <botan/pem.h>
#include <botan/internal/ffi_util.h>
#include <botan/internal/ffi_cert.h>
#include <botan/internal/ffi_pkey.h>
#include <botan/internal/ffi_rng.h>

using namespace Botan_FFI;

extern "C" {

int jbotan_x509_create_self_signed(botan_x509_cert_t* cert_obj,
                                   botan_privkey_t key,
                                   botan_rng_t rng,
                                   const char* hash_fn,
                                   uint32_t expire_time,
                                   int is_ca,
                                   const char* cn,
                                   const char* country,
                                   const char* org,
                                   const char* org_unit,
                                   const char* locality,
                                   const char* state,
                                   const char* email,
                                   const char* dns,
                                   const char* uri,
                                   const char* serial_number) {
    if(Botan::any_null_pointers(cert_obj))
        return BOTAN_FFI_ERROR_NULL_POINTER;

    return ffi_guard_thunk(__func__, [=]() -> int {
        Botan::X509_Cert_Options opts("", expire_time);
        if(is_ca) opts.CA_key();
        if(cn) opts.common_name = cn;
        if(country) opts.country = country;
        if(org) opts.organization = org;
        if(org_unit) opts.org_unit = org_unit;
        if(locality) opts.locality = locality;
        if(state) opts.state = state;
        if(email) opts.email = email;
        if(dns) opts.dns = dns;
        if(uri) opts.uri = uri;
        if(serial_number) opts.serial_number = serial_number;

        auto cert = std::make_unique<Botan::X509_Certificate>(
            Botan::X509::create_self_signed_cert(
                opts, safe_get(key),
                hash_fn ? hash_fn : "SHA-256",
                safe_get(rng)));

        return ffi_new_object(cert_obj, std::move(cert));
    });
}

int jbotan_x509_cert_issue(botan_x509_cert_t* cert_obj,
                           botan_privkey_t subject_key,
                           botan_x509_cert_t ca_cert,
                           botan_privkey_t ca_key,
                           botan_rng_t rng,
                           const char* hash_fn,
                           uint64_t not_before,
                           uint64_t not_after,
                           int is_ca,
                           const char* cn,
                           const char* country,
                           const char* org,
                           const char* org_unit,
                           const char* locality,
                           const char* state,
                           const char* email,
                           const char* dns,
                           const char* uri,
                           const char* serial_number) {
    if(Botan::any_null_pointers(cert_obj))
        return BOTAN_FFI_ERROR_NULL_POINTER;

    return ffi_guard_thunk(__func__, [=]() -> int {
        Botan::X509_Cert_Options opts("");
        if(is_ca) opts.CA_key();
        if(cn) opts.common_name = cn;
        if(country) opts.country = country;
        if(org) opts.organization = org;
        if(org_unit) opts.org_unit = org_unit;
        if(locality) opts.locality = locality;
        if(state) opts.state = state;
        if(email) opts.email = email;
        if(dns) opts.dns = dns;
        if(uri) opts.uri = uri;
        if(serial_number) opts.serial_number = serial_number;

        auto req = Botan::X509::create_cert_req(
            opts, safe_get(subject_key),
            hash_fn ? hash_fn : "SHA-256",
            safe_get(rng));

        auto ca = Botan::X509_CA(
            safe_get(ca_cert), safe_get(ca_key),
            hash_fn ? hash_fn : "SHA-256", "",
            safe_get(rng));

        auto cert = std::make_unique<Botan::X509_Certificate>(
            ca.sign_request(req, safe_get(rng),
                            Botan::X509_Time(std::chrono::system_clock::from_time_t(not_before)),
                            Botan::X509_Time(std::chrono::system_clock::from_time_t(not_after))));

        return ffi_new_object(cert_obj, std::move(cert));
    });
}

int jbotan_x509_cert_to_pem(botan_x509_cert_t cert,
                            botan_view_ctx ctx,
                            botan_view_str_fn view) {
    return ffi_guard_thunk(__func__, [=]() -> int {
        auto der = safe_get(cert).BER_encode();
        auto pem = Botan::PEM_Code::encode(der, "CERTIFICATE");
        return view(ctx, pem.data(), pem.size());
    });
}

int jbotan_x509_cert_to_der(botan_x509_cert_t cert,
                            botan_view_ctx ctx,
                            botan_view_bin_fn view) {
    return ffi_guard_thunk(__func__, [=]() -> int {
        auto der = safe_get(cert).BER_encode();
        return view(ctx, der.data(), der.size());
    });
}

int jbotan_x509_crl_to_pem(botan_x509_crl_t crl,
                           botan_view_ctx ctx,
                           botan_view_str_fn view) {
    return ffi_guard_thunk(__func__, [=]() -> int {
        auto der = safe_get(crl).BER_encode();
        auto pem = Botan::PEM_Code::encode(der, "X509 CRL");
        return view(ctx, pem.data(), pem.size());
    });
}

int jbotan_x509_crl_to_der(botan_x509_crl_t crl,
                           botan_view_ctx ctx,
                           botan_view_bin_fn view) {
    return ffi_guard_thunk(__func__, [=]() -> int {
        auto der = safe_get(crl).BER_encode();
        return view(ctx, der.data(), der.size());
    });
}

} // extern "C"
