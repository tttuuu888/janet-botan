(use ../build/botan)
(use spork/test)

(start-suite "X509 Certificate")

(def crl-pem `-----BEGIN X509 CRL-----
MIIC9zCB4AIBATANBgkqhkiG9w0BAQUFADCBhzELMAkGA1UEBhMCS1IxDjAMBgNV
BAgMBVNlb3VsMQ4wDAYDVQQHDAVTZW91bDEQMA4GA1UECgwHZXhhbXBsZTEQMA4G
A1UECwwHZXhhbXBsZTEQMA4GA1UEAwwHZXhhbXBsZTEiMCAGCSqGSIb3DQEJARYT
ZXhhbXBsZUBleGFtcGxlLmNvbRcNMjQwNDA2MTI0NzE3WhcNMjUwMzI4MTI0NzE3
WjAUMBICAQEXDTI0MDQwNjEyNDUzNlqgDjAMMAoGA1UdFAQDAgEDMA0GCSqGSIb3
DQEBBQUAA4ICAQBzIhR2xoUrqd2nmChhrYzHED/upcrVUvxWW+LmZu/Z9VqwssYA
4IIFxXq7oDrEdcgjP2/GXvrwZ5w6UZG7uk2D0X1WW/RESLq3R/sQo1PAvZ0lcrtW
SPdExBvVTh5rwicM+0ALp33tI5ws7CDA636tuqD1EZIBK6oGlR3NYKciCUKAv8P+
ZSAKr0/nVUEdUTs+LRQ9eTyNx6KG0UrRFnmAifjBVQf2OBoDDGXLp66clHeYRVkB
1mjzvYC+WzOfc2iLqdIdZq3NK95hdqVIy5OFsZ1qKVHmoTYV6m9qdtj/UvtWG6FN
oQWFpbM9b/gFzIZVv4QH9ilUkty+3lXAUYwRUE+GRH9ozZRQ0L9BUa4NTb+F5Ze9
gwsJeWeH14TWDgOZ6Gz0Jm4gg51NBePPoz03S50O+OnVVQCmS85gbFN231rvZjDx
4muCAx2lQL4UE1Lj/68tb7OFkasfkq830PLwXbCTpCxScMsJ95Usvt/B9GnfJVid
M0lOLR1AK6lFbAp2jyaX1R9gS4lRggWtJshN9fZ7oUHGIt1sFxsSlq07Ml1znXX/
s6u015qE5DkUGQ/O6mUZb/KRpVT0KOrV66Amh3OMOZrzfU4M5qove+/WnzX9YyXb
hFmGar762fRi4y+DxZLebYCGbzY2CT/y+BtzjUixjzsmfxAKTyj7bma5CA==
-----END X509 CRL-----`)

(def cert-pem2 `-----BEGIN CERTIFICATE-----
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
knl2gdOvpiIRf3P4HjNPPYgDiqE=
-----END CERTIFICATE-----`)

# From IPAddrBlocksUnsorted.pem
(def ip-addr-blocks-unsorted-pem `-----BEGIN CERTIFICATE-----
MIICqzCCAmKgAwIBAgIRANPort9DlhqMt2QI6bFLA+IwCgYIKoZIzj0EAwIwSTEQ
MA4GA1UEAxMHVGVzdCBDQTELMAkGA1UEBhMCVVMxFjAUBgNVBAoTDUJvdGFuIFBy
b2plY3QxEDAOBgNVBAsTB1Rlc3RpbmcwHhcNMjUwNjE0MTkxNjEzWhcNMjYwNjE0
MTkxNjEzWjBJMRAwDgYDVQQDEwdUZXN0IENBMQswCQYDVQQGEwJVUzEWMBQGA1UE
ChMNQm90YW4gUHJvamVjdDEQMA4GA1UECxMHVGVzdGluZzBJMBMGByqGSM49AgEG
CCqGSM49AwEBAzIABN0stcHCSpEww/+tZrO2Uv36ZJmjLel058Rdr5tdShPCNEmy
MeXB+cGQ1kWVMh+sp6OCATkwggE1MHMGCCsGAQUFBwEHBGcwZTAHBAMAAgEFADAZ
BAIAAjATAxEA/////////////////////zAHBAMAAQIFADAVBAMAAQEwDjAMAwMD
wKgDBQHAqAIAMBcEAwABATAQMA4DBQHAqAICAwUAyAAAADAGBAIAAQUAMCEGA1Ud
DgQaBBgub8YveBEYQ3Q3XbeiHtrh38tnkuzOOtQwDgYDVR0PAQH/BAQDAgGGMFIG
A1UdEQRLMEmBFXRlc3RpbmdAcmFuZG9tYml0Lm5ldIITYm90YW4ucmFuZG9tYml0
Lm5ldIYbaHR0cHM6Ly9ib3Rhbi5yYW5kb21iaXQubmV0MBIGA1UdEwEB/wQIMAYB
Af8CAQEwIwYDVR0jBBwwGoAYLm/GL3gRGEN0N123oh7a4d/LZ5LszjrUMAoGCCqG
SM49BAMCAzcAMDQCGF6Idq8d0ibVHxOTBA7xzFrquTz7crUfBAIYMNxljBJPw+CX
VaIdhfLji2fOE9P8vx9O
-----END CERTIFICATE-----`)

# From IPAddrBlocksAll.pem
(def ip-addr-blocks-all-pem `-----BEGIN CERTIFICATE-----
MIID2TCCAsGgAwIBAgIIDCV8W/5Tqq8wDQYJKoZIhvcNAQELBQAwYTENMAsGA1UE
AxMEWk9SQjELMAkGA1UEBhMCREUxDTALBgNVBAgTBFRodXIxEzARBgNVBAoTClRV
IElsbWVuYXUxHzAdBgNVBAsTFlRlbGVtYXRpay9SZWNobmVybmV0emUwHhcNMjQx
MDAyMTIxMDM4WhcNMjcxMDAyMTIxMDM4WjBhMQ0wCwYDVQQDEwRaT1JCMQswCQYD
VQQGEwJERTENMAsGA1UECBMEVGh1cjETMBEGA1UEChMKVFUgSWxtZW5hdTEfMB0G
A1UECxMWVGVsZW1hdGlrL1JlY2huZXJuZXR6ZTCCASIwDQYJKoZIhvcNAQEBBQAD
ggEPADCCAQoCggEBAKS8eqobCYN9/Gj41lEVvYxkBBj0tWTVKCavNRPtAPpATsbO
hGEDO0Cvt2WZZMBTjXdiCjJkdy8aHfsg4SDOK9GUlxCAR7jL1XfFeHE2Q2CWBM8J
NDk+Kx7Nxj1TBY//rTf2gPiu/CDMQPpihTH0kGUw+dR2zybjj0d3h1nQAiVWaauf
A+QZ1qcgpXpSp9r0Jds+GzCW9119oglPVMgbQGR8ExO9/gU3VS15MowZ+lonGCa7
KSd8rO+rUbDvdZ3Gu3C00yR8Dsft4/1YqSYtdeKD87AdGu3wkx62Ia4lwarjWYwE
mmbOzEXddy/rM7eFEgCIPecxk/8eMb3MxB1Y2tsCAwEAAaOBlDCBkTCBjgYIKwYB
BQUHAQcEgYEwfzAmBAIAATAgAwQHwKgAAwMBwagwDAMDA8KoAwUAw68BAgMFAMSo
AAEwVQQCAAIwTwMKB/qAAAAAAAAAAAMGA/4gAAAAAxEAIAMAAGgpNDUEIBDFAAAA
xDAmAxEAqwEAAAAAAAAAAAAAAAAAAQMRAM0CAAAAAAAAAAAAAAAAAAIwDQYJKoZI
hvcNAQELBQADggEBAA1vysHUycl6/ij2b6pXlvei4Qni1laHGJT/8b2YW2Q3U0uc
V4WMy+nKR9/IDpFc03kZW9ihe7zbbJcoINaKq3UTfEeMcLbzDSzFFaKUANv/C2vx
sUihUo1ojle4EmmVYyYXeiZiu+46aUzuUJuWddTs4kJdNUxFkTKMmhdiGSosGKvz
wRqXj5pG1iEQZmZYDWrricVFkGuwcbAbWTtQqh+cSTt+1sKi4FwL6kkCH9kG5D+1
/zugVwhXRgguSmqMixpNowMmiDJggzIruGGeJc3ubKuvAnRJmW4VZCXXbVDNAPXi
HDOjomC4OO17uOrWnLht/oiJ+VUhjkFtorO2RLY=
-----END CERTIFICATE-----`)

# From ASNumberCert.pem
(def as-number-cert-pem `-----BEGIN CERTIFICATE-----
MIIBqDCCAU6gAwIBAgIRALPImt78hhfZi1Y9pXp9uPkwCgYIKoZIzj0EAwIwADAe
Fw0yNDEwMjExNDQ1MTBaFw0yNTEwMjExNDQ1MTBaMAAwWTATBgcqhkjOPQIBBggq
hkjOPQMBBwNCAAQYLa6kWGm3hE1ug3BVUaui+Ui013pu/ZTeCKYU++tQEjGydJyO
UCzFDjuMZgu76+iaGWfa0PlN2pPFoIQoJduAo4GoMIGlME0GCCsGAQUFBwEIAQH/
BD4wPKAbMBkwBwIBAAICA+cCAhOyMAoCAQACBQD/////oR0wGzAIAgIE0gICFi4C
AwCAADAKAgEAAgUA/////zAhBgNVHQ4EGgQYGz6Wu2X5h8+j64aiGIj9ts4i+J6R
lBMHMAwGA1UdEwEB/wQCMAAwIwYDVR0jBBwwGoAYGz6Wu2X5h8+j64aiGIj9ts4i
+J6RlBMHMAoGCCqGSM49BAMCA0gAMEUCIG+x6GaNAKDT2Gs9Jh7rTtAd8KAP/MCC
orUYhAug4kzQAiEApwyX0MvUoZV9fUg0AyN79OCbt0XPneyjdwYPSk3nmyI=
-----END CERTIFICATE-----`)

# From ASNumberInherit.pem
(def as-number-inherit-pem `-----BEGIN CERTIFICATE-----
MIIBiTCCATCgAwIBAgIRAIxkvUFe24qH+RH0D814mEswCgYIKoZIzj0EAwIwADAe
Fw0yNDEwMjIxMDQwMTNaFw0yNTEwMjIxMDQwMTNaMAAwWTATBgcqhkjOPQIBBggq
hkjOPQMBBwNCAAS8OgRLt85kZt8M5MGKcwXyOkUXoylpsp3gKVnQukeEVUPzhYUT
t/nAC9s6tlqQx06aLo4NMpC/ZiLjfqRoh7/Co4GKMIGHMC8GCCsGAQUFBwEIAQH/
BCAwHqACBQChGDAWMAgCAgTSAgIWLjAKAgEAAgUA/////zAhBgNVHQ4EGgQYEekx
OowtPJb0QL2dSh4YuqEhfAEZh6g6MAwGA1UdEwEB/wQCMAAwIwYDVR0jBBwwGoAY
EekxOowtPJb0QL2dSh4YuqEhfAEZh6g6MAoGCCqGSM49BAMCA0cAMEQCIG5s6rM9
fpV76Ydij83G5dfNw8xq/PKohCQAsRc5BFP1AiANm2/BiqB6yzNO3t+1PFdjgpFu
8zYpwnxA4Q4yEvKDxg==
-----END CERTIFICATE-----`)

# From ASRdiOnly.pem
(def as-rdi-only-pem `-----BEGIN CERTIFICATE-----
MIIBhjCCASygAwIBAgIRANz2VZ/ccV2i/GgObA+fDU4wCgYIKoZIzj0EAwIwADAe
Fw0yNDEwMjIxMDM5MjZaFw0yNTEwMjIxMDM5MjZaMAAwWTATBgcqhkjOPQIBBggq
hkjOPQMBBwNCAATpsmi/80tOyt9nDOqJzNTVox3wOGZSEwGXeMNTR0cbytK9h+t8
Ea3+dl6LeXvo423FZd0TNPxRrjaLYFpFjX4Ko4GGMIGDMCsGCCsGAQUFBwEIAQH/
BBwwGqEYMBYwCAICBNICAhYuMAoCAQACBQD/////MCEGA1UdDgQaBBhMamGZIJk1
k//8v1K14lioRkSxGj2ryhIwDAYDVR0TAQH/BAIwADAjBgNVHSMEHDAagBhMamGZ
IJk1k//8v1K14lioRkSxGj2ryhIwCgYIKoZIzj0EAwIDSAAwRQIhAMHro3vcKus9
Id+1hnMeffZL/CWFOSTgtKjX7OMbQOK8AiBijOvIranrc1X0OwtvM2A4bJi035G9
e8BeRHCpaJGitg==
-----END CERTIFICATE-----`)

(let [cert2 (x509-cert/load cert-pem2)]
  (assert (not (:is-ca cert2)))
  (assert (:allowed-ext-usage cert2 "PKIX.ServerAuth"))
  (assert (not (:allowed-ext-usage cert2 "PKIX.ClientAuth")))
  (assert (not (:allowed-ext-usage cert2 "PKIX.CodeSigning"))))

(let [crl (x509-crl/load crl-pem)
     cert (x509-cert/load cert-pem2)]
  (assert (:is-revoked crl cert))
  (assert (> (:this-update crl) 0))
  (assert (> (:next-update crl) (:this-update crl)))
  (assert (= (:entries-count crl) 1))

  # Test CRL entry inspection
  (let [entry (:get-entry crl 0)]
    (assert (>= (:reason entry) 0))
    (assert (> (:revocation-date entry) 0))
    (assert (= (:serial-number entry) (hex-decode "01")))))

(let [now (os/time)
      a-year-later (+ now (* 60 60 24 365))
      cert1 (x509-cert/create-self-signed
             (privkey/new "ECDSA")
             :CN "Example Company" :C "KR" :O "Global Security" :OU "IT Department"
             :ST "Seoul" :L "Gangnam-gu" :dns "root.example.com")
      cert1-dup (:dup cert1)]
  (assert (= (:fingerprint cert1) (:fingerprint cert1-dup)))
  (assert (<= now (:not-before cert1) (+ now 1)))
  (assert (<= a-year-later (:not-after cert1) (+ a-year-later 1)))
  (assert (= (:subject-dn cert1 :ST 0) "Seoul"))
  (assert (= (:issuer-dn cert1 :ST 0) "Seoul"))
  (assert (= (:subject-dn cert1 :L 0) "Gangnam-gu"))
  (assert (= (:issuer-dn cert1 :L 0) "Gangnam-gu"))
  (assert (:hostname-match cert1 "root.example.com"))
  (assert (:allowed-usage cert1 :no-constraints))
  (assert (:allowed-usage cert1 :digital-signature))
  (assert (:allowed-usage cert1 :non-repudiation))
  (assert (:allowed-usage cert1 :key-encipherment))
  (assert (:allowed-usage cert1 :data-encipherment))
  (assert (:allowed-usage cert1 :key-agreement))
  (assert (:allowed-usage cert1 :key-cert-sign))
  (assert (:allowed-usage cert1 :crl-sign))
  (assert (:allowed-usage cert1 :encipher-only))
  (assert (:allowed-usage cert1 :decipher-only))
  (assert (not (:is-ca cert1)))
  (assert (= (x509-cert/verify cert1) 3001))
  (assert (= (x509-cert/validation-status 3001) "Cannot establish trust"))
  (assert (= (x509-cert/validation-status 0) "Verified")))

# Test x509-cert/create-self-signed and x509-cert/issue
(let [ca-key (privkey/new "RSA" "2048")
      ca-cert (x509-cert/create-self-signed
               ca-key
               :CN "Test-CA" :C "KR" :O "Test Org" :ST "Seoul" :L "Gangnam"
               :is-ca true)]
  (assert (:is-ca ca-cert))
  (assert (= (:subject-dn ca-cert :CN 0) "Test-CA"))
  (assert (= (:subject-dn ca-cert :C  0) "KR"))
  (assert (= (:subject-dn ca-cert :O  0) "Test Org"))
  (assert (= (:subject-dn ca-cert :ST 0) "Seoul"))
  (assert (= (:subject-dn ca-cert :L  0) "Gangnam"))
  (assert (= (:issuer-dn  ca-cert :CN 0) "Test-CA"))
  (assert (= (:issuer-dn ca-cert :CN) ["Test-CA"]))
  (assert (:hostname-match ca-cert "Test-CA"))

  (let [server-key (privkey/new "RSA" "2048")
        now (os/time)
        server-cert (x509-cert/issue
                     server-key ca-cert ca-key
                     (- now 3600) (+ now (* 365 24 3600))
                     :CN "server.example.com" :C "KR" :O "Test Org"
                     :key-usage [:digital-signature :key-encipherment]
                     :ext-key-usage ["PKIX.ServerAuth"])]
    (assert (not (:is-ca server-cert)))
    (assert (= (:subject-dn server-cert :CN 0) "server.example.com"))
    (assert (= (:issuer-dn  server-cert :CN 0) "Test-CA"))
    (assert (:allowed-usage server-cert :digital-signature))
    (assert (:allowed-usage server-cert :key-encipherment))
    (assert (not (:allowed-usage server-cert :crl-sign)))
    (assert (:allowed-ext-usage server-cert "PKIX.ServerAuth"))
    (assert (not (:allowed-ext-usage server-cert "PKIX.ClientAuth")))
    (assert (= (x509-cert/verify server-cert :trusted [ca-cert]) 0))))

# Test multiple OU and DNS values
(let [cert (x509-cert/create-self-signed
            (privkey/new "ECDSA")
            :CN "Multi Test" :C "KR" :O "Test Org"
            :OU ["IT" "Engineering" "Security"]
            :dns ["example.com" "*.example.com" "api.example.com"]
            :email "admin@example.com")]
  (assert (= (:subject-dn cert :OU 0) "IT"))
  (assert (= (:subject-dn cert :OU 1) "Engineering"))
  (assert (= (:subject-dn cert :OU 2) "Security"))
  (assert (= (:subject-dn cert :OU) ["IT" "Engineering" "Security"]))
  (assert (= (:subject-dn cert :CN) ["Multi Test"]))
  (assert (not (:hostname-match cert "Multi Test"))) # SAN present, CN ignored (RFC 6125)
  (assert (:hostname-match cert "example.com"))
  (assert (:hostname-match cert "www.example.com"))
  (assert (:hostname-match cert "api.example.com"))
  # Botan may reorder SAN entries, so sort before comparing
  (assert (= [;(sorted (:san cert :dns))]
             [;(sorted ["*.example.com" "api.example.com" "example.com"])]))
  (assert (nil? (:san cert :dns 3)))
  (assert (= (:san cert :email) ["admin@example.com"]))
  (assert (= (:san cert :uri) []))
  (assert (nil? (:san cert :email 1))))

# Test KeyUsage and ExtendedKeyUsage constraints
(let [cert (x509-cert/create-self-signed
            (privkey/new "RSA" "2048")
            :CN "Constrained Cert" :C "KR"
            :key-usage [:digital-signature :key-encipherment]
            :ext-key-usage ["PKIX.ServerAuth" "PKIX.ClientAuth"])]
  (assert (:allowed-usage cert :digital-signature))
  (assert (:allowed-usage cert :key-encipherment))
  (assert (not (:allowed-usage cert :crl-sign)))
  (assert (not (:allowed-usage cert :key-cert-sign)))
  (assert (:allowed-ext-usage cert "PKIX.ServerAuth"))
  (assert (:allowed-ext-usage cert "PKIX.ClientAuth"))
  (assert (not (:allowed-ext-usage cert "PKIX.CodeSigning"))))

# Test single keyword key-usage
(let [cert (x509-cert/create-self-signed
            (privkey/new "ECDSA")
            :CN "Single Usage" :C "KR"
            :key-usage :digital-signature
            :ext-key-usage "PKIX.ServerAuth")]
  (assert (:allowed-usage cert :digital-signature))
  (assert (not (:allowed-usage cert :key-encipherment)))
  (assert (:allowed-ext-usage cert "PKIX.ServerAuth"))
  (assert (not (:allowed-ext-usage cert "PKIX.ClientAuth"))))

# Test CRL creation, revocation, and verification
(let [ca-key (privkey/new "RSA" "2048")
      ca-cert (x509-cert/create-self-signed
               ca-key
               :CN "CRL Test CA" :C "KR" :O "Test Org"
               :is-ca true
               :key-usage [:key-cert-sign :crl-sign])
      server-key (privkey/new "RSA" "2048")
      now (os/time)
      server-cert (x509-cert/issue
                   server-key ca-cert ca-key
                   (- now 3600) (+ now (* 365 24 3600))
                   :CN "server.example.com")
      ca-pubkey (x509-cert/subject-public-key ca-cert)]

  # Create empty CRL
  (let [crl (x509-crl/create ca-cert ca-key now (* 30 24 3600))]
    (assert (= (:entries-count crl) 0))
    (assert (>= (:this-update crl) now))
    (assert (:verify crl ca-pubkey))
    (assert (not (:is-revoked crl server-cert)))

    # Create CRL entry with keyword reason
    (let [entry (x509-crl-entry/create server-cert :key-compromise)]
      (assert (= (:reason entry) 1))

      # Revoke: add entry to CRL
      (let [updated-crl (:revoke crl ca-cert ca-key now (* 30 24 3600) [entry])]
        (assert (= (:entries-count updated-crl) 1))
        (assert (:is-revoked updated-crl server-cert))
        (assert (:verify updated-crl ca-pubkey))

        (let [e (:get-entry updated-crl 0)]
          (assert (= (:reason e) 1))
          (assert (> (:revocation-date e) 0))
          (assert (= (:serial-number e)
                     (x509-cert/serial-number server-cert)))))))

  # Create CRL entry with integer reason
  (let [entry (x509-crl-entry/create server-cert 4)]
    (assert (= (:reason entry) 4)))

  # Verify with wrong key should fail
  (let [crl (x509-crl/create ca-cert ca-key now (* 30 24 3600))
        other-key (privkey/new "RSA" "2048")
        other-pubkey (privkey/get-pubkey other-key)]
    (assert (not (:verify crl other-pubkey)))))

# Test RFC 3779 extensions
(let [ip-cert (x509-cert/load ip-addr-blocks-unsorted-pem)
      ip-all-cert (x509-cert/load ip-addr-blocks-all-pem)
      as-cert (x509-cert/load as-number-cert-pem)
      as-inherit-cert (x509-cert/load as-number-inherit-pem)
      as-rdi-cert (x509-cert/load as-rdi-only-pem)
      no-ext-cert (x509-cert/load cert-pem2)]
  (assert (= (:subject-dn ip-cert :CN 0) "Test CA"))
  (assert (:is-ca ip-cert))
  (each cert [as-cert as-inherit-cert as-rdi-cert]
    (assert (not (:is-ca cert))))
  (assert (not (:is-ca no-ext-cert)))

  (let [blocks (x509-cert/ext-ip-addr-blocks ip-cert)
        v6-max "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"]

    # The DER holds six families; the two adjacent unicast ranges
    # 192.168.0.0-192.168.2.1 and 192.168.2.2-200.0.0.0 merge into one.
    (assert (= (length blocks) 5))
    (assert (deep= blocks
                   [{:version :v4 :ranges :inherit}
                    {:version :v4 :safi 1 :ranges [["192.168.0.0" "200.0.0.0"]]}
                    {:version :v4 :safi 2 :ranges :inherit}
                    {:version :v6 :ranges [[v6-max v6-max]]}
                    {:version :v6 :safi 1 :ranges :inherit}]))
  (assert (= (x509-cert/ext-ip-addr-blocks ip-cert)
             (:ext-ip-addr-blocks ip-cert)))

  (assert (= (x509-cert/ext-ip-addr-blocks ip-all-cert)
             [{:version :v4
               :ranges [["192.168.0.0" "192.168.127.255"]
                        ["193.168.0.0" "193.169.255.255"]
                        ["194.168.0.0" "195.175.1.2"]
                        ["196.168.0.1" "196.168.0.1"]]}
              {:version :v6
               :ranges [["2003:0:6829:3435:420:10c5:0:c4"
                         "2003:0:6829:3435:420:10c5:0:c4"]
                        ["ab01::1" "cd02::2"]
                        ["fa80::" "fa80::7fff:ffff:ffff:ffff"]
                        ["fe20::" "fe20:0:7ff:ffff:ffff:ffff:ffff:ffff"]]}]))

  (assert (nil? (x509-cert/ext-ip-addr-blocks no-ext-cert)))
  (assert (nil? (x509-cert/ext-ip-addr-blocks as-cert)))))

(end-suite)
