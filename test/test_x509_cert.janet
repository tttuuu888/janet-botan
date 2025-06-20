(use ../build/botan)
(use spork/test)

(start-suite "X509 Certificate")

(def cert-pem `-----BEGIN CERTIFICATE-----
MIICFjCCAb2gAwIBAgIULwai5OMhN/rVFSqcODrzACa0QfwwCgYIKoZIzj0EAwIw
ejELMAkGA1UEBhMCR0IxDjAMBgNVBAgMBVNlb3VsMQ4wDAYDVQQHDAVTZW91bDEY
MBYGA1UECgwPR2xvYmFsIFNlY3VyaXR5MRYwFAYDVQQLDA1JVCBEZXBhcnRtZW50
MRkwFwYDVQQDDBByb290LmV4YW1wbGUuY29tMB4XDTI0MDMzMTA3NDUyNFoXDTI1
MDMzMTA3NDUyNFowejELMAkGA1UEBhMCR0IxDjAMBgNVBAgMBVNlb3VsMQ4wDAYD
VQQHDAVTZW91bDEYMBYGA1UECgwPR2xvYmFsIFNlY3VyaXR5MRYwFAYDVQQLDA1J
VCBEZXBhcnRtZW50MRkwFwYDVQQDDBByb290LmV4YW1wbGUuY29tMFkwEwYHKoZI
zj0CAQYIKoZIzj0DAQcDQgAEcfV9ilcOb4NyJemITxufAe5/mBraz5SMjljq0E5Q
U55mi3+tiLmRgQxP1EaAkHR+sEpJfK4J7kD+Xe2+v831p6MhMB8wHQYDVR0OBBYE
FAcnZiHVXU8Q5SoGGRq3PcslvPQRMAoGCCqGSM49BAMCA0cAMEQCIHoMOXZBO3Zg
ko2ILsX3RIGui+UMxpfHaqwEpeIOolVjAiBK/Y/EAaxIXlwmzt5axWZIIOSdrvzy
GfhWL0+0pcmP2g==
-----END CERTIFICATE-----`)

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

(let [cert-not-before 1711871124
      cert-not-after 1743407124
      cert-fingerprint "43:95:0A:CC:2D:71:60:00:5F:04:97:0C:8A:A2:F6:C3:09:CB:5A:43:CF:BB:AB:1B:55:43:55:AF:B3:1E:20:4D"
      cert-serial-number (hex-decode "2F06A2E4E32137FAD5152A9C383AF30026B441FC")
      cert-authority-key-id ""
      cert-subject-key-id (hex-decode "07276621D55D4F10E52A06191AB73DCB25BCF411")
      cert-pubkey-bits (hex-decode "301306072A8648CE3D020106082A8648CE3D0301070342000471F57D8A570E6F837225E9884F1B9F01EE7F981ADACF948C8E58EAD04E50539E668B7FAD88B991810C4FD4468090747EB04A497CAE09EE40FE5DEDBEBFCDF5A7")
      cert1 (x509-cert/load cert-pem)]
  (assert (= (:not-before cert1) cert-not-before))
  (assert (= (:not-after cert1) cert-not-after))
  (assert (= (:fingerprint cert1) cert-fingerprint))
  (assert (= (:serial-number cert1) cert-serial-number))
  (assert (= (:authority-key-id cert1) cert-authority-key-id))
  (assert (= (:subject-key-id cert1) cert-subject-key-id))
  (assert (= (:subject-public-key-bits cert1) cert-pubkey-bits))
  (assert (string/has-suffix? cert-pubkey-bits
                              (:to-der (:subject-public-key cert1))))
  (assert (= (:subject-dn cert1 "State" 0) "Seoul"))
  (assert (= (:issuer-dn cert1 "State" 0) "Seoul"))
  (assert (:hostname-match cert1 "root.example.com"))
  (assert (:allowed-usage cert1 :NO-CONSTRAINTS))
  (assert (:allowed-usage cert1 :DIGITAL-SIGNATURE))
  (assert (:allowed-usage cert1 :NON-REPUDIATION))
  (assert (:allowed-usage cert1 :KEY-ENCIPHERMENT))
  (assert (:allowed-usage cert1 :DATA-ENCIPHERMENT))
  (assert (:allowed-usage cert1 :KEY-AGREEMENT))
  (assert (:allowed-usage cert1 :KEY-CERT-SIGN))
  (assert (:allowed-usage cert1 :CRL-SIGN))
  (assert (:allowed-usage cert1 :ENCIPHER-ONLY))
  (assert (:allowed-usage cert1 :DECIPHER-ONLY))
  (assert (= (x509-cert/verify cert1) 3001))
  (assert (= (x509-cert/validation-status 3001) "Cannot establish trust"))
  (assert (= (x509-cert/validation-status 0) "Verified")))

(let [crl (x509-crl/load crl-pem)
     cert (x509-cert/load cert-pem2)]
  (assert (:is-revoked crl cert)))

(end-suite)
