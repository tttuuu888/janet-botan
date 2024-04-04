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
  (assert (:allowed-usage cert1 "NO-CONSTRAINTS"))
  (assert (:allowed-usage cert1 "DIGITAL-SIGNATURE"))
  (assert (:allowed-usage cert1 "NON-REPUDIATION"))
  (assert (:allowed-usage cert1 "KEY-ENCIPHERMENT"))
  (assert (:allowed-usage cert1 "DATA-ENCIPHERMENT"))
  (assert (:allowed-usage cert1 "KEY-AGREEMENT"))
  (assert (:allowed-usage cert1 "KEY-CERT-SIGN"))
  (assert (:allowed-usage cert1 "CRL-SIGN"))
  (assert (:allowed-usage cert1 "ENCIPHER-ONLY"))
  (assert (:allowed-usage cert1 "DECIPHER-ONLY"))
  (assert (= (x509-cert/verify cert1) 3001))
  (assert (= (x509-cert/validation-status 3001) "Cannot establish trust"))
  (assert (= (x509-cert/validation-status 0) "Verified")))

(end-suite)
