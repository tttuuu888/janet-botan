(use ../build/botan)
(use spork/test)

(start-suite "private key")

(pp (privkey/new "RSA" "1024"))

(end-suite)
