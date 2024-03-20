(use ../build/botan)
(use spork/test)

(start-suite "private key")

(pp (privkey/new "RSA" "1024"))

(let [prikey (privkey/new "RSA" "1024")]
  (pp (hex-decode (:to-pem prikey))))


(end-suite)
