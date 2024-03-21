(use ../build/botan)
(use spork/test)

(start-suite "private key")

(let [prikey1 (privkey/new "RSA" "1024")
      prikey1-pem (:to-pem prikey1)
      prikey1-der (:to-der prikey1)
      prikey2-load-from-pem (privkey/load prikey1-pem)
      prikey2-load-from-der (privkey/load prikey1-der)]
  )


(end-suite)
