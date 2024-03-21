(use ../build/botan)
(use spork/test)

(start-suite "private key")

(let [prikey1 (privkey/new "RSA" "1024")
      prikey1-pem (:to-pem prikey1)
      prikey1-der (:to-der prikey1)
      prikey2-load-from-pem (privkey/load prikey1-pem)
      prikey2-load-from-der (privkey/load prikey1-der)]
  (assert (= (:check-key prikey1 (rng/new)) true))
  (assert (= (:check-key prikey1 (rng/new) :weak) true))
  (assert (= (:algo-name prikey1) "RSA"))
  )


(end-suite)
