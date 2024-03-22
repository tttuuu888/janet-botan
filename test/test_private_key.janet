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

  (assert (= (:to-pem prikey1) (:export prikey1 :pem)))
  (assert (= (:to-der prikey1) (:export prikey1))))


(let [p (mpi/new-from-str "1090660992520643446103273789680343")
      q (mpi/new-from-str "1162435056374824133712043309728653")
      e (mpi/new-from-str "65537")
      rsa-priv-key1 (privkey/load-rsa p q e)]
  (assert (= (:get-field rsa-priv-key1 "p") p))
  (assert (= (:get-field rsa-priv-key1 "q") q))
  (assert (= (:get-field rsa-priv-key1 "e") e)))


(end-suite)
