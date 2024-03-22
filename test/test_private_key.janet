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

(let [p (mpi/new-from-hex-str "a8f9cd201e5e35d892f85f80e4db2599a5676a3b1d4f190330ed3256b26d0e80a0e49a8fffaaad2a24f472d2573241d4d6d6c7480c80b4c67bb4479c15ada7ea8424d2502fa01472e760241713dab025ae1b02e1703a1435f62ddf4ee4c1b664066eb22f2e3bf28bb70a2a76e4fd5ebe2d1229681b5b06439ac9c7e9d8bde283")
      q (mpi/new-from-hex-str "f85f0f83ac4df7ea0cdf8f469bfeeaea14156495")
      g (mpi/new-from-hex-str "2b3152ff6c62f14622b8f48e59f8af46883b38e79b8c74deeae9df131f8b856e3ad6c8455dab87cc0da8ac973417ce4f7878557d6cdf40b35b4a0ca3eb310c6a95d68ce284ad4e25ea28591611ee08b8444bd64b25f3f7c572410ddfb39cc728b9c936f85f419129869929cdb909a6a3a99bbe089216368171bd0ba81de4fe33")
      x (mpi/new-from-hex-str "c53eae6d45323164c7d07af5715703744a63fc3a")
      dsa-priv-key1 (privkey/load-dsa p q g x)]
  (assert (= (:get-field dsa-priv-key1 "p") p))
  (assert (= (:get-field dsa-priv-key1 "q") q))
  (assert (= (:get-field dsa-priv-key1 "g") g))
  (assert (= (:get-field dsa-priv-key1 "x") x))
)


(end-suite)
