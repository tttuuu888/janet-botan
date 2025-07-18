(use ../build/botan)
(use spork/test)

(start-suite "Private Key")

(let [prikey1 (privkey/new "RSA" "1024")
      prikey1-pem (:to-pem prikey1)
      prikey1-der (:to-der prikey1)
      prikey2-load-from-pem (privkey/load prikey1-pem)
      prikey2-load-from-der (privkey/load prikey1-der)]
  (assert (= (:check-key prikey1 (rng/new)) true))
  (assert (= (:check-key prikey1 (rng/new) :weak) true))

  (assert (= (:algo-name prikey1) "RSA"))

  (assert (= (:stateful-operation prikey1) false))

  (assert (= (:to-pem prikey1) (:export prikey1 :pem)))
  (assert (= (:to-der prikey1) (:export prikey1))))

(let [prikey (privkey/new "XMSS" "XMSS-SHA2_10_256")]
  (assert (= (:stateful-operation prikey) true))
  (assert (= (:remaining-operations prikey) 1024)))

(let [p (mpi/new "1090660992520643446103273789680343")
      q (mpi/new "1162435056374824133712043309728653")
      e (mpi/new "65537")
      rsa-priv-key (privkey/load-rsa p q e)]
  (assert (= (:get-field rsa-priv-key "p") p))
  (assert (= (:get-field rsa-priv-key "q") q))
  (assert (= (:get-field rsa-priv-key "e") e)))

(let [p (mpi/new "a8f9cd201e5e35d892f85f80e4db2599a5676a3b1d4f190330ed3256b26d0e80a0e49a8fffaaad2a24f472d2573241d4d6d6c7480c80b4c67bb4479c15ada7ea8424d2502fa01472e760241713dab025ae1b02e1703a1435f62ddf4ee4c1b664066eb22f2e3bf28bb70a2a76e4fd5ebe2d1229681b5b06439ac9c7e9d8bde283" 16)
      q (mpi/new "f85f0f83ac4df7ea0cdf8f469bfeeaea14156495" 16)
      g (mpi/new "2b3152ff6c62f14622b8f48e59f8af46883b38e79b8c74deeae9df131f8b856e3ad6c8455dab87cc0da8ac973417ce4f7878557d6cdf40b35b4a0ca3eb310c6a95d68ce284ad4e25ea28591611ee08b8444bd64b25f3f7c572410ddfb39cc728b9c936f85f419129869929cdb909a6a3a99bbe089216368171bd0ba81de4fe33" 16)
      x (mpi/new "c53eae6d45323164c7d07af5715703744a63fc3a" 16)
      dsa-priv-key (privkey/load-dsa p q g x)]
  (assert (= (:get-field dsa-priv-key "p") p))
  (assert (= (:get-field dsa-priv-key "q") q))
  (assert (= (:get-field dsa-priv-key "g") g))
  (assert (= (:get-field dsa-priv-key "x") x)))

(let [p (mpi/new "32317006071311007300714876688669951960444102669715484032130345427524655138867890893197201411522913463688717960921898019494119559150490921095088152386448283120630877367300996091750197750389652106796057638384067568276792218642619756161838094338476170470581645852036305042887575891541065808607552399123930385521914333389668342420684974786564569494856176035326322058077805659331026192708460314150258592864177116725943603718461857357598351152301645904403697613233287231227125684710820209725157101726931323469678542580656697935045997268352998638215525166389437335543602135433229604645318478604952148193555853611059594288367")
      g (mpi/new "2")
      x (mpi/new "123456789")
      dh-priv-key (privkey/load-dh p g x)]
  (assert (= (:get-field dh-priv-key "p") p))
  (assert (= (:get-field dh-priv-key "g") g))
  (assert (= (:get-field dh-priv-key "x") x)))

(let [p (mpi/new "1898479519619165222561514020362438903700593475271")
      g (mpi/new "2")
      x (mpi/new "123456789")
      elgamal-priv-key (privkey/load-elgamal p g x)]
  (assert (= (:get-field elgamal-priv-key "p") p))
  (assert (= (:get-field elgamal-priv-key "g") g))
  (assert (= (:get-field elgamal-priv-key "x") x)))

(let [curve "secp256r1"
      ecdsa-priv-key1 (privkey/new "ECDSA" curve)
      x (:get-field ecdsa-priv-key1 "x")
      ecdsa-priv-key2 (privkey/load-ecdsa curve x)]
  (assert (= (:get-field ecdsa-priv-key1 "x")
             (:get-field ecdsa-priv-key2 "x"))))

(let [curve "secp256r1"
      ecdh-priv-key1 (privkey/new "ECDH" curve)
      x (:get-field ecdh-priv-key1 "x")
      ecdh-priv-key2 (privkey/load-ecdh curve x)]
  (assert (= (:get-field ecdh-priv-key1 "x")
             (:get-field ecdh-priv-key2 "x"))))

(let [curve "sm2p256v1"
      sm2-priv-key1 (privkey/new "SM2_Enc" curve)
      x (:get-field sm2-priv-key1 "x")
      sm2-priv-key2 (privkey/load-sm2 curve x)]
  (assert (= (:get-field sm2-priv-key1 "x")
             (:get-field sm2-priv-key2 "x"))))

(end-suite)
