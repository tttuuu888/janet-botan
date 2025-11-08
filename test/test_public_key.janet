(use ../build/botan)
(use spork/test)

(start-suite "Public Key")

(defn compress-sec1 (uncompressed-sec1)
  (let [sec1 (hex-encode uncompressed-sec1)
        _ (assert (string/has-prefix? "04" sec1))
        x-len (/ (- (length sec1) 2) 2)
        x (string/slice sec1 2 (+ 2 x-len))]
    (if (odd? (mpi/get-bit (mpi/new sec1 16) 0))
      (hex-decode (string "03" x))
      (hex-decode (string "02" x)))))

(let [n (mpi/new "1090660992520643446103273789680343")
      e (mpi/new "65537")
      rsa-pub-key (pubkey/load-rsa n e)]
  (assert (= (:get-field rsa-pub-key "n") n))
  (assert (= (:get-field rsa-pub-key "e") e)))

(let [scalar (mpi/new "DBC868EF66949314FC040180FC6F1A9867466028364140361FF770733B23EF76" 16)
      prikey (privkey/load-ecdsa "secp256r1" scalar)
      pubkey (:get-pubkey prikey)
      pub-point (hex-encode (:get-public-point pubkey))
      pub-x (hex-encode (:to-bin (:get-field pubkey "public_x")))
      pub-y (hex-encode (:to-bin (:get-field pubkey "public_y")))
      fingerprint (:fingerprint pubkey)
      sha256-hash-of-pubkey (:final (:update (hash/new "SHA-256") (hex-decode pub-point)))]
  (assert (= pub-point (string "04" pub-x pub-y)))
  (assert (= fingerprint sha256-hash-of-pubkey))
  (assert (= (:estimated-strength pubkey) 128)))

(let [curve "secp256r1"
      ecdsa-prikey (privkey/new "ECDSA" curve)
      ecdsa-pubkey (:get-pubkey ecdsa-prikey)
      pub-x (hex-encode (:to-bin (:get-field ecdsa-pubkey "public_x")))
      pub-y (hex-encode (:to-bin (:get-field ecdsa-pubkey "public_y")))
      uncompressed-sec1 (:to-raw ecdsa-pubkey)
      compressed-sec1 (compress-sec1 uncompressed-sec1)
      ecdsa-pubkey1 (pubkey/load-ecdsa curve (mpi/new pub-x 16) (mpi/new pub-y 16))
      ecdsa-pubkey2 (pubkey/load-ecdsa-sec1 curve uncompressed-sec1)
      ecdsa-pubkey3 (pubkey/load-ecdsa-sec1 curve compressed-sec1)]
  (assert (= (:get-field ecdsa-pubkey1 "public_x")
             (:get-field ecdsa-pubkey2 "public_x")
             (:get-field ecdsa-pubkey3 "public_x")))
  (assert (= (:get-field ecdsa-pubkey1 "public_y")
             (:get-field ecdsa-pubkey2 "public_y")
             (:get-field ecdsa-pubkey3 "public_y"))))

(let [curve "secp256r1"
      ecdh-prikey (privkey/new "ECDH" curve)
      ecdh-pubkey (:get-pubkey ecdh-prikey)
      pub-x (hex-encode (:to-bin (:get-field ecdh-pubkey "public_x")))
      pub-y (hex-encode (:to-bin (:get-field ecdh-pubkey "public_y")))
      uncompressed-sec1 (:to-raw ecdh-pubkey)
      compressed-sec1 (compress-sec1 uncompressed-sec1)
      ecdh-pubkey1 (pubkey/load-ecdh curve (mpi/new pub-x 16) (mpi/new pub-y 16))
      ecdh-pubkey2 (pubkey/load-ecdh-sec1 curve uncompressed-sec1)
      ecdh-pubkey3 (pubkey/load-ecdh-sec1 curve compressed-sec1)]
  (assert (= (:get-field ecdh-pubkey1 "public_x")
             (:get-field ecdh-pubkey2 "public_x")
             (:get-field ecdh-pubkey3 "public_x")))
  (assert (= (:get-field ecdh-pubkey1 "public_y")
             (:get-field ecdh-pubkey2 "public_y")
             (:get-field ecdh-pubkey3 "public_y"))))

(let [curve "sm2p256v1"
      sm2-prikey (privkey/new "SM2" curve)
      sm2-pubkey (:get-pubkey sm2-prikey)
      pub-x (hex-encode (:to-bin (:get-field sm2-pubkey "public_x")))
      pub-y (hex-encode (:to-bin (:get-field sm2-pubkey "public_y")))
      uncompressed-sec1 (:to-raw sm2-pubkey)
      compressed-sec1 (compress-sec1 uncompressed-sec1)
      sm2-pubkey1 (pubkey/load-sm2 curve (mpi/new pub-x 16) (mpi/new pub-y 16))
      sm2-pubkey2 (pubkey/load-sm2-sec1 curve uncompressed-sec1)
      sm2-pubkey3 (pubkey/load-sm2-sec1 curve compressed-sec1)]
  (assert (= (:get-field sm2-pubkey1 "public_x")
             (:get-field sm2-pubkey2 "public_x")
             (:get-field sm2-pubkey3 "public_x")))
  (assert (= (:get-field sm2-pubkey1 "public_y")
             (:get-field sm2-pubkey2 "public_y")
             (:get-field sm2-pubkey3 "public_y"))))

(end-suite)
