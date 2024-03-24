(use ../build/botan)
(use spork/test)

(start-suite "public key")

(let [n (mpi/from-str "1090660992520643446103273789680343")
      e (mpi/from-str "65537")
      rsa-pub-key (pubkey/load-rsa n e)]
  (assert (= (:get-field rsa-pub-key "n") n))
  (assert (= (:get-field rsa-pub-key "e") e)))

(let [scalar (mpi/from-hex-str "DBC868EF66949314FC040180FC6F1A9867466028364140361FF770733B23EF76")
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


(end-suite)
