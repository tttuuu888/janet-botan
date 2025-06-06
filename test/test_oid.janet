(use ../build/botan)
(use spork/test)

(start-suite "Object Identifiers")

(let [oid-str "1.2.3.4.5"
      oid-name "random-name-that-definitely-has-no-oid"
      oid (oid/from-string oid-str)]
  (assert (= (:to-string oid)) oid-str)
  (assert (= (:to-name oid)) oid-str)

  (:register oid oid-name)
  (assert (= (:to-name oid)) oid-name))

(let [oid-rsa-str "1.2.840.113549.1.1.1"
      oid-rsa-name "RSA"
      oid1 (oid/from-string oid-rsa-str)
      oid2 (oid/from-string oid-rsa-name)]
  (assert (= (:to-string oid1)) oid-rsa-str)
  (assert (= (:to-string oid2)) oid-rsa-str)
  (assert (= (:to-name oid1)) oid-rsa-name)
  (assert (= (:to-name oid2)) oid-rsa-name))

(let [prikey-rsa (privkey/new "RSA" "1024")
      pubkey-rsa (:get-pubkey prikey-rsa)
      oid-rsa-priv (:oid prikey-rsa)
      oid-rsa-pub (:oid pubkey-rsa)
      oid-rsa (oid/from-string "RSA")]
  (assert (= oid-rsa oid-rsa-priv oid-rsa-pub))
  (assert (= (:to-string oid-rsa) (:to-string oid-rsa-priv) (:to-string oid-rsa-pub)))
  (assert (= (:to-name oid-rsa) (:to-name oid-rsa-priv) (:to-name oid-rsa-pub))))

(let [oid1 (oid/from-string "1.2.3.4.5.6")
      oid2 (oid/from-string "1.2.3.4.5.6")
      oid3 (oid/from-string "1.2.3.4")]
  (assert (= oid1 oid2))
  (assert (> oid1 oid3))
  (assert (>= oid1 oid3))
  (assert (< oid3 oid1))
  (assert (<= oid3 oid1)))

(end-suite)
