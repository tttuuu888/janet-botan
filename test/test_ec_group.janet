(use ../build/botan)
(use spork/test)

(start-suite "EC Groups")

(assert (ec-group/supports-named-group "secp256r1"))
(assert (not (ec-group/supports-named-group "no-such-group-123")))

(let [oid (oid/from-string "1.2.840.10045.3.1.7")
     group-from-name (ec-group/from-name "secp256r1")
     group-from-oid (ec-group/from-oid oid)]
  (assert (= oid (:get-curve-oid group-from-name)))
  (assert (= group-from-name group-from-oid)))

(let [ec-group (ec-group/from-name "secp256r1")
      priv-key (privkey/new-ec "ECDSA" ec-group)]
  (assert (= (:algo-name priv-key) "ECDSA"))
  (assert (= ec-group (ec-group/from-pem (:to-pem ec-group))))
  (assert (= ec-group (ec-group/from-ber (:to-der ec-group)))))

(when-let
    [_ (ec-group/supports-application-specific-group)
     oid (assert (oid/from-string "1.3.6.1.4.1.25258.100.0"))
     _ (assert (:register oid "secp256r1-but-manually-registered"))
     p (mpi/new "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF" 16)
     a (mpi/new "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC" 16)
     b (mpi/new "5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B" 16)
     gx (mpi/new "6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296" 16)
     gy (mpi/new "4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5" 16)
     order (mpi/new "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551" 16)
     ec-group (ec-group/from-params oid p a b gx gy order)
     ec-group-from-name (ec-group/from-name "secp256r1")]
    (assert (= ec-group ec-group-from-name))
    (assert (= p (:get-p ec-group) (:get-p ec-group-from-name)))
    (assert (= a (:get-a ec-group) (:get-a ec-group-from-name)))
    (assert (= b (:get-b ec-group) (:get-b ec-group-from-name)))
    (assert (= gx (:get-gx ec-group) (:get-gx ec-group-from-name)))
    (assert (= gy (:get-gy ec-group) (:get-gy ec-group-from-name)))
    (assert (= order (:get-order ec-group) (:get-order ec-group-from-name))))
