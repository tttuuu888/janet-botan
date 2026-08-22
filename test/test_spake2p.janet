(use ../build/botan)
(use spork/test)

(start-suite "SPAKE2+")

# SPAKE2+ system parameters
(assert-error "Error expected" (spake2p-params/new "P37-MD5"))

(let [params (assert (spake2p-params/new "P256-SHA256"))
      ec-g (ec-group/from-name "secp256r1")
      params2 (assert (spake2p-params/new-custom ec-g "seed-bytes" "SHA-256"))]

  (assert (= (spake2p-params/share-size params)
             (:share-size params)
             65))
  (assert (= (spake2p-params/confirmation-size params)
             (:confirmation-size params)
             32))
  (assert (= (:share-size params2) 65))

  (let [password "hunter2"
        prover-id "client"
        verifier-id "server"
        salt (hex-decode "adb63d2727f971e1b52b7ba1e42ab73c")
        secret (assert (spake2p-derive-secret params password prover-id verifier-id salt))]

    (assert (= (length secret) 64))
    (assert (= secret
               (spake2p-derive-secret params password prover-id verifier-id salt)))

    (let [record (assert (spake2p-registration-record params secret))]
      (assert (= (length record) 97))
      (assert (= record
                 (spake2p-registration-record params secret))))))

(end-suite)
