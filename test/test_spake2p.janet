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
                 (spake2p-registration-record params secret)))

      # A full exchange between a prover and a verifier
      (let [context "janet-botan"
            prover (assert (spake2p-prover/new params secret
                                               prover-id verifier-id context))
            verifier (assert (spake2p-verifier/new params record
                                                   prover-id verifier-id context))
            share-p (assert (spake2p-prover/generate-message prover))
            response (assert (spake2p-verifier/process-message verifier share-p))
            confirm-p (assert (spake2p-prover/process-message prover response))]

        (assert (= (length share-p) 65))
        (assert (= (length response) 97))
        (assert (= (length confirm-p) 32))
        (assert (spake2p-verifier/verify-confirmation verifier confirm-p))
        (assert (= (spake2p-prover/shared-secret prover)
                   (:shared-secret prover)
                   (spake2p-verifier/shared-secret verifier)
                   (:shared-secret verifier))))

      # A prover which does not know the password fails key confirmation
      (let [wrong (spake2p-derive-secret params "wrong-password"
                                         prover-id verifier-id salt)
            prover (spake2p-prover/new params wrong prover-id verifier-id "")
            verifier (spake2p-verifier/new params record prover-id verifier-id "")
            response (:process-message verifier (:generate-message prover))]

        (assert (nil? (:process-message prover response)))
        (assert (not (:verify-confirmation verifier (string/repeat "\0" 32)))))

      # skip-confirmation yields the shared secret without checking confirmP
      (let [prover (spake2p-prover/new params secret prover-id verifier-id "")
            verifier (spake2p-verifier/new params record prover-id verifier-id "")]

        (:process-message verifier (:generate-message prover))
        (assert (= verifier (:skip-confirmation verifier)))
        (assert (= (length (:shared-secret verifier)) 32))))))

(end-suite)
