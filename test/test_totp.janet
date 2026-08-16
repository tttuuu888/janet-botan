(use ../build/botan)
(use spork/test)

(start-suite "TOTP")

(let [key (hex-decode "3132333435363738393031323334353637383930")
      hash "SHA-1"
      digits 8
      timestep 30
      totp (totp/new key hash digits timestep)
      timestamp 1000216740]
  (assert (= (:generate totp timestamp) 34097298))
  (assert (= (:generate totp 1111111109) 7081804))

  (assert (= (:check totp 34097298 (+ timestamp 60) 2) true))
  (assert (= (:check totp 34097298 (+ timestamp 61) 1) false)))

(end-suite)
