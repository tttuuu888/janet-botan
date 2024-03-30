(use ../build/botan)
(use spork/test)

(start-suite "TOTP")

(let [key (hex-decode "3132333435363738393031323334353637383930")
      hash "SHA-1"
      digits 8
      timestep 30
      totp (totp/new key hash digits timestep)]
  (assert (= (:generate totp 59) 94287082))
  (assert (= (:generate totp 1111111109) 7081804))

  (assert (= (:check totp 94287082 (+ 59 60) 60) true))
  (assert (= (:check totp 94287082 (+ 59 31) 1) false))
  (assert (= (:check totp 94287082 (+ 59 61) 1) false)))

(end-suite)
