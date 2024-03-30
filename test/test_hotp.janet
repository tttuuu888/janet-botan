(use ../build/botan)
(use spork/test)

(start-suite "HOTP")

(let [key (hex-decode "3132333435363738393031323334353637383930")
      hotp (hotp/new key "SHA-1" 6)]
  (assert (= (:generate hotp 0) 755224))
  (assert (= (:generate hotp 1) 287082))
  (assert (= (:generate hotp 2) 359152))
  (assert (= (:generate hotp 0) 755224))

  (assert (= (:check hotp 755224 0 0) [true 1]))
  (assert (= (:check hotp 359152 2 0) [true 3]))
  (assert (= (:check hotp 359152 1 0) [false 1]))
  (assert (= (:check hotp 359152 0 2) [true 3])))


(end-suite)
