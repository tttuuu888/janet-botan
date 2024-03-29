(use ../build/botan)
(use spork/test)

(start-suite "Format Preserving Encryption (FE1 scheme)")

(let [modulus (mpi/from-str "1000000000")
      input (mpi/from-str "939210311")
      key (string/repeat (hex-encode "0") 32)
      tweak (string/repeat (hex-encode "0") 32)
      fpe (fpe/new modulus key 8)
      ctext (:encrypt fpe input tweak)
      ptext (:decrypt fpe ctext tweak)]
  (assert (= ptext input)))

(end-suite)
