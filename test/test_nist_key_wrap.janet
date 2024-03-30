(use ../build/botan)
(use spork/test)

(start-suite "NIST Key Wrapping")

(let [kek (hex-decode "000102030405060708090A0B0C0D0E0F")
      key (hex-decode "00112233445566778899AABBCCDDEEFF")
      wrapped-key (nist-key-wrap kek key)
      unwrapped-key (nist-key-unwrap kek wrapped-key)]
  (assert (= key unwrapped-key)))

(end-suite)
