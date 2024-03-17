(use ../build/botan)
(use spork/test)

(start-suite "block-cipher")

(assert-error "Error expected" (block-cipher/new "AES-129"))

(let [cipher (assert (block-cipher/new "AES-128"))]
  (assert (= (block-cipher/block-size cipher) 16))

  (assert (= (block-cipher/name cipher) "AES-128"))

  (let [[min-key max-key mod-key] (block-cipher/get-keyspec cipher)]
    (assert (= min-key 16))
    (assert (= max-key 16))
    (assert (= mod-key 1)))

  (assert (block-cipher/clear cipher))

  (assert (block-cipher/set-key
           cipher
           (hex-decode "00000000000000000000000000000000")))

  (assert (deep= (hex-encode (block-cipher/encrypt
                              cipher
                              (hex-decode "00000000000000000000000000000000")))
                 "66E94BD4EF8A2C3B884CFA59CA342B2E"))

  (assert (deep= (hex-encode (block-cipher/decrypt
                              cipher
                              (hex-decode "66E94BD4EF8A2C3B884CFA59CA342B2E")))
                 "00000000000000000000000000000000")))

(end-suite)
