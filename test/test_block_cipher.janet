(use ../build/botan)
(use spork/test)

(start-suite "block-cipher")

(let [cipher (block-cipher/init "AES-128")]
  (assert (= (block-cipher/block-size cipher) 16))

  (assert (= (block-cipher/name cipher) "AES-128"))

  (assert (= (block-cipher/get-min-keylen cipher) 16))
  (assert (= (block-cipher/get-max-keylen cipher) 16))
  (assert (= (block-cipher/get-keylen-modulo cipher) 1))

  (assert (= (block-cipher/clear cipher) true))

  (assert (= (block-cipher/set-key
              cipher
              (hex-decode "00010203040506070001020304050607"))
             true))

  (block-cipher/destroy cipher))

(end-suite)
