(use ../build/botan)
(use spork/test)

(start-suite "block-cipher")

(let [cipher (block-cipher/init "AES-128")]
  (assert (= (block-cipher/block-size cipher) 16))

  (assert (= (block-cipher/name cipher) "AES-128"))

  (assert (= 16 (block-cipher/get-min-keylen cipher)))
  (assert (= 16 (block-cipher/get-max-keylen cipher)))
  (assert (= 1 (block-cipher/get-keylen-modulo cipher)))

  (block-cipher/destroy cipher))

(end-suite)
