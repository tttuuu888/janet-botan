(use ../build/botan)
(use spork/test)

(start-suite "block-cipher")

(let [cipher (block-cipher/init "AES-128")]
  (assert (= (block-cipher/block-size cipher) 16))
  (block-cipher/destroy cipher))

(let [cipher (block-cipher/init "AES-128")]
  (assert (= (block-cipher/name cipher) "AES-128"))
  (block-cipher/destroy cipher))

(end-suite)
