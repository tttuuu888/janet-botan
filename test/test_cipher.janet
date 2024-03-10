(use ../build/botan)
(use spork/test)

(start-suite "symmetric cipher")

(assert-error "Error expected" (cipher/init "AES-127/CBC/PKCS7"))

(let [cipher (assert (cipher/init "AES-128/CBC/PKCS7"))]
  (assert (= (cipher/get-min-keylen cipher) 16))
  (assert (= (cipher/get-max-keylen cipher) 16))

  (assert (not (cipher/set-key cipher (hex-decode "898BE9CC5004ED0FA6E117C9A3099D31"))))
  (assert (not (cipher/clear cipher)))

  (assert (not (cipher/destroy cipher))))

(end-suite)
