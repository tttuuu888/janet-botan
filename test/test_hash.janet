(use ../build/botan)
(use spork/test)

(start-suite "hash")

(assert-error "Error expected" (hash/init "SHA-255"))

(let [hash (assert (hash/init "SHA-256"))]
  (assert (= (hash/name hash) "SHA-256"))

  (assert (not (hash/destroy hash))))

(end-suite)
