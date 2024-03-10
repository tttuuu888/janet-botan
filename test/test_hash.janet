(use ../build/botan)
(use spork/test)

(start-suite "hash")

(assert-error "Error expected" (hash/init "SHA-255"))

(let [hash (assert (hash/init "SHA-256"))]
  (assert (= (hash/name hash) "SHA-256"))

  (let [hash2 (assert (hash/copy hash))]
    (assert (= (hash/name hash2) "SHA-256"))
    (assert (not (hash/destroy hash2))))

  (assert (not (hash/clear hash)))

  (assert (= (hash/output-len hash) 32))

  (assert (not (hash/destroy hash))))

(end-suite)
