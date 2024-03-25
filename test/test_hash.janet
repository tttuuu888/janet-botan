(use ../build/botan)
(use spork/test)

(start-suite "Hash Functions")

(assert-error "Error expected" (hash/new "SHA-255"))

(let [hash (assert (hash/new "SHA-256"))]
  (assert (= (hash/name hash) "SHA-256"))
  (assert (= (hash/output-length hash) 32))

  (assert (hash/update hash "ABC"))
  (assert (deep= (hex-encode (hash/final hash))
                 "B5D4045C3F466FA91FE2CC6ABE79232A1A57CDF104F7A26E716E0A1E2789DF78"))

  (assert (hash/update hash "message digest"))
  (assert (deep= (hex-encode (hash/final hash))
                 "F7846F55CF23E14EEBEAB5B4E1550CAD5B509E3348FBC4EFA3A1413D393CB650"))

  (assert (hash/clear hash))

  (assert (hash/update hash "ABC"))
  (assert (deep= (hex-encode (hash/final hash))
                 "B5D4045C3F466FA91FE2CC6ABE79232A1A57CDF104F7A26E716E0A1E2789DF78"))

  (let [hash2 (assert (hash/copy hash))]
    (assert (= (hash/name hash2) "SHA-256"))
    (assert (hash/update hash2 "message digest"))
    (assert (deep= (hex-encode (hash/final hash2))
                   "F7846F55CF23E14EEBEAB5B4E1550CAD5B509E3348FBC4EFA3A1413D393CB650"))))

(end-suite)
