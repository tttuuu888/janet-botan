(use ../build/botan)
(use spork/test)

(start-suite "mpi")

(let [mpi1 (assert (mpi/new-from-int 1))
      mpi2 (assert (mpi/new-from-int 1))
      mpi3 (assert (mpi/new-from-mpi mpi1))
      mpi4 (assert (mpi/new-from-str "1"))
      mpi5 (assert (mpi/new-from-hex-str "01"))

      mpi6 (assert (mpi/new-from-int 2))
      mpi7 (assert (mpi/new-from-rng (rng/new) 16))
      mpi8 (assert (mpi/new-from-int 0))

      mpi9  (assert (:lshift mpi1 1))]
  (assert (= (mpi/new) (mpi/new-from-int 0)))
  (assert (= mpi1 mpi2 mpi3 mpi4 mpi5))
  (assert (not (= mpi6 mpi7 mpi8)))
  (assert (< mpi1 mpi6))
  (assert (not (:is-zero mpi1)))
  (assert (:is-zero mpi8))
  (assert (:is-positive mpi1))
  (assert (not (:is-negative mpi1)))
  (assert (:is-negative (:flip-sign mpi1)))
  (assert (:is-positive (:flip-sign mpi1)))
  (assert (< mpi2 mpi7))
  (assert (:swap mpi2 mpi7))
  (assert (> mpi2 mpi7))
  (assert (= mpi9 (mpi/new-from-int (blshift 1 1))))
  (assert (= mpi1 (:rshift (:lshift mpi1 1) 1))))

(let [mpi1 (mpi/new-from-int 1)
      mpi2 (mpi/new-from-int 2)
      mpi3 (mpi/new-from-int 3)
      mpi4 (mpi/new-from-int 4)
      mpi5 (mpi/new-from-int 5)]
  (assert (= (:add mpi1 mpi2) mpi3))
  (assert (= (:add mpi1 2) mpi3))
  (assert (= (:sub mpi3 mpi1) mpi2))
  (assert (= (:sub mpi3 1) mpi2))
  (assert (= (:mul mpi2 mpi2) mpi4))
  (assert (= (:to-u32 mpi1) 1))
  (assert (= (:num-bytes mpi1) 1))
  (assert (= (:to-bin mpi1) (hex-decode "01")))
  (let [[q r] (:div mpi5 mpi2)]
    (assert (= q mpi2))
    (assert (= r mpi1))))

(let [long-hex-input "0102030405060708090a0b0c0d0e0f"
      mpi1 (mpi/new-from-hex-str long-hex-input)]
  (assert-error "Error expected" (:to-u32 mpi1))
  (assert (= (:to-bin mpi1)) (hex-decode long-hex-input)))

(end-suite)
