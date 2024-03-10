(use ../build/botan)
(use spork/test)

(start-suite "rng")

(assert (deep-not= (rng/get 30) (rng/get 30)))

(let [rng-ori (assert (rng/init))
      rng-src (assert (rng/init))
      seed (range 8)]
  (assert (not (rng/reseed rng-ori 32)))
  (assert (not (rng/reseed-from-rng rng-ori rng-src 32)))
  (assert (not (rng/add-entropy rng-ori (string/from-bytes ;seed))))
  (assert (not (rng/destroy rng-ori)))
  (assert (not (rng/destroy rng-src))))

(end-suite)
