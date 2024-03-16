(use ../build/botan)
(use spork/test)

(start-suite "rng")

(let [rng-ori (assert (rng/new))
      rng-src (assert (rng/new))
      seed (range 8)]
  (assert (deep-not= (:get rng-ori 30) (:get rng-src 30)))
  (assert (not (rng/reseed rng-ori 32)))
  (assert (not (rng/reseed-from-rng rng-ori rng-src 32)))
  (assert (not (rng/add-entropy rng-ori (string/from-bytes ;seed)))))

(end-suite)
