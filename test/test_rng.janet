(use ../build/botan)
(use spork/test)

(start-suite "rng")

(assert (deep-not= (rng/get 30) (rng/get 30)))

(let [rng (rng/init)]
  (assert (not (rng/reseed rng 32)))
  (rng/destroy rng))

(let [rng (rng/init)]
  (assert (not (rng/reseed rng 32)))
  (rng/destroy rng))

(let [rng (rng/init)
      rng-src (rng/init)]
  (assert (not (rng/reseed-from-rng rng rng-src 32)))
  (map rng/destroy [rng rng-src]))

(let [rng (rng/init)
     seed (range 8)]
  (assert (not (rng/add-entropy rng (string/from-bytes ;seed))))
  (rng/destroy rng))

(end-suite)
