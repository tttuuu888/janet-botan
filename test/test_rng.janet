(use ../build/botan)
(use spork/test)

(start-suite "rng")

(assert (deep-not= (rng/generate 30) (rng/generate 30)))

(let [rng (rng/create)]
  (assert (not (rng/reseed rng 32)))
  (rng/destroy rng))

(let [rng (rng/create)]
  (assert (not (rng/reseed rng 32)))
  (rng/destroy rng))

(let [rng (rng/create)
      rng-src (rng/create)]
  (assert (not (rng/reseed-from-rng rng rng-src 32)))
  (map rng/destroy [rng rng-src]))

(let [rng (rng/create)
     seed (range 8)]
  (assert (not (rng/add-entropy rng (string/from-bytes ;seed))))
  (rng/destroy rng))

(end-suite)
