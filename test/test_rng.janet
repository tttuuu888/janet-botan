(use ../build/botan)
(use spork/test)

(start-suite "rng")

(assert (deep-not= (rng/generate 30) (rng/generate 30)))

(end-suite)
