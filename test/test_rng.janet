(use ../build/botan)
(use spork/test)

(start-suite "random")

(assert (deep-not= (rng-get 30) (rng-get 30)))

(end-suite)
