(use ../build/botan)
(use spork/test)

(start-suite "Random Number Generators")

(let [rng-ori (assert (rng/new))
      rng-src (assert (rng/new))
      seed (range 8)]
  (assert (deep-not= (:get rng-ori 30) (:get rng-src 30)))
  (assert (rng/reseed rng-ori 32))
  (assert (rng/reseed-from-rng rng-ori rng-src 32))
  (assert (rng/add-entropy rng-ori (string/from-bytes ;seed))))

(let [rng-user (assert (rng/new :user))
      rng-user-threadsafe (assert (rng/new :user-threadsafe))
      rng-null (assert (rng/new :null))]
  (assert (:get rng-user 32))
  (assert (:get rng-user-threadsafe 32))
  (assert-error "Error expected" (:get rng-null 32))
  (assert-error "Error expected" (rng/new :unknown-keyword)))

(end-suite)
