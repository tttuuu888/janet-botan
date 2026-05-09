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

# DRBG: same name + same seed must produce identical output
(let [seed (string/from-bytes ;(range 64))
      drbg1 (assert (rng/new-drbg "HMAC_DRBG(SHA-256)" seed))
      drbg2 (assert (rng/new-drbg "HMAC_DRBG(SHA-256)" seed))]
  (assert (deep= (:get drbg1 32) (:get drbg2 32)))
  (assert (deep= (:get drbg1 64) (:get drbg2 64))))

# DRBG: different seed -> different output
(let [seed-a (string/from-bytes ;(range 64))
      seed-b (string/from-bytes ;(map |(- 255 $) (range 64)))
      drbg-a (assert (rng/new-drbg "HMAC_DRBG(SHA-256)" seed-a))
      drbg-b (assert (rng/new-drbg "HMAC_DRBG(SHA-256)" seed-b))]
  (assert (deep-not= (:get drbg-a 32) (:get drbg-b 32))))

# DRBG: works with other underlying hashes
(let [seed (string/from-bytes ;(range 64))
      drbg (assert (rng/new-drbg "HMAC_DRBG(SHA-512)" seed))]
  (assert (:get drbg 32))
  (assert (rng/add-entropy drbg (string/from-bytes ;(range 16)))))

# DRBG: invalid name must fail
(assert-error "Error expected"
              (rng/new-drbg "Not_A_DRBG" (string/from-bytes ;(range 64))))

(end-suite)
