(use ../build/botan)
(use spork/test)

(start-suite "EC Scalars")

(let [grp (ec-group/from-name "secp256r1")
      rng (rng/new)
      s1 (assert (ec-scalar/random grp rng))
      s2 (assert (ec-scalar/random grp rng))]
  # Two random scalars are extremely unlikely to be equal
  (assert (deep-not= (:to-mp s1) (:to-mp s2))))

# from-mp / to-mp round trip
(let [grp (ec-group/from-name "secp256r1")
      mp (mpi/new "1234567890ABCDEF" 16)
      sc (assert (ec-scalar/from-mp grp mp))]
  (assert (= mp (:to-mp sc))))

# Scalar 0 is out of range (allowed range is 1..order-1)
(let [grp (ec-group/from-name "secp256r1")
      zero (mpi/new "0")]
  (assert-error "Error expected" (ec-scalar/from-mp grp zero)))

# Negative MPI must be rejected
(let [grp (ec-group/from-name "secp256r1")
      neg (:flip-sign (mpi/new "1"))]
  (assert-error "Error expected" (ec-scalar/from-mp grp neg)))

# MPI equal to or larger than the group order must be rejected
(let [grp (ec-group/from-name "secp256r1")
      order (:get-order grp)
      too-big (:add order (mpi/new "1"))]
  (assert-error "Error expected" (ec-scalar/from-mp grp order))
  (assert-error "Error expected" (ec-scalar/from-mp grp too-big)))

(end-suite)
