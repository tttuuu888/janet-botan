(use ../build/botan)
(use spork/test)

(start-suite "EC Points")

# identity / generator
(let [grp (ec-group/from-name "secp256r1")
      id (assert (ec-point/identity grp))
      g (assert (ec-point/generator grp))]
  (assert (:is-identity id))
  (assert (not (:is-identity g)))
  (assert (deep-not= id g)))

# from-xy with the group's generator coordinates equals generator
(let [grp (ec-group/from-name "secp256r1")
      g (ec-point/generator grp)
      g2 (assert (ec-point/from-xy grp (:get-gx grp) (:get-gy grp)))]
  (assert (= g g2)))

# from-bytes round-trip via uncompressed and compressed
(let [grp (ec-group/from-name "secp256r1")
      g (ec-point/generator grp)
      enc-uncomp (:to-uncompressed g)
      enc-comp (:to-compressed g)
      g-from-uncomp (assert (ec-point/from-bytes grp enc-uncomp))
      g-from-comp (assert (ec-point/from-bytes grp enc-comp))]
  (assert (= g g-from-uncomp g-from-comp)))

# SEC1 prefix bytes / lengths for secp256r1
(let [grp (ec-group/from-name "secp256r1")
      g (ec-point/generator grp)
      enc-uncomp (:to-uncompressed g)
      enc-comp (:to-compressed g)
      x (:get-x g)
      y (:get-y g)
      xy (:get-xy g)]
  (assert (= 65 (length enc-uncomp)))
  (assert (= 0x04 (get enc-uncomp 0)))
  (assert (= 33 (length enc-comp)))
  (assert (or (= 0x02 (get enc-comp 0))
              (= 0x03 (get enc-comp 0))))
  (assert (= 32 (length x)))
  (assert (= 32 (length y)))
  (assert (= 64 (length xy)))
  (assert (= xy (string x y))))

# negate(negate(P)) == P, P + (-P) == identity
(let [grp (ec-group/from-name "secp256r1")
      g (ec-point/generator grp)
      id (ec-point/identity grp)
      neg-g (:negate g)
      neg-neg-g (:negate neg-g)]
  (assert (not= g neg-g))
  (assert (= (:get-x g) (:get-x neg-g)))
  (assert (not= (:get-y g) (:get-y neg-g)))
  (assert (= g neg-neg-g))
  (assert (= id (:add g neg-g))))

# G + identity == G
(let [grp (ec-group/from-name "secp256r1")
      g (ec-point/generator grp)
      id (ec-point/identity grp)]
  (assert (= g (:add g id)))
  (assert (= g (:add id g))))

# G * 1 == G, G * 2 == G + G, G * 3 == G + G + G
# (scalar 0 cannot be constructed via ec-scalar/from-mp; valid range is 1..order-1)
(let [grp (ec-group/from-name "secp256r1")
      rng (rng/new)
      g (ec-point/generator grp)
      one (ec-scalar/from-mp grp (mpi/new "1"))
      two (ec-scalar/from-mp grp (mpi/new "2"))
      three (ec-scalar/from-mp grp (mpi/new "3"))]
  (assert (= g (:mul g one rng)))
  (assert (= (:add g g) (:mul g two rng)))
  (assert (= (:add g (:add g g)) (:mul g three rng))))

# from-bytes rejects garbage
(let [grp (ec-group/from-name "secp256r1")]
  (assert-error "Error expected"
                (ec-point/from-bytes grp (string/from-bytes ;(range 10)))))

(end-suite)
