# This is embedded, so all botann functions are available

(defn random
  "Get `n` bytes of random using rng"
  [n]
  (:get (rng/new) n))
