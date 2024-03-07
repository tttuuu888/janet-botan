# This is embedded, so all botanm functions are available

(defn random
  "Get `n` bytes of random"
  [n]
  (rng/get n))
