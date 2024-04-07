(use ../build/botan)
(use spork/test)

(start-suite "SRP6 Server Session")


(let [identity "userid"
      password "userpassword1234"
      rng (rng/new)
      group "modp/srp/1024"
      hash "SHA-512"

      server (srp6-server-session/new group)
      salt (:get rng 24)
      verifier (srp6-generate-verifier identity password salt group hash)
      B (:step1 server verifier hash rng)
      [A key-c] (srp6-client-agree identity password group hash salt B)

      key-s (:step2 server A)]
  (assert (= key-c key-s))
)

(end-suite)
