(use ../build/botan)
(use spork/test)

(start-suite "Public Key Operations")

(let [prikey (privkey/new "RSA" "1024")
      pubkey (:get-pubkey prikey)
      pk-enc (pk-encrypt/new pubkey "OAEP(SHA-256)")
      pk-dec (pk-decrypt/new prikey "OAEP(SHA-256)")
      plain "plaintext"
      encrypted (:encrypt pk-enc plain)
      decrypted (:decrypt pk-dec encrypted)]
  (assert (= plain decrypted)))

(end-suite)
