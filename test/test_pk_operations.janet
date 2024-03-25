(use ../build/botan)
(use spork/test)

(start-suite "Public Key Operations")

(let [prikey (privkey/new "RSA" "1024")
      pubkey (:get-pubkey prikey)
      pk-enc (pk-encrypt/new pubkey "OAEP(SHA-256)")
      pk-dec (pk-decrypt/new prikey "OAEP(SHA-256)")
      pk-sig (pk-sign/new prikey "PKCS1v15(SHA-256)")
      pk-veri (pk-verify/new pubkey "PKCS1v15(SHA-256)")
      plain "plaintext"
      encrypted (:encrypt pk-enc plain)
      decrypted (:decrypt pk-dec encrypted)
      signature (:finish (:update pk-sig plain))]
  (assert (= plain decrypted))
  (assert (:finish (:update pk-veri plain) signature)))

(end-suite)
