(use ../build/botan)
(use spork/test)

(start-suite "Public Key Operations")

(let [prikey (privkey/new "RSA" "1024")
      prikey1 (privkey/new "ECDH" "secp256r1")
      prikey2 (privkey/new "ECDH" "secp256r1")
      pubkey (:get-pubkey prikey)
      pubkey1 (:get-pubkey prikey1)
      pubkey2 (:get-pubkey prikey2)
      pk-enc (pk-encrypt/new pubkey "OAEP(SHA-256)")
      pk-dec (pk-decrypt/new prikey "OAEP(SHA-256)")
      pk-sig (pk-sign/new prikey "PKCS1v15(SHA-256)")
      pk-veri (pk-verify/new pubkey "PKCS1v15(SHA-256)")
      pk-ka1 (pk-key-agreement/new prikey1 "KDF2(SHA-256)")
      pk-ka2 (pk-key-agreement/new prikey2 "KDF2(SHA-256)")
      plain "plaintext"
      encrypted (:encrypt pk-enc plain)
      decrypted (:decrypt pk-dec encrypted)
      signature (:finish (:update pk-sig plain))
      salt (:get (rng/new) 64)]
  (assert (= plain decrypted))
  (assert (:finish (:update pk-veri plain) signature))
  (assert (= (:public-value pk-ka1)
             (:get-public-point (:get-pubkey prikey1))))
  (assert (= (:agree pk-ka1 (:get-public-point pubkey2) salt)
             (:agree pk-ka2 (:get-public-point pubkey1) salt)))
  (assert (= (:agree pk-ka1 (:get-public-point pubkey2) salt 64)
             (:agree pk-ka2 (:get-public-point pubkey1) salt 64)))
  (assert (= (:agree pk-ka1 (:get-public-point pubkey2) salt 128)
             (:agree pk-ka2 (:get-public-point pubkey1) salt 128))))

(let [raw-pri "4CCD089B28FF96DA9DB6C346EC114E0F5B8A319F35ABA624DA8CF6ED4FB8A6FB"
      raw-pub "3D4017C3E843895A92B70AA74D1B7EBC9C982CCF2EC4968CC0CD55F12AF4660C"
      exp-sig "92A009A9F0D4CAB8720E820B5F642540A2B27B5416503F8FB3762223EBDB69DA085AC1E43E15996E458F3613D0F11D8C387B2EAEB4302AEEB00D291612BB0C00"
      prikey (privkey/load-ed25519 (hex-decode raw-pri))
      pubkey (pubkey/load-ed25519 (hex-decode raw-pub))
      pk-sig (pk-sign/new prikey "")
      pk-veri (pk-verify/new pubkey "")
      plain "r"
      signature (:finish (:update pk-sig plain))]
  (assert (= raw-pub
             (hex-encode (:to-raw (:get-pubkey prikey)))
             (hex-encode (:to-raw pubkey))))
  (assert (= exp-sig (hex-encode signature)))
  (assert (:finish (:update pk-veri plain) signature)))

(let [prikey (privkey/new "ML-DSA" "ML-DSA-6x5")
      pubkey (:get-pubkey prikey)
      pk-sig (pk-sign/new prikey "")
      pk-veri (pk-verify/new pubkey "")
      plain "plaintext"
      signature (:finish (:update pk-sig plain))]
  (assert (:finish (:update pk-veri plain) signature)))

(let [ml-kem-priv (privkey/new "ML-KEM" "ML-KEM-1024")
      ml-kem-pub (:get-pubkey ml-kem-priv)
      kem-enc (pk-kem-encrypt/new ml-kem-pub "KDF2(SHA-256)")
      kem-dec (pk-kem-decrypt/new ml-kem-priv "KDF2(SHA-256)")
      shared-key-len 32
      salt (:get (rng/new) 12)
      [shared-key encap-key] (:create-shared-key kem-enc salt shared-key-len)
      shared-key-d (:decrypt-shared-key kem-dec salt shared-key-len encap-key)]
  (assert (= (length shared-key) shared-key-len))
  (assert (= (length encap-key) 1568))
  (assert (= shared-key shared-key-d)))

(end-suite)
