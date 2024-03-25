(use ../build/botan)
(use spork/test)

(start-suite "Symmetric Ciphers")

(assert-error "Error expected" (cipher/new "AES-127/CBC/PKCS7" :encrypt))

(let [cipher (assert (cipher/new "AES-128/CBC/PKCS7" :encrypt))
      decrypt-cipher (assert (cipher/new "AES-128/CBC" :decrypt))
      cipher-aes-128-gcm (assert (cipher/new "AES-128/GCM" :encrypt))
      key (hex-decode "898BE9CC5004ED0FA6E117C9A3099D31")
      nonce (hex-decode "9DEA7621945988F96491083849B068DF")
      plain (hex-decode "0397F4F6820B1F9386F14403BE5AC16E50213BD473B4874B9BCBF5F318EE686B1D")
      encrypted (hex-decode "E232CD6EF50047801EE681EC30F61D53CFD6B0BCA02FD03C1B234BAA10EA82AC9DAB8B960926433A19CE6DEA08677E34")]

  (assert (= (cipher/name cipher) "AES-128/CBC/PKCS7"))

  (let [[min-key max-key mod-key] (cipher/get-keyspec cipher)]
    (assert (= min-key 16))
    (assert (= max-key 16))
    (assert (= mod-key 1)))

  (assert (cipher/set-key cipher key))

  (assert-error "Error expected" (cipher/set-associated-data cipher nonce))

  (assert (not (cipher/is-authenticated cipher)))
  (assert (= (cipher/get-tag-length cipher) 0))
  (assert (= (cipher/get-default-nonce-length cipher) 16))
  (assert (= (cipher/get-update-granularity cipher) 16))
  (assert (cipher/valid-nonce-length cipher 16))
  (assert (not (cipher/valid-nonce-length cipher 1)))

  (assert (cipher/clear cipher))
  (assert (cipher/set-key cipher key))
  (assert (cipher/start cipher nonce))
  (assert (= (cipher/finish cipher plain) encrypted))

  (assert (not (cipher/is-authenticated cipher)))

  (assert (cipher/set-key decrypt-cipher key))
  (assert (cipher/start decrypt-cipher nonce))
  (assert (= (cipher/finish decrypt-cipher encrypted) plain))

  (assert (= (cipher/get-default-nonce-length cipher-aes-128-gcm) 12))
  (assert (cipher/valid-nonce-length cipher-aes-128-gcm 12))
  (assert (= (cipher/get-tag-length cipher-aes-128-gcm) 16))
  (assert (cipher/is-authenticated cipher-aes-128-gcm)))

(end-suite)
