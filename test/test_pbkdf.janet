(use ../build/botan)
(use spork/test)

(start-suite "pbkdf")

(let [salt (hex-decode "102030405060708090A0B0C0D0E0F000")
      expected-output (hex-decode "DECF9EF197B87ABBDB6CBA9E81A7BCB8AC36BB2BFA3B93746C8042227A27CFEA")]
  (assert (= (pbkdf "PBKDF2(SHA-256)" "abcd" 32 1001 salt)
             (pbkdf "PBKDF2(SHA-256)" "abcd" 32 1001 salt)
             [salt 1001 expected-output])))

(assert (not= (pbkdf "PBKDF2(SHA-256)" "abcd" 32)
              (pbkdf "PBKDF2(SHA-256)" "abcd" 32)))

(let [[salt iter psk] (pbkdf-timed "PBKDF2(SHA-256)" "abcd" 32 10)]
  (assert (= [salt iter psk]
             (pbkdf "PBKDF2(SHA-256)" "abcd" 32 iter salt))))

(end-suite)
