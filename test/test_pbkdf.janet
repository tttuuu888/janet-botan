(use ../build/botan)
(use spork/test)

(start-suite "pbkdf")

(assert (= (hex-encode (pbkdf "PBKDF2(SHA-256)" "abcd" 32 1001
                              (hex-decode "102030405060708090A0B0C0D0E0F000")))
           (hex-encode (pbkdf "PBKDF2(SHA-256)" "abcd" 32 1001
                              (hex-decode "102030405060708090A0B0C0D0E0F000")))
           "DECF9EF197B87ABBDB6CBA9E81A7BCB8AC36BB2BFA3B93746C8042227A27CFEA"))

(assert (not= (pbkdf "PBKDF2(SHA-256)" "abcd" 32)
              (pbkdf "PBKDF2(SHA-256)" "abcd" 32)))

(end-suite)
