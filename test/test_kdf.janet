(use ../build/botan)
(use spork/test)

(start-suite "kdf")

(assert (= (hex-encode (kdf "HKDF(HMAC(SHA-256))"
                            42
                            (hex-decode "0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B")
                            (hex-decode "000102030405060708090A0B0C")
                            (hex-decode "F0F1F2F3F4F5F6F7F8F9")))
           "3CB25F25FAACD57A90434F64D0362F2A2D2D0A90CF1A5A4C5DB02D56ECC4C5BF34007208D5B887185865"))

(assert (= (hex-encode (kdf "HKDF-Extract(HMAC(SHA-256))"
                            32
                            (hex-decode "0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B")
                            (hex-decode "000102030405060708090A0B0C")))
           "077709362C2E32DF0DDC3F0DC47BBA6390B6C73BB50F9C3122EC844AD7C2B3E5"))

(end-suite)
