(use ../build/botan)
(use spork/test)

(start-suite "Utility")

(assert (constant-time-compare "abc" "abc"))
(assert (not (constant-time-compare "abc" "bcd")))
(assert (not (constant-time-compare "abc" "abcd")))

(assert (= (hex-encode "abcd") "61626364"))
(assert (= (hex-decode "61626364") "abcd"))

(assert (= (base64-encode "abcd") "YWJjZA=="))
(assert (= (base64-decode "YWJjZA==") "abcd"))
(assert (= (base64-decode (base64-encode "abcd")) "abcd"))

(assert (= (base64-encode (hex-decode "68656C6C6F20776F726C64"))
           "aGVsbG8gd29ybGQ="))

(assert (= (base64-decode "aGVsbG8gd29ybGQ=")
           (hex-decode "68656C6C6F20776F726C64")))

(end-suite)
