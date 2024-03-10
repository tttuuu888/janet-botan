(use ../build/botan)
(use spork/test)

(start-suite "utility")

(assert (constant-time-compare "abc" "abc"))
(assert (not (constant-time-compare "abc" "bcd")))
(assert (not (constant-time-compare "abc" "abcd")))

(assert (deep= (hex-encode "abcd") "61626364"))
(assert (deep= (hex-decode "61626364") "abcd"))

(end-suite)
