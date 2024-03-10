(use ../build/botan)
(use spork/test)

(start-suite "mac")

(assert-error "Error expected" (mac/init "HMAC(SHA-255)"))

(let [mac (assert (mac/init "HMAC(SHA-256)"))]
  (assert (= (mac/output-length mac) 32))
  (let [[min-key max-key mod-key] (mac/get-keyspec mac)]
    (assert (= min-key 0))
    (assert (= max-key 4096))
    (assert (= mod-key 1)))

  (assert (not (mac/set-key mac (hex-decode "AABBCCDD"))))
  (assert (not (mac/update mac "ABC")))
  (assert (deep= (hex-encode (mac/final mac))
                 "1A82EEA984BC4A7285617CC0D05F1FE1D6C96675924A81BC965EE8FF7B0697A7"))

  (assert (not (mac/update mac "ABC")))
  (assert (deep= (hex-encode (mac/final mac))
                 "1A82EEA984BC4A7285617CC0D05F1FE1D6C96675924A81BC965EE8FF7B0697A7"))

  (assert (not (mac/clear mac)))
  (assert-error "Error expected" (mac/update mac "ABC"))
  (assert (not (mac/set-key mac (hex-decode "AABBCCDD"))))
  (assert (not (mac/update mac "ABC")))
  (assert (deep= (hex-encode (mac/final mac))
                 "1A82EEA984BC4A7285617CC0D05F1FE1D6C96675924A81BC965EE8FF7B0697A7"))

  (assert (not (mac/destroy mac))))

(let [mac (assert (mac/init "GMAC(AES-128)"))]
  (assert (not (mac/set-key mac (hex-decode "000102030405060708090A0B0C0D0E0F"))))
  (assert (not (mac/set-nonce mac (hex-decode "FFFFFFFFFFFFFFFFFFFFFFFF"))))
  (assert (not (mac/update mac (hex-decode "102030405060708090A0B0C0D0E0F000"))))
  (assert (deep= (hex-encode (mac/final mac))
                 "0474FA92425A16FA4404824A00398C74"))
  (assert (not (mac/destroy mac))))

(end-suite)
