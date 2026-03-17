(use ../build/botan)
(use spork/test)

(start-suite "eXtendable Output Functions (XOF)")

(assert-error "Error expected" (xof/new "INVALID-XOF"))

(let [xof (assert (xof/new "SHAKE-128"))]
  (assert (= (xof/name xof) "SHAKE-128"))
  (assert (> (xof/block-size xof) 0))
  (assert (xof/accepts-input xof))

  (assert (xof/update xof (hex-decode "d94be6703183babe2a30331b0028193c")))
  (let [out (xof/output xof 32)]
    (assert (= (length out) 32))
    (assert (= out
               (hex-decode "0583c92e58ec7df9365dfa9ae3fab8bab0ae1a85c24cc834751a39159fe17d77"))))

  # After output, XOF no longer accept input
  (assert (not (xof/accepts-input xof)))

  # Can still request more output
  (let [out2 (xof/output xof 16)]
    (assert (= (length out2) 16))))

(let [xof (assert (xof/new "SHAKE-256"))]
  (assert (= (xof/name xof) "SHAKE-256"))

  (assert (xof/update xof (hex-decode "dc886df3f69c49513de3627e9481db5871e8ee88eb9f99611541930a8bc885e0")))
  (let [out (xof/output xof 32)]
    (assert (= out
               (hex-decode "00648afbc5e651649db1fd82936b00dbbc122fb4c877860d385c4950d56de7e0")))))

(let [xof (assert (xof/new "SHAKE-128"))]
  (assert (xof/update xof "ABC"))
  (xof/output xof 32)
  (assert (xof/clear xof))

  # After clear, XOF accept input again
  (assert (xof/accepts-input xof))

  (assert (xof/update xof (hex-decode "d94be6703183babe2a30331b0028193c")))
  (let [out (xof/output xof 32)]
    (assert (= out
               (hex-decode "0583c92e58ec7df9365dfa9ae3fab8bab0ae1a85c24cc834751a39159fe17d77")))))

(let [xof   (assert (xof/new "SHAKE-128"))
      _     (assert (xof/update xof (hex-decode "d94be6703183babe2a30331b0028193c")))
      xof2  (assert (xof/copy xof))
      _     (assert (= (xof/name xof2) "SHAKE-128"))
      out1  (xof/output xof 32)
      out2  (xof/output xof2 32)]
  (assert (= out1 out2)))

(let [xof   (assert (xof/new "Ascon-XOF128"))
      _     (assert (= (xof/name xof) "Ascon-XOF128"))
      _     (assert (xof/update xof (hex-decode "b97478ce249b899f010195e709636901")))
      out   (xof/output xof 32)]
  (assert out
          (hex-decode "c6cd1bf440b71f124da6dae310e15e2ead208798604a6371dfda5c4a34548c64")))

(end-suite)
