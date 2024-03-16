(use ../build/botan)
(use spork/test)

(start-suite "bcrypt")

(let [rng (rng/new)]

  (assert (bcrypt-is-valid (hex-decode "616263")
                           (bcrypt (hex-decode "616263") rng 4)))

  (assert (not (bcrypt-is-valid (hex-decode "616264")
                                (bcrypt (hex-decode "616263") rng 4))))

  (assert (bcrypt-is-valid (hex-decode "A3")
                           "$2a$05$/OK.fbVrR/bpIqNJ5ianF.Sa7shbm4.OzKpvFnX1pQLmQW96oUlCq"))

  (assert (bcrypt-is-valid (hex-decode "303132333435363738396162636465666768696A6B6C6D6E6F707172737475767778797A4142434445464748494A4B4C4D4E4F505152535455565758595A303132333435363738396368617273206166746572203732206172652069676E6F726564")
                           "$2a$05$abcdefghijklmnopqrstuu5s2v8.iXieOjg/.AySBTTZIIVFJeBui"))

)

(end-suite)
