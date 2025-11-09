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

(let [cipher (assert (cipher/new "AES-256/GCM" :encrypt))
      key "0000000000000000000000000000000000000000000000000000000000000000"
      nonce "000000000000000000000000"
      in "00000000000000000000000000000000"
      expected-out "CEA7403D4D606B6E074EC5D3BAF39D18D0D1C8A799996BF0265B98B5D48AB919"
      _ (assert (cipher/set-key cipher (hex-decode key)))
      _ (assert (cipher/start cipher (hex-decode nonce)))
      out (assert (cipher/finish cipher (hex-decode in)))]
  (assert (= expected-out (hex-encode out))))

(let [cipher (assert (cipher/new "AES-256/GCM" :encrypt))
      key "0000000000000000000000000000000000000000000000000000000000000000"
      nonce "000000000000000000000000"
      in1 "0000000000000000"
      in2 "0000000000000000"
      expected-out "CEA7403D4D606B6E074EC5D3BAF39D18D0D1C8A799996BF0265B98B5D48AB919"
      _ (assert (cipher/set-key cipher (hex-decode key)))
      _ (assert (cipher/start cipher (hex-decode nonce)))
      out1 (assert (cipher/update cipher (hex-decode in1)))
      out2 (assert (cipher/finish cipher (hex-decode in2)))]
  (assert (= expected-out (hex-encode (string out1 out2)))))

(let [cipher (assert (cipher/new "AES-256/GCM" :encrypt))
      key "FEFFE9928665731C6D6A8F9467308308FEFFE9928665731C6D6A8F9467308308"
      nonce "CAFEBABEFACEDBADDECAF888"
      ad "FEEDFACEDEADBEEFFEEDFACEDEADBEEFABADDAD2"
      in "D9313225F88406E5A55909C5AFF5269A86A7A9531534F7DA2E4C303D8A318A721C3C0C95956809532FCF0E2449A6B525B16AEDF5AA0DE657BA637B39"
      expected-out "522DC1F099567D07F47F37A32A84427D643A8CDCBFE5C0C97598A2BD2555D1AA8CB08E48590DBB3DA7B08B1056828838C5F61E6393BA7A0ABCC9F66276FC6ECE0F4E1768CDDF8853BB2D551B"
      _ (assert (cipher/set-key cipher (hex-decode key)))
      _ (assert (cipher/set-associated-data cipher (hex-decode ad)))
      _ (assert (cipher/start cipher (hex-decode nonce)))
      out (assert (cipher/finish cipher (hex-decode in)))]
  (assert (= expected-out (hex-encode out))))

(let [cipher (assert (cipher/new "ARIA-256/GCM" :encrypt))
      key "0C5FFD37A11EDC42C325287FC0604F2E3E8CD5671A00FE3216AA5EB105783B54"
      nonce "000020E8F5EB00000000315E"
      ad "8008315EBF2E6FE020E8F5EB"
      in "F57AF5FD4AE19562976EC57A5A7AD55A5AF5C5E5C5FDF5C55AD57A4A7272D57262E9729566ED66E97AC54A4A5A7AD5E15AE5FDD5FD5AC5D56AE56AD5C572D54AE54AC55A956AFD6AED5A4AC562957A9516991691D572FD14E97AE962ED7A9F4A955AF572E162F57A956666E17AE1F54A95F566D54A66E16E4AFD6A9F7AE1C5C55AE5D56AFDE916C5E94A6EC56695E14AFDE1148416E94AD57AC5146ED59D1CC5"
      expected-out "6F9E4BCBC8C85FC0128FB1E4A0A20CB9932FF74581F54FC013DD054B19F99371425B352D97D3F337B90B63D1B082ADEEEA9D2D7391897D591B985E55FB50CB5350CF7D38DC27DDA127C078A149C8EB98083D66363A46E3726AF217D3A00275AD5BF772C7610EA4C23006878F0EE69A8397703169A419303F40B72E4573714D19E2697DF61E7C7252E5ABC6BADE876AC4961BFAC4D5E867AFCA351A48AED52822E210D6CED2CF430FF841472915E7EF48"
      _ (assert (cipher/set-key cipher (hex-decode key)))
      _ (assert (cipher/set-associated-data cipher (hex-decode ad)))
      _ (assert (cipher/start cipher (hex-decode nonce)))
      out (assert (cipher/finish cipher (hex-decode in)))]
  (assert (= expected-out (hex-encode out))))

(let [cipher (assert (cipher/new "SM4/GCM" :encrypt))
      key "0123456789ABCDEFFEDCBA9876543210"
      nonce "00001234567800000000ABCD"
      ad "FEEDFACEDEADBEEFFEEDFACEDEADBEEFABADDAD2"
      in "AAAAAAAAAAAAAAAABBBBBBBBBBBBBBBBCCCCCCCCCCCCCCCCDDDDDDDDDDDDDDDDEEEEEEEEEEEEEEEEFFFFFFFFFFFFFFFFEEEEEEEEEEEEEEEEAAAAAAAAAAAAAAAA"
      expected-out "17F399F08C67D5EE19D0DC9969C4BB7D5FD46FD3756489069157B282BB200735D82710CA5C22F0CCFA7CBF93D496AC15A56834CBCF98C397B4024A2691233B8D83DE3541E4C2B58177E065A9BF7B62EC"
      _ (assert (cipher/set-key cipher (hex-decode key)))
      _ (assert (cipher/set-associated-data cipher (hex-decode ad)))
      _ (assert (cipher/start cipher (hex-decode nonce)))
      out (assert (cipher/finish cipher (hex-decode in)))]
  (assert (= expected-out (hex-encode out))))

(let [cipher (assert (cipher/new "3DES/CBC/NoPadding" :encrypt))
      key "08763DA862AD16EF5815408F5D3B705415AB1543A42C3EFB"
      nonce "0634D69EAFF3AE17"
      in "109A3D3D745D65B38EDBC73D1DE8B2807F7820221A6C3937FAAB19FCBB75D3C8AAF4B63F2714CFC94E95AE43D65F6DF43815EFC214EC66A5D1BE185D855A6260141FFD179BC980490F8A26D8215DD2AB"
      expected-out "E9513E8892A09085BEE29C358014AFD60D7578D21E00A31E5D61B965C18778EBE18469170794E5DDF24AA777C8AB0A2C62474109E617978BCC5CE3456DDD9622833420443C2A26B1B6E20A05C189DA6C"
      _ (assert (cipher/set-key cipher (hex-decode key)))
      _ (assert (cipher/start cipher (hex-decode nonce)))
      out (assert (cipher/finish cipher (hex-decode in)))]
  (assert (= expected-out (hex-encode out))))

(end-suite)
