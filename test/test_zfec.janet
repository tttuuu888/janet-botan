(use ../build/botan)
(use spork/test)

(start-suite "ZFEC Forward Error Correction")

(let [k 3
      n 11
      input "Does this work?AAAAAAAAAAAAAAAzzzzzzzzzzzzzzz"]

  (def encoded (assert (zfec-encode k n input)))
  (def decoded (zfec-decode k n [0 1 2 3 4 5 6 7 8 9 10] encoded))
  (assert (= input (string/join decoded)))

  (let [indexes [1 2 3]
        inputs (tuple ;(map (fn [x] (x encoded)) indexes))]
    (assert (= input (string/join (zfec-decode k n indexes inputs)))))

  (let [indexes [3 2 1]
        inputs (tuple ;(map (fn [x] (x encoded)) indexes))]
    (assert (= input (string/join (zfec-decode k n indexes inputs)))))

  (let [indexes [8 9 10]
        inputs (tuple ;(map (fn [x] (x encoded)) indexes))]
    (assert (= input (string/join (zfec-decode k n indexes inputs))))))

(end-suite)
