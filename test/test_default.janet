(use ../build/botan)

(assert (= (ffi-api-version) 20231009))

(assert (= (ffi-supports-api (ffi-api-version)) 0))
