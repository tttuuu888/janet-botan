(use ../build/botan)
(use spork/test)

(start-suite "versioning")

(assert (= (ffi-api-version) 20231009))

(assert (= (ffi-supports-api (ffi-api-version)) 0))

(assert (= (string/slice (version-string) 0 11) "Botan 3.3.0"))

(assert (= (version-major) 3))

(assert (= (version-minor) 3))

(assert (= (version-patch) 0))

(assert (= (version-datestamp) 0))

(end-suite)
