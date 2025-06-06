(use ../build/botan)
(use spork/test)

(start-suite "Versioning")

(let [ver-str   "Botan 3.8.1"
      ver-ffi   20250506
      ver-major 3
      ver-minor 8
      ver-patch 1
      ver-date  0]
  (assert (= (string/slice (version-string) 0 11) ver-str))
  (assert (= (ffi-api-version) ver-ffi))
  (assert (ffi-supports-api (ffi-api-version)))
  (assert (= (version-major) ver-major))
  (assert (= (version-minor) ver-minor))
  (assert (= (version-patch) ver-patch))
  (assert (= (version-datestamp) ver-date)))


(end-suite)
