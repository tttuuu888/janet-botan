(use ../build/botan)
(use spork/test)

(start-suite "Versioning")

(let [ver-str   "Botan 3.13.0"
      ver-ffi   20260811
      ver-major 3
      ver-minor 13
      ver-patch 0
      ver-date  0]
  (assert (string/has-prefix? ver-str (version-string)))
  (assert (= (ffi-api-version) ver-ffi))
  (assert (ffi-supports-api (ffi-api-version)))
  (assert (= (version-major) ver-major))
  (assert (= (version-minor) ver-minor))
  (assert (= (version-patch) ver-patch))
  (assert (= (version-datestamp) ver-date)))

(end-suite)
