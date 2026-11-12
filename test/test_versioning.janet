(use ../build/botan)
(use spork/test)

(start-suite "Versioning")

(let [ver-str   "Botan 3.14.1"
      ver-ffi   20261104
      ver-major 3
      ver-minor 14
      ver-patch 1
      ver-date  0]
  (assert (string/has-prefix? ver-str (version-string)))
  (assert (= (ffi-api-version) ver-ffi))
  (assert (ffi-supports-api (ffi-api-version)))
  (assert (= (version-major) ver-major))
  (assert (= (version-minor) ver-minor))
  (assert (= (version-patch) ver-patch))
  (assert (= (version-datestamp) ver-date)))

# Janet-botan currently builds Botan without the ffi_tls module
(assert (= (ffi-tls-api-version) 0))
(assert (not (ffi-tls-supports-api 20260916)))
(assert (not (ffi-tls-supports-api 0)))

(end-suite)
