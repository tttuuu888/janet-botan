(declare-project
 :name "botan"
 :description "Janet bindings to Botan."
 :author "Seungki Kim <tttuuu888@gmail.com>"
 :license "MIT"
 :url "https://github.com/tttuuu888/janet-botan"
 :repo "git+https://github.com/tttuuu888/janet-botan"
 :dependencies ["spork"])

(declare-native
 :name "botan"
 :cflags ["-I." "-Ibotan/build/include/public/botan" "-Wall" ;default-cflags]
 :lflags ["-Lbotan" "-l:libbotan-3.a" "-lstdc++"]
 :source ["src/main.c"])

(import spork/json)

(rule "botan-library" ["./botan"]
      (let [project-path  (os/cwd)
            p (os/spawn ["git" "submodule" "status"] :p {:out :pipe})
            rev1 ((string/split " " (:read (p :out) :all)) 1)
            f (file/open "botan/build/build_config.json")
            j (and f (json/decode (file/read f :all)))
            rev2 (and f j (last (string/split ":" (j "version_vc_rev"))))]
        (and f (file/close f))

        (unless (= rev1 rev2)
          (print "Initializing Botan library build...")
          (os/execute ["git" "submodule" "update" "--recursive"] :p)
          (os/cd "botan")
          (os/execute ["./configure.py" "--without-documentation"] :p)
          (os/execute ["make" "clean"] :p)
          (os/cd project-path))

        (print "Build botan library...")
        (os/cd "botan")
        (os/shell "make -j$(nproc)")
        (os/cd project-path)

        (unless (os/stat "botan/build.h")
          (print "Copy botan header...")
          (copyfile "botan/build/build.h" "botan/build.h"))))

(rule "pre-install" ["build"]
      (os/execute ["./pre_install.sh"] :p))

(add-dep "build" "botan-library")
(add-dep "build/src___main.o" "botan-library")
(add-dep "install" "pre-install")
