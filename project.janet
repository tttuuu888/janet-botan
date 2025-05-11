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

(rule "botan-library" ["./botan"]
      (let [project-path  (os/cwd)
            p1 (os/spawn ["git" "submodule" "status"] :p {:out :pipe})
            rev1 ((string/split " " (:read (p1 :out) :all)) 1)
            p2 (os/spawn ["/bin/sh" "-c"
                          "grep '\"version_vc_rev\"' botan/build/build_config.json | sed -E 's/.*\"version_vc_rev\": \"git:([^\"]+)\".*/\\1/'"]
                         :p {:out :pipe})
            rev2 (string/trim (:read (p2 :out) :all))]

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
