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
            peg-rev '{:vc `"version_vc_rev": "git:`
                      :main (sequence (to :vc) :vc
                               (capture (sequence (any :w) (any :d))))}
            p2 (file/open "botan/build/build_config.json")
            rev2 (and p2 (first (peg/match peg-rev (file/read p2 :all))))]
        (when p2 (file/close p2))

        (unless (= rev1 rev2)
          (print "Initializing Botan library build...")
          (os/execute ["git" "submodule" "update" "--recursive"] :p)
          (os/cd "botan")
          (os/execute ["./configure.py"
                       "--without-documentation"
                       "--build-targets=static"] :p)
          (os/execute ["make" "clean"] :p)
          (os/cd project-path))

        (print "Build botan library...")
        (os/cd "botan")
        (os/shell "make -j$(nproc)")
        (os/cd project-path)))

(rule "pre-install" ["build"]
      (os/execute ["./pre_install.sh"] :p))

(rule "remove-pre-botan-a" []
      (os/execute ["rm" "-f" "build/botan.a"] :p))

(add-dep "botan-library" "remove-pre-botan-a")
(add-dep "build/src___main.o" "botan-library")
(add-dep "install" "pre-install")
