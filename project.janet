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

(def project-path (os/cwd))

(rule "botan-library" ["./botan"]
      (unless (and (os/stat "./botan/libbotan-3.a")
                   (os/stat "./botan/libbotan-3.so.5"))
        (os/cd "botan")
        (print "Build botan library...")
        (unless (os/stat "build")
          (os/execute ["./configure.py" "--without-documentation"] :p))
        (os/execute ["make" "-j8"] :p)
        (os/cd project-path)))

(rule "botan-header" ["botan-library"]
      (unless (os/stat "botan/build.h")
        (os/cd project-path)
        (print "Copy botan header...")
        (copyfile "botan/build/build.h" "botan/build.h")))

(rule "pre-install" ["build"]
      (os/execute ["./pre_install.sh"] :p))

(add-dep "build" "botan-header")
(add-dep "build/src___main.o" "botan-header")
(add-dep "install" "pre-install")
