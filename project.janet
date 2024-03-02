(declare-project
 :name "botan"
 :description "Janet bindings to Botan."
 :url "https://github.com/tttuuu888/botan-janet"
 :author "Seungki Kim <tttuuu888@gmail.com>"
 :dependencies ["spork"])

(declare-native
 :name "botan"
 :cflags ["-I." "-Ibotan/build/include/public/botan" ;default-cflags]
 :lflags ["-Lbotan" "-l:libbotan-3.a" "-lstdc++"]
 :source ["src/main.c"])

(def project-path (os/cwd))

(rule "botan-library" ["./botan"]
      (unless (and (os/stat "./botan/libbotan-3.a")
                   (os/stat "./botan/libbotan-3.so.3"))
        (os/cd "botan")
        (print "Build botan library...")
        (unless (os/stat "build")
          (os/execute ["./configure.py"] :p))
        (os/execute ["make" "-j8"] :p)
        (os/cd project-path)))

(rule "botan-header" ["botan-library"]
      (unless (os/stat "botan/build.h")
        (os/cd project-path)
        (print "Copy botan header...")
        (copyfile "botan/build/build.h" "botan/build.h")))

(task "build-botan" ["botan-header"])

(add-dep "build" "build-botan")
