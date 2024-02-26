(declare-project
 :name "botan-janet"
 :description "Janet bindings to Botan."
 :url "https://github.com/tttuuu888/botan-janet"
 :author "Seungki Kim <tttuuu888@gmail.com>")

(declare-native
 :name "botan-janet"
 :cflags ["-I." "-Ibotan/build/include/public/botan" ;default-cflags]
 :lflags ["-Lbotan" "-l:libbotan-3.a" "-lstdc++"]
 :source ["src/main.c"])

(def project-path (os/cwd))

(rule "botan-library" ["./botan"]
      (unless (os/stat "./botan/libbotan-3.a")
        (print "Build botan library...")
        (os/cd project-path)
        (os/cd "botan")
        (unless (os/stat "build")
          (os/execute ["./configure.py" "--without-documentation"] :p))
        (os/execute ["make" "-j8"] :p)
        (os/cd project-path)))

(rule "botan-header" ["botan-library"]
      (unless (os/stat "botan/build.h")
        (print "Copy botan header...")
        (os/cd project-path)
        (copyfile "botan/build/build.h" "botan/build.h")))

(task "build-botan" ["botan-header"])

(add-dep "build" "build-botan")
