(declare-project
 :name "botan-janet"
 :description "Janet bindings to Botan."
 :url "https://github.com/tttuuu888/botan-janet"
 :author "Seungki Kim <tttuuu888@gmail.com>"
 :dependencies ["spork"])

(declare-native
 :name "botan-janet"
 :cflags ["-I." "-I./botan/build/include/public/botan" ;default-cflags]
 :lflags ["-L./botan" "-l:libbotan-3.a" "-lstdc++"]
 :source ["src/main.c"])


(import spork/sh)

(rule "botan/libbotan-3.a" ["botan/libbotan-3.a"]
      (do
        (os/cd "botan")
        (unless (os/stat "build")
          (os/execute ["./configure.py"] :p))
        (assert
         (zero?
          (os/execute ["make"] :p)))))

(rule "botan/botan.h" []
      (sh/copy "./botan/build/build.h" "./botan/"))

(add-dep "build" "botan/libbotan-3.a")
(add-dep "build" "botan/botan.h")
