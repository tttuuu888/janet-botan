#!/bin/bash

# Merge libbotan-3.a and botan.a
ar -M <<EOM
    CREATE botan.a
    ADDLIB build/botan.a
    ADDLIB botan/libbotan-3.a
    SAVE
    END
EOM

mv botan.a build/botan.a

# Update botan.meta.janet
cat <<EOT > build/botan.meta.janet
# Metadata for static library botan.a

{ :cpp false
  :ldflags (quote nil)
  :lflags (quote ("-lstdc++"))
  :static-entry "janet_module_entry_botan"}
EOT
