#!/bin/bash

# Create merged static library from .static.o and libbotan-3.a
ar rcs janet_botan.a build/src___main.static.o build/x509_ext.o

ar -M <<EOM
    CREATE botan.a
    ADDLIB janet_botan.a
    ADDLIB botan/libbotan-3.a
    SAVE
    END
EOM

mv botan.a build/botan.a
rm -f janet_botan.a

# Update botan.meta.janet
cat <<EOT > build/botan.meta.janet
# Metadata for static library botan.a

{ :cpp false
  :ldflags (quote nil)
  :lflags (quote ("-lstdc++"))
  :static-entry "janet_module_entry_botan"}
EOT
