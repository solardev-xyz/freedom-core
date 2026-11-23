# COL-2's trial of a build without the call verifier (design 0014, "The call
# verifier"): CI points CMAKE_TOOLCHAIN_FILE here, which CMake reads from the
# environment, so the cache entry exists before Colibri's
# option(ETH_CALL ...) runs, and the option keeps it. Not a toolchain: it
# only presets this one option.
set(ETH_CALL OFF CACHE BOOL "COL-2 trial: leave out the call verifier and evmone" FORCE)
