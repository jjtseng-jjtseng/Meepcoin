#!/usr/bin/env python3
"""Wire the frozen MeepHash-W v2 library into the MeepCoin (Monero-derived) daemon build.

Idempotent: safe to re-run. Consumes meepow/ as a LIBRARY via add_subdirectory so the daemon
compiles the exact frozen sources rather than a vendored snapshot that could drift.
"""
import sys, os

ROOT = os.path.expanduser("~/meepcoin-node")


def patch(path, old, new, label, required=True):
    p = os.path.join(ROOT, path)
    s = open(p).read()
    if new in s:
        print(f"  = {label} (already applied)")
        return True
    if old not in s:
        if required:
            print(f"  ! {label} ANCHOR NOT FOUND")
            return False
        print(f"  - {label} (anchor absent, skipped)")
        return True
    open(p, "w").write(s.replace(old, new, 1))
    print(f"  + {label}")
    return True


ok = True

# 1) collapse the duplicated PUBLIC keyword introduced when linking meepow_v2 into cncrypto
ok &= patch(
    "src/crypto/CMakeLists.txt",
    "target_link_libraries(cncrypto\n    PUBLIC\n      meepow_v2\n  PUBLIC\n    epee",
    "target_link_libraries(cncrypto\n  PUBLIC\n    meepow_v2\n    epee",
    "cncrypto link line tidied",
    required=False,
)

# 2) build the frozen meepow libraries as part of the daemon build
MEEPOW_BLOCK = """# --- MeepCoin: frozen MeepHash-W v2 consensus library -----------------------------------------
# Consumed from the meepcoin repository as a LIBRARY, not vendored, so the daemon compiles the
# exact frozen sources (git tag v2-frozen) and cannot drift from the committed vectors.
set(MEEPCOIN_MEEPOW_DIR "$ENV{MEEPCOIN_MEEPOW_DIR}" CACHE PATH "Path to the meepcoin meepow/ tree")
if(NOT MEEPCOIN_MEEPOW_DIR)
  set(MEEPCOIN_MEEPOW_DIR "/mnt/c/Users/tseng/meepcoin/meepow")
endif()
if(NOT EXISTS "${MEEPCOIN_MEEPOW_DIR}/include/meepow/v2.hpp")
  message(FATAL_ERROR "MEEPCOIN_MEEPOW_DIR is not a meepow tree: ${MEEPCOIN_MEEPOW_DIR}")
endif()
set(MEEPOW_LIB_ONLY ON CACHE BOOL "" FORCE)
set(MEEPOW_BLAKE3_PORTABLE ON CACHE BOOL "" FORCE)
add_subdirectory(${MEEPCOIN_MEEPOW_DIR} meepow_build)
message(STATUS "MeepCoin PoW: MeepHash-W v2 from ${MEEPCOIN_MEEPOW_DIR}")

"""
ok &= patch("CMakeLists.txt", "add_subdirectory(contrib)",
            MEEPOW_BLOCK + "add_subdirectory(contrib)", "meepow library added to build")

print("BUILD_PATCH_OK" if ok else "BUILD_PATCH_FAILED")
sys.exit(0 if ok else 1)
