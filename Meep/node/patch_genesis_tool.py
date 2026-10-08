#!/usr/bin/env python3
"""Install the MeepCoin genesis generator into the fork tree and give genesis a real timestamp.

Idempotent.
"""
import os, shutil, sys

ROOT = os.path.expanduser("~/meepcoin-node")
SRC = "/mnt/c/Users/tseng/meepcoin/node/meepcoin_genesis.cpp"
DST_DIR = os.path.join(ROOT, "src/meepcoin_genesis")
ok = True


def patch(path, old, new, label):
    global ok
    p = os.path.join(ROOT, path)
    s = open(p).read()
    if new in s:
        print(f"  = {label} (already)")
        return
    if old not in s:
        print(f"  ! {label} ANCHOR MISSING")
        ok = False
        return
    open(p, "w").write(s.replace(old, new, 1))
    print(f"  + {label}")


# 1) drop the tool in with its own CMakeLists
os.makedirs(DST_DIR, exist_ok=True)
shutil.copyfile(SRC, os.path.join(DST_DIR, "meepcoin_genesis.cpp"))
open(os.path.join(DST_DIR, "CMakeLists.txt"), "w").write(
    'add_executable(meepcoin-genesis meepcoin_genesis.cpp)\n'
    'target_link_libraries(meepcoin-genesis PRIVATE cryptonote_core cncrypto common epee\n'
    '  ${Boost_PROGRAM_OPTIONS_LIBRARY} ${Boost_SYSTEM_LIBRARY} ${Boost_FILESYSTEM_LIBRARY}\n'
    '  ${Boost_THREAD_LIBRARY} ${EXTRA_LIBRARIES})\n'
    'set_property(TARGET meepcoin-genesis PROPERTY RUNTIME_OUTPUT_DIRECTORY\n'
    '  "${CMAKE_BINARY_DIR}/bin")\n'
)
print("  + src/meepcoin_genesis/ installed")

patch("src/CMakeLists.txt", "add_subdirectory(daemon)",
      "add_subdirectory(meepcoin_genesis)\nadd_subdirectory(daemon)",
      "meepcoin_genesis added to src/CMakeLists.txt")

# 2) genesis gets a real MeepCoin timestamp instead of the inherited 0
patch("src/cryptonote_config.h",
      '#define CRYPTONOTE_NAME                         "meepcoin"',
      '#define CRYPTONOTE_NAME                         "meepcoin"\n'
      '// MeepCoin genesis timestamp (unix seconds). Monero hardcodes 0; MeepCoin records a real\n'
      '// one so the genesis block carries an auditable creation time.\n'
      '#define MEEPCOIN_GENESIS_TIMESTAMP              1785283200ULL',
      "MEEPCOIN_GENESIS_TIMESTAMP defined")

patch("src/cryptonote_core/cryptonote_tx_utils.cpp",
      "    bl.timestamp = 0;\n    bl.nonce = nonce;",
      "    bl.timestamp = MEEPCOIN_GENESIS_TIMESTAMP;  // MeepCoin: real genesis time, not 0\n"
      "    bl.nonce = nonce;",
      "generate_genesis_block uses the MeepCoin timestamp")

print("GENESIS_TOOL_OK" if ok else "GENESIS_TOOL_FAILED")
sys.exit(0 if ok else 1)
