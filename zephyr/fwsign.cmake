# SPDX-License-Identifier: Apache-2.0
#
# Zephyr signing script (see "Extending signing externally" in Zephyr's
# doc/build/signing/index.rst). It runs Zephyr's own cmake/mcuboot.cmake,
# so every image variant and MCUBOOT_* option keeps working, but makes it
# call fwsign instead of the Python imgtool.

zephyr_get(FWSIGN SYSBUILD GLOBAL)
find_program(FWSIGN fwsign)
if(NOT FWSIGN)
  message(FATAL_ERROR "fwsign not found. Install it with "
                      "'cargo install --locked --git https://github.com/amazeng-co/fwsign' "
                      "or pass -DFWSIGN=/path/to/fwsign.")
endif()
message(STATUS "Signing MCUboot images with ${FWSIGN}")

# mcuboot.cmake (Zephyr 4.0+) builds its command as
# "${PYTHON_EXECUTABLE} ${IMGTOOL} sign ...". With the interpreter blanked,
# the unquoted expansion drops it and fwsign runs directly.
# ponytail: depends on that line of mcuboot.cmake; ship a full copy of the
# script if upstream ever changes how it invokes imgtool.
set(fwsign_python ${PYTHON_EXECUTABLE})
set(PYTHON_EXECUTABLE "")
set(IMGTOOL ${FWSIGN})
include(${ZEPHYR_BASE}/cmake/mcuboot.cmake)
set(PYTHON_EXECUTABLE ${fwsign_python})
unset(IMGTOOL)
