# SPDX-License-Identifier: Apache-2.0

if(CONFIG_FWSIGN)
  set_target_properties(zephyr_property_target PROPERTIES SIGNING_SCRIPT ${CMAKE_CURRENT_LIST_DIR}/fwsign.cmake)
endif()
