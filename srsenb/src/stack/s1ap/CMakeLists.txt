#
# Copyright 2013-2023 Software Radio Systems Limited
#
# This file is part of srsRAN
#
# srsRAN is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of
# the License, or (at your option) any later version.
#
# srsRAN is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU Affero General Public License for more details.
#
# A copy of the GNU Affero General Public License can be found in
# the LICENSE file in the top-level directory of this distribution
# and at http://www.gnu.org/licenses/.
#

set(SOURCES s1ap.cc s1ap_x2.cc)
add_library(srsenb_s1ap STATIC ${SOURCES})

set(X2AP_CODEC_DIR "" CACHE PATH "Generated, pinned X2AP ASN.1 codec directory")
if(X2AP_CODEC_DIR)
  add_subdirectory(${X2AP_CODEC_DIR} ${CMAKE_BINARY_DIR}/x2ap-codec)
  target_link_libraries(srsenb_s1ap PUBLIC x2ap_codec)
  target_compile_definitions(srsenb_s1ap PUBLIC SRSENB_ENABLE_X2)
  # Other stack libraries include s1ap.h and must see the same class layout.
  add_compile_definitions(SRSENB_ENABLE_X2)
endif()
