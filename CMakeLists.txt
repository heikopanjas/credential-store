################################################################################
#
# Copyright (c) The Ultralove Project (https://github.com/ultralove)
#
# The MIT License (MIT)
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.
#
################################################################################

cmake_minimum_required(VERSION 3.19)

project(ultralove-credentials
  VERSION 1.0.0
  DESCRIPTION "ultralove credential store interface"
  LANGUAGES C CXX
)

if(CMAKE_PROJECT_NAME STREQUAL PROJECT_NAME)
  set(CMAKE_CXX_EXTENSIONS OFF)
  set(CMAKE_CXX_STANDARD 20)
  set(CMAKE_CXX_STANDARD_REQUIRED ON)
  set_property(GLOBAL PROPERTY USE_FOLDERS ON)
endif()

if(WIN32)
    set(ULTRALOVE_TARGET_SYSTEM "windows")
elseif(APPLE)
    set(ULTRALOVE_TARGET_SYSTEM "macos")
elseif(UNIX)
  execute_process(COMMAND uname -a RESULT_VARIABLE UNAME_RESULT OUTPUT_VARIABLE UNAME_OUTPUT OUTPUT_STRIP_TRAILING_WHITESPACE)
  if(UNAME_RESULT EQUAL 0)
    if(${UNAME_OUTPUT} MATCHES "[U|u]buntu")
        set(ULTRALOVE_TARGET_SYSTEM "linux")
    else()
      message(STATUS "Unsupported platform: " ${UNAME_OUTPUT})
      message(FATAL_ERROR "Supported platforms are Windows, macOS and Ubuntu Linux")
    endif()
  else()
    message(FATAL_ERROR "Failed to run uname, result: ${UNAME_RESULT}")
  endif()
endif()

set(CMAKE_POSITION_INDEPENDENT_CODE ON  CACHE INTERNAL "")
set(CMAKE_WARN_DEPRECATED           OFF CACHE INTERNAL "")
set(BUILD_SHARED_LIBS               OFF CACHE INTERNAL "")

message(STATUS "ULTRALOVE_TARGET_SYSTEM = " ${ULTRALOVE_TARGET_SYSTEM})

if(ULTRALOVE_TARGET_SYSTEM STREQUAL "windows")
  include_directories(windows)
  add_subdirectory(windows)
elseif(ULTRALOVE_TARGET_SYSTEM STREQUAL "macos")
  include_directories(macos)
  add_subdirectory(macos)
elseif(ULTRALOVE_TARGET_SYSTEM STREQUAL "linux")
  include_directories(linux)
  add_subdirectory(linux)
else()
  message(STATUS "Unsupported platform: " ${ULTRALOVE_TARGET_SYSTEM})
  message(FATAL_ERROR "Supported platforms are Windows, macOS and Ubuntu Linux")
endif()
