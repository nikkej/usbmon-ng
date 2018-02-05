#******************************************************************************
#
#      CMakeLists.txt
#      Copyright (c) 2018, Juha T Nikkanen <nikkej@gmail.com>
#
# --- Legal stuff ---
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
#******************************************************************************

if( "${CMAKE_SOURCE_DIR}" STREQUAL "${CMAKE_BINARY_DIR}" )
    message( "  In-source build detected, please consider using" )
    message( "  separate build subdir and invoke cmake from there" )
endif()

project( usbmon-ng )
cmake_minimum_required( VERSION 2.8 )
aux_source_directory( . SRC_LIST )
set( C_ADDITIONAL_COMPILE_FLAGS "-g -Wall" )
set( CMAKE_C_FLAGS  "${CMAKE_C_FLAGS} ${C_ADDITIONAL_COMPILE_FLAGS}" )

if ( CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT )
    set ( CMAKE_INSTALL_PREFIX "/bin" CACHE PATH "default path for executables" FORCE )
endif()

find_package( PkgConfig )
pkg_search_module( UDEV REQUIRED libudev )

if( UDEV_FOUND )
    add_executable( ${PROJECT_NAME} ${SRC_LIST} )
    target_link_libraries( ${PROJECT_NAME} ${UDEV_LIBRARIES} "-lpthread" )
    install( FILES ${CMAKE_BINARY_DIR}/${PROJECT_NAME} PERMISSIONS OWNER_EXECUTE OWNER_WRITE OWNER_READ DESTINATION ${CMAKE_INSTALL_PREFIX} )
else()
    message( FATAL_ERROR "Could not find required libraries!" )
endif()
