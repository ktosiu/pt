CMAKE_BUILD_TYPE ?= Release
CMAKE_FLAGS := -DCMAKE_BUILD_TYPE=$(CMAKE_BUILD_TYPE)

all: pt

pt: deps cmake
	cd build && make

cmake:
	cd build && cmake $(CMAKE_FLAGS) .. 

deps:
	mkdir -p build

clean: 
	rm -rf build

