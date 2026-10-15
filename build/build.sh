rm -f CMakeCache.txt
rm -rf CMakeFiles
rm -rf cmake
rm -f Makefile
rm -f cmake_install.cmake

cmake ../src \
    -DCMAKE_C_COMPILER=clang \
    -DCMAKE_CXX_COMPILER=clang++ \
    #-DCMAKE_C_FLAGS="-Wall -Wextra -Wpedantic -Werror -Wconversion -Wsign-conversion -Wshadow -Wdouble-promotion -Wformat=2 -Wnull-dereference -Wimplicit-fallthrough -Wunreachable-code -Wstrict-prototypes" \
    -DCMAKE_VERBOSE_MAKEFILE=OFF \
    -B .

make -B -j4
