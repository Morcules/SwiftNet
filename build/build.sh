rm -f CMakeCache.txt
rm -rf CMakeFiles
rm -rf cmake
rm -f Makefile
rm -f cmake_install.cmake

cmake ../src -B .
make -B -j8
