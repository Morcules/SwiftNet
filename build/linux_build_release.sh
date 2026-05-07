rm -f CMakeCache.txt
rm -rf CMakeFiles
rm -rf cmake
rm -f Makefile
rm -f cmake_install.cmake

cmake ../src -DCMAKE_BUILD_TYPE=Release -DSANITIZER=none -B .
make -B -j8
