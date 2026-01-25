rm -f CMakeCache.txt
rm -rf CMakeFiles

cmake ../src -DCMAKE_BUILD_TYPE=Release -DSANITIZER=none
make -B -j8
