rm -f CMakeCache.txt
rm -rf CMakeFiles

cmake ../src -DCMAKE_BUILD_TYPE=Debug -DSANITIZER=thread -DSWIFT_NET_INTERNAL_TESTING=ON
make -B -j8
