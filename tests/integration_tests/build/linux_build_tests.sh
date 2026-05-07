cmake . -DCMAKE_BUILD_TYPE=Debug -DSANITIZER=none -B .
make -B -j8
