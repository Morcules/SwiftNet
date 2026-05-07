cmake . -DCMAKE_BUILD_TYPE=Debug -DSANITIZER=thread -B .
make -B -j8
