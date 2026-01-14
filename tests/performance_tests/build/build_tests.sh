cmake . -DCMAKE_BUILD_TYPE=Debug -DSANITIZER=thread
make -B -j8
