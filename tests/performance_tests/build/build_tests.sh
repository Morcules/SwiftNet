cmake . -DCMAKE_BUILD_TYPE=Release -DSANITIZER=none
make -B -j8
