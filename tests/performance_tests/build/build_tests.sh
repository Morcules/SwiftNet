cmake . -DCMAKE_BUILD_TYPE=Release -DSANITIZER=none -B .
make -B -j8
