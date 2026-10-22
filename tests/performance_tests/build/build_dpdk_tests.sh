rm -f CMakeCache.txt
rm -rf CMakeFiles
rm -rf cmake
rm -f Makefile
rm -f cmake_install.cmake

cd ../../../build
cp profiles/dpdk_perf_profile.cmake ./profile.cmake
sudo ./build.sh
cd ../tests/performance_tests/build

cmake . -DBACKEND=dpdk -DCMAKE_BUILD_TYPE=Release -DSANITIZER=address -B .
make -B -j8
