rm -f CMakeCache.txt
rm -rf CMakeFiles
rm -rf cmake
rm -f Makefile
rm -f cmake_install.cmake

cd ../../../build
cp profiles/pcap_profile.cmake ./profile.cmake
sudo ./build.sh
cd ../tests/integration_tests/build

cmake . -DBACKEND=pcap -DCMAKE_BUILD_TYPE=Debug -DSANITIZER=address -B .
make -B -j8
