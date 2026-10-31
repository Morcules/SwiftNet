@echo off
setlocal

del -f CMakeCache.txt
rmdir /s /q CMakeFiles
rmdir /s /q cmake
del -f Makefile
del -f cmake_install.cmake

cd ..\..\..\build
copy profiles\pcap_profile.cmake .\profile.cmake
call .\build.bat
cd ..\tests\integration_tests\build

cmake . -G "MinGW Makefiles" -DCMAKE_C_COMPILER=clang -DCMAKE_MAKE_PROGRAM=make -DBACKEND=pcap -DCMAKE_BUILD_TYPE=Debug -DSANITIZER=none -B .
make -B -j8