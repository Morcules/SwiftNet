@echo off
setlocal

cmake -S ..\src -B . -G "MinGW Makefiles" ^
    -DCMAKE_C_COMPILER=clang ^
    -DCMAKE_CXX_COMPILER=clang++ ^
    -DCMAKE_VERBOSE_MAKEFILE=OFF ^
    -DCMAKE_MAKE_PROGRAM=make

if errorlevel 1 exit /b %errorlevel%

cmake --build . --parallel 4 --clean-first

if errorlevel 1 exit /b %errorlevel%

endlocal
