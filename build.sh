x86_64-w64-mingw32-gcc -c stub.c -fPIC -O0 -o stub.o
x86_64-w64-mingw32-objcopy -O binary --only-section=.text stub.o stub-x64.o
xxd --include stub-x64.o > stub.h

x86_64-w64-mingw32-gcc -Os -c cascade.c -o cascade.o -D_BOF
x86_64-w64-mingw32-gcc -Os cascade.c file.c -o cascade.exe
