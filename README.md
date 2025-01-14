# Early Cascade Injection Loader

This is an implementation of the "Early Cascade Injection" technique described in this [blog](https://www.outflank.nl/blog/2024/10/15/introducing-early-cascade-injection-from-windows-process-creation-to-stealthy-injection/) by Outflank. If you're curious about this, I recommend reading the blog post.

**TL;DR**: This technique allows you to inject code into a suspended process in such a way that your code is ran before any AV/EDR DLLs are initialized via their entrypoint (DllMain). This is done by enabling the "shims" application compatibility feature, then writing shellcode to a function that is only called when process shims are enabled. This shellcode then creates an APC Routine which gets ran prior to the program's entry point when `NtContinue` is called.

The important part here is that the initial stub ***runs prior to dll initialization.***. This means that within our stub we can stop AV/EDR initialization DLLs from loading into our process.

### Key steps in the process:

1. Resolve address of shim pointers: `g_ShimsEnabled` and `g_pfnSE_DllLoaded`
2. Resolve address of `NtQueueApcThread` and any other functions your stub might call
3. Update addresses within stub. Stub shellcode must toggle `g_ShimsEnabled` and call `NtQueueApcThread` with payload address. 
4. Create target process in a suspended state.
5. Allocate memory for stub and payload.
6. Write `1` to `g_ShimsEnabled` address in child process.
7. Encode the pointer to the stub (allocation in step 5)
8. Write encoded stub pointer to address of `g_pfnSE_DllLoaded` in the child process.
9. Resume the thread. 

## Building

Build this tool with the provided build script `build.sh` with mingw-w64 installed.

build.sh
```bash
# Compile PIC stub object
x86_64-w64-mingw32-gcc -c stub.c -fPIC -O0 -o stub.o

# Get the TEXT section
x86_64-w64-mingw32-objcopy -O binary --only-section=.text stub.o stub-x64.o

# Generate the header for the stub
xxd --include stub-x64.o > stub.h

# BOF
x86_64-w64-mingw32-gcc -Os -c cascade.c -o cascade.o -D_BOF
# PE
x86_64-w64-mingw32-gcc -Os cascade.c file.c -o cascade.exe
```

## Stub implementation

The shellcode stub in the project performs the following:

1. Queues the APC routine
2. Iterates through the `LDR_DATA_TABLE_ENTRY` structure passed to `g_pfnSE_DllLoaded` for a non-standard initialization PE.
3. If one is found, then the entry point of that PE is replaced with a patch (currently just `ret` (`0xC3`))

Since unicode string needed to be compared, additional API resolution was needed `RtlEqualUnicodeString`. Likewise, `NtProtectVirtualMemory` was needed as well.

## Running

Run the executable loader by passing a single argument to a shellcode binary:

```bash
cascade.exe loader.bin
```

## References
- https://github.com/Cracked5pider/earlycascade-injection
- https://www.outflank.nl/blog/2024/10/15/introducing-early-cascade-injection-from-windows-process-creation-to-stealthy-injection/
- https://malwaretech.com/2024/02/bypassing-edrs-with-edr-preload.html