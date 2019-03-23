llvm-YAHFA
----------------
This is the open source method hooking library from https://github.com/rk700/YAHFA, with changes made so we can instrument the code to achieve SFI. 

The following changes had to be made:
* Use CMake instead of ndkbuild to use the clang compiler to compile the native code (I couldn't get the clang compiler working with ndkbuild).
* Move code from trampoline.c into HookMain.c

