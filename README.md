# unxorer-plus
Adding few things Samuel Tulach's unxorer

https://github.com/SamuelTulach/unxorer/

<img width="1024" height="559" alt="image" src="https://github.com/user-attachments/assets/e025a07c-cdee-4ed9-b502-cbb746bec5e5" />


Changes
1. Fake Heap Arena & Win64 API Stubs
Implemented fake_heap: A dynamic bump-allocator mapping a conflict-free memory space.
Intercepts IAT calls and direct jumps (thunks) using Win64 calling convention (RCX, RDX, R8, R9).
Supported stubs: malloc, HeapAlloc, VirtualAlloc, memcpy, memset, strlen, strcpy, and various Rtl* / string operations.
2. Page-Granularity Write Tracking
Added write_tracker to track memory modifications via a Unicorn write hook.
String scans are restricted to CALL/RET boundaries and dirty pages only, reducing CPU overhead.
3. SIMD / AVX & AES-NI Software Emulation
Extended handler.cpp and instruction_classifier.hpp to intercept and software-emulate instructions unsupported or buggy in Unicorn:
Vector Moves: movdqa, movdqu, vmovdqu, vmovdqa, movd/movq.
Vector Operations: pxor/vpxor, pand/vpand, por/vpor, pandn/vpandn, pshufb/vpshufb, shifts (psll*, psrl*, psra*), and vector arithmetic (padd*, psub*, pmullw).
AES-NI: Custom software AES round emulation for aesenc, aesdec, aesenclast, aesdeclast, aesimc, aeskeygenassist, and AVX equivalents (vaes*).
4. Mutation-Based Loop Scaling
Decryption loops that actively modify memory dynamically scale up to 2000 iterations to allow large string decryption to finish without triggering infinite loop heuristics.
