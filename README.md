# EAT Hooking Library

This library focuses on manipulating the Export Address Table (EAT) to achieve function hooking in Windows binaries.

## Overview

The Export Address Table (EAT) is part of the Portable Executable (PE) format used in Windows executables (like .exe, .dll files). It provides a table of functions that are exported by a module, making them accessible to other modules. By modifying the EAT, we can redirect calls to these functions to our own custom functions.

## Features

- **EAT Manipulation**: Allows for the retrieval and modification of function addresses in the EAT.
- **Memory Allocation Near Module**: Allocates executable memory close to a specified module, suitable for placing our hooking stubs.
- **Function Hooking**: Redirects function calls by modifying their addresses in the EAT to point to our own custom functions.

## Usage

1. **Initialize Headers**: Use `getHeaders` to retrieve the DOS and NT headers of the target module.
2. **Get EAT Info**: Use `getFunctionAddresses` to populate the `EAT_FUNCTION_INFO` structure, which contains pointers to important parts of the EAT and the number of functions.
3. **Hook a Function**: Use `Hooking` to redirect a specified function in the EAT to your custom function. This will modify the EAT so that any call to the specified function will now go to your custom function.
4. **Test the Hook**: After hooking, when the targeted function is called, it will instead execute your custom function.

## Example

The provided `main` function demonstrates hooking the `LoadLibraryW` function from `kernel32.dll` to redirect it to a custom function (`printHooked`). When the hooked function is called, instead of its usual behavior, it will print "Hello From hooked function!!".
