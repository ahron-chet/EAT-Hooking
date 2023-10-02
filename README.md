<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>EAT Hooking Library README</title>
</head>
<body>
    <h1>EAT Hooking Library</h1>

    <p>This library focuses on manipulating the Export Address Table (EAT) to achieve function hooking in Windows binaries.</p>

    <h2>Overview</h2>
    <p>The Export Address Table (EAT) is part of the Portable Executable (PE) format used in Windows executables (like .exe, .dll files). It provides a table of functions that are exported by a module, making them accessible to other modules. By modifying the EAT, we can redirect calls to these functions to our own custom functions.</p>

    <h2>Features</h2>
    <ul>
        <li><strong>EAT Manipulation</strong>: Allows for the retrieval and modification of function addresses in the EAT.</li>
        <li><strong>Memory Allocation Near Module</strong>: Allocates executable memory close to a specified module, suitable for placing our hooking stubs.</li>
        <li><strong>Function Hooking</strong>: Redirects function calls by modifying their addresses in the EAT to point to our own custom functions.</li>
    </ul>

    <h2>Usage</h2>
    <ol>
        <li><strong>Initialize Headers</strong>: Use <code>getHeaders</code> to retrieve the DOS and NT headers of the target module.</li>
        <li><strong>Get EAT Info</strong>: Use <code>getFunctionAddresses</code> to populate the <code>EAT_FUNCTION_INFO</code> structure, which contains pointers to important parts of the EAT and the number of functions.</li>
        <li><strong>Hook a Function</strong>: Use <code>Hooking</code> to redirect a specified function in the EAT to your custom function. This will modify the EAT so that any call to the specified function will now go to your custom function.</li>
        <li><strong>Test the Hook</strong>: After hooking, when the targeted function is called, it will instead execute your custom function.</li>
    </ol>

    <h2>Example</h2>
    <p>The provided <code>main</code> function demonstrates hooking the <code>LoadLibraryW</code> function from <code>kernel32.dll</code> to redirect it to a custom function (<code>printHooked</code>). When the hooked function is called, instead of its usual behavior, it will print "Hello From hooked function!!".</p>
</body>
</html>
