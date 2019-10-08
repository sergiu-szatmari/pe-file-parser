# Portable-Executable File Parser

Parser for PE files made using C programming language.
The file's path is given as a command line parameter.

The parser outputs information such as:
* File Header information (Machine, Number of Sections)
* Optional Header information (Address of Entry, Image base, ...)
* Available sections: name, file address, size
* Exports
* Imports

### Usage

```bash
Compile "pe-parser.c" as "parser.exe"

./parser.exe [PE file path]
```