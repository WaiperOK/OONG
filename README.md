# OONG Disassembler Tool

This tool is designed to disassemble binary files and provide various analyses on the disassembled code. It supports multiple architectures and modes, allowing for detailed inspection and visualization of executable code.

## Features

- **Architecture Support**: Automatically detects and disassembles binaries for x86, ARM, and ARM64 architectures.
- **Interactive and Command-line Modes**: Supports both interactive mode for user input and command-line arguments for automation.
- **Instruction Analysis**: Provides detailed information about each disassembled instruction, including mnemonics, operands, and bytes.
- **Pseudocode Generation**: Generates a rough pseudocode representation of the disassembled program.
- **Control Flow Graph (CFG) Generation**: Creates and saves a graphical representation of the control flow within the program.
- **Data Flow Graph (DFG) Generation**: Generates and saves a graphical representation of data flows within the program.
- **Dangerous Instruction Analysis**: Identifies and highlights potentially dangerous instructions in the disassembled code.
- **Integration with GDB**: Optionally allows running the binary with GDB for debugging before disassembly.

## Installation

Compile the program: g++ -o disassemblers disassembler.cpp -lmagic -lcurl -lcapstone -lgvc -lcgraph -lcdt

