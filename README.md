
# Cryptographic Scheme for Pooled Decryption and Traitor Tracing

This repository implements the cryptographic schemes described in the research paper on "Silent Threshold Traitor Tracing & Enhancing Mempool Privacy". The implementation focuses on a pooled decryption protocol with a trace decoder mechanism that enables identification of malicious participants in a threshold cryptosystem.

## Overview

The codebase implements:
- A threshold cryptographic scheme with pooled decryption capabilities
- A trace decoder for identifying potential traitors in the system
- Benchmarking tools for performance analysis
- Size measurement utilities for various cryptographic components

## Features

- Pairing-based cryptography using BLS12-381 curves
- Threshold decryption requiring cooperation of multiple parties
- Traitor tracing capabilities
- Comprehensive benchmarking suite

## Setup and Run

### Prerequisites

- Go 1.16 or later

### Installation

1. Clone the repository:
```bash
git clone https://github.com/kushazsehgal/RPEPB.git
cd rpepd_decoder
```
2. Initialize the Go module (only needed once):
```bash
go mod init pooled_decrypt
```
3. Download dependencies:
```bash
go mod tidy
```
4. Build the project:
```bash
go build .
```
### Running the Project
Run the main program which executes benchmarks and tests:
```bash
go run .
```
The program will:
- Run exponentiation time tests
- Measure ciphertext sizes for various security parameters
- Benchmark group elements and key sizes
- Test the scheme directly with different parameters
- Run decoder trace tests
## Project Structure
- [`decoder`](decoder ) - Implementation of the traitor tracing decoder
- [`models`](models ) - Core cryptographic types and primitives
- [`scheme`](scheme ) - Implementation of the threshold cryptographic scheme
- [`utils`](utils ) - Utility functions for cryptographic operations
- [`main.go`](main.go ) - Entry point and benchmarking suite
- [`plots.py`](plots.py ) - Python script for plotting benchmark results
- [`plot_memory.py`](plot_memory.py ) - Python script for plotting memory usage
## Benchmark Results
The program generates several CSV files with benchmark results:
- [`exponentiation_times.csv`](exponentiation_times.csv ) - Performance benchmarks for exponentiation operations
- [`ciphertext_sizes.csv`](ciphertext_sizes.csv ) - Size measurements for ciphertexts
- [`sizes.csv`](sizes.csv ) - Size measurements for various cryptographic components
- [`scheme_times.csv`](scheme_times.csv ) - Performance benchmarks for the scheme operations
- [`decoder_times.csv`](decoder_times.csv ) - Performance benchmarks for the decoder operations
These files can be analyzed using the included Python plotting scripts:
```bash
python plots.py
python plot_memory.py
```
