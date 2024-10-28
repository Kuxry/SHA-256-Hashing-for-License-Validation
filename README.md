
# Program Overview

This program is designed to perform system verification by using hardware-specific information (such as BIOS serial number, OS serial number, and hard disk serial number) and a key from a binary file (`zxjl.bin`). It combines this information, applies a series of transformations and hashing using SHA-256, and compares the generated hash with an expected value from a license file (`license.txt`).

## Features

1. **Hardware Information Retrieval**:
    - The program retrieves the BIOS serial number, operating system serial number, and hard disk serial number using WMI (Windows Management Instrumentation).
    
2. **Key Processing**:
    - It reads the key from a binary file (`zxjl.bin`) and performs bitwise and arithmetic operations on the key.

3. **SHA-256 Hashing**:
    - The program combines the system information and processed key to generate a final SHA-256 hash.

4. **License Verification**:
    - The final SHA-256 hash is compared with a pre-defined hash in a file (`license.txt`) to determine if the system is authorized or not.

## Input

1. **Binary File (`zxjl.bin`)**:
    - Contains at least 3 bytes of options (`opt`) and additional key data (`keya`), which are processed to generate a new key (`keyb`).

2. **License File (`license.txt`)**:
    - Contains the expected SHA-256 hash to verify system authenticity.

## Output

1. **Computer Information Hash**:
    - The program outputs the SHA-256 hash prefix generated from system information.
    
2. **Final Hash**:
    - The program generates a final SHA-256 hash based on combined system information and the processed key.
    
3. **Verification Result**:
    - The program compares the final hash with the value from `license.txt` and outputs whether the result is "Agree" or "Disagree" based on the match.

## Code Breakdown

### Functions

- **`GetBiosSerialNumber()`**:
    - Retrieves the BIOS serial number using WMI.

- **`GetOperatingSystemSerialNumber()`**:
    - Retrieves the OS serial number using WMI.

- **`GetHardDiskSerialNumber()`**:
    - Retrieves the hard disk serial number using WMI.

- **`SHA256HashString()`**:
    - Takes an input string and computes its SHA-256 hash.

- **`handleErrors()`**:
    - Handles OpenSSL errors.

### Main Process Flow

1. **Read Binary File**:
    - The program reads the binary file `zxjl.bin` to extract the `opt` values and `keya` data.

2. **Key Processing**:
    - It processes the key by shifting and applying bitwise XOR and subtraction operations based on the values in `opt`.

3. **System Information Retrieval**:
    - The program gathers the BIOS, OS, and hard disk serial numbers and combines them into one string.

4. **Hash Calculation**:
    - The combined string is hashed using SHA-256.

5. **Final Hash Calculation**:
    - The system information hash and the processed key are combined, and the final SHA-256 hash is computed.

6. **Verification**:
    - The final hash is compared with the expected value from the license file, and the result is printed.

## How to Use

1. Prepare the `zxjl.bin` binary file with at least 3 bytes of data for the `opt` array and additional bytes for the `keya` data.
2. Prepare the `license.txt` file with the expected SHA-256 hash.
3. Compile the program and run it on a Windows system.
4. The program will output the hash values and whether the system is verified (`Agree`) or not (`Disagree`).

## Example Output

```
Computer Information: 5D41402ABC4B2A76B9719D911017C592
Final SHA-256 hash: A9993E364706816ABA3E25717850C26C9CD0D89D
Result: Agree
```

## Libraries Required

- **WinSock2.h**: Used for socket programming and network-related functions.
- **iphlpapi.h**: Provides IP helper API functions to retrieve network information.
- **wbemidl.h**: Windows Management Instrumentation (WMI) header for accessing system information.
- **OpenSSL**: For cryptographic functions such as SHA-256.

## Compilation

To compile the program, ensure you link the required libraries:
```bash
g++ -o system_verifier system_verifier.cpp -lwbemuuid -lIPHLPAPI -lOpenSSL
```

## Error Handling

The program uses the `handleErrors()` function to capture any OpenSSL errors during hashing operations.

