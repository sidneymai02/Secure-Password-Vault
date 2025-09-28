# Password Vault

**A secure, console-based password manager written in C++ with AES encryption, JSON storage, password generation, and colored strength audits.**  

## Project Overview

Password Vault is a **secure and practical password manager** built in C++ for desktop environments. It allows users to **store, manage, and audit credentials** for multiple sites. All passwords are **encrypted using industry-standard AES encryption** and saved in a **JSON-formatted vault file**.  

This project demonstrates **strong C++ programming skills**, integration with **OpenSSL for encryption**, **JSON storage**, and a **user-friendly console interface**.


## Features

- **Secure AES Encryption:** All credentials are encrypted before being written to disk.  
- **JSON Storage:** Credentials are stored in a human-readable JSON file (`vault.dat`) with secure encryption.  
- **Master Password Protection:** Users must authenticate to access stored credentials.  
- **Password Generation:** Generate strong random passwords with configurable length and symbol inclusion.  
- **Password Strength Audit:** Passwords are assessed and visually represented with **colored output** (green = strong, red = weak).  
- **Multi-account Search & Delete:** Search credentials by site and select which accounts to view or delete.  
- **Clear All with Confirmation:** Delete all stored credentials safely.  
- **Console-based Interface:** Intuitive menu-driven interface.  
- **Exception Handling:** Master password errors or invalid operations do not crash the program.  



## Technology Stack

- **Language:** C++17  
- **Libraries:**  
  - [OpenSSL](https://www.openssl.org/) – for AES encryption  
  - [nlohmann/json](https://github.com/nlohmann/json) – JSON parsing and serialization  
  - Windows Console API – colored output  
- **Development Environment:** Visual Studio Code on Windows 10  
- **Build Tool:** `g++` (MinGW) or MSVC compiler  


## Project Structure

- main.cpp: Main console menu and interaction
- VaultManager.h:
- VaultManager.cpp:
- ConsoleColor.h: Helper for colored console output

## Setup and Installation

### Prerequisites

1. **C++ Compiler:** Ensure you have `g++` or Visual Studio C++ tools installed.  
2. **OpenSSL:** Required for AES encryption. Install via [OpenSSL for Windows](https://slproweb.com/products/Win32OpenSSL.html).  
3. **nlohmann/json:** Header-only library (`json.hpp`). Include in your project directory.  

### Steps

1. Clone the repository: ```https://github.com/sidneymai02/Secure-Password-Vault.git```
2. Place ```json.hpp``` in the project directory or include path
3. Compile the project: ```g++ main.cpp VaultManager.cpp CryptoHandler.cpp PasswordGenerator.cpp PasswordAuditor.cpp -lssl -lcrypto -o vault.exe```
4. Run the vault: ```./vault.exe```

## Usage

### Starting the Vault

1. Enter a master password.
    - You get 3 attempts to enter the correct password.
    - All stored credentials are encrypted using this master password.

### Menu Options

1. Add Credential: Add a new site, username, and password. Leave blank to generate a strong password.
2. View All Credentials: Displays all stored credentials with colored strength indicators.
3. Search Credentials: Search by site name. Multi-account matches are displayed with numbers.
4. Audit Password: Enter any password to get a strength assessment (Very Weak → Very Strong) with color coding.
5. Delete Credential: Search for a site, then select which credential to delete. Includes a confirmation prompt.
6. Clear All Credentials: Deletes all credentials after confirmation.
7. Exit: Quit the program safely.

### Example output
```
Site: github.com
Username: alice
Password: Hunter123!
Strength: Strong (cyan)
```

## Security Details
- AES-256 Encryption: Credentials are never stored in plaintext.
- JSON Storage: Encrypted JSON allows easy integration with other tools or migration to secure databases.
- Master Password: Required to unlock vault; changing master password requires decrypting and re-encrypting the vault.
- Password Audit: Detects weak passwords to encourage stronger security.
