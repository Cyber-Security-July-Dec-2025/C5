# **CryptoQtApp**

This is a desktop application built with Qt and the Crypto++ library for performing various cryptographic operations.

## **Features**

* **AES Encryption and Decryption:** Supports AES with the mode specified in the config.json file.  
* **Symmetric Key Generation:** Generates a symmetric key for AES operations.  
* **SHA-256 Hashing:** Computes the SHA-256 hash of a file.  
* **HMAC-SHA256:** Generates an HMAC-SHA256 digest using a user-provided key.  
* **File I/O:** Allows uploading input files and downloading processed output files.

## **Prerequisites**

To build and run this application, you will need the following:

* A C++ compiler that supports C++17 (e.g., GCC, Clang, MSVC)  
* \*\*Qt 5:\*\* The Qt framework is required for the GUI.

* **CMake:** A cross-platform build system.  
* **Crypto++:** A free and open-source C++ class library of cryptographic schemes.

## **Installation**

### **1\. Install Dependencies**

You need to install the Qt 5 development libraries and the Crypto++ library on your system.

**On Ubuntu/Debian:**

sudo apt-get update  
sudo apt-get install build-essential cmake qt5-default libqt5widgets5 libcryptopp-dev

**On macOS (using Homebrew):**

brew update  
brew install qt@5  
brew install cryptopp

You may need to manually link Qt if it's not in your PATH: echo 'export PATH="/usr/local/opt/qt@5/bin:$PATH"' \>\> \~/.zshrc or \~/.bash\_profile

On Windows:  
Install the Qt SDK from the official website and a C++ build toolchain like Visual Studio or MinGW. You will also need to download and build Crypto++ manually or use a package manager like vcpkg.

### **2\. Configure the Project**

Ensure your project directory has the following structure:

.  
├── CMakeLists.txt  
├── config.json  
├── include/  
│   ├── cryptoops.h  
│   └── mainwindow.h  
├── src/  
│   ├── cryptoops.cpp  
│   ├── main.cpp  
│   └── mainwindow.cpp  
└── ui/  
    └── mainwindow.ui

### **3\. Build the Application**

From the root of your project directory, run the following commands:

mkdir build  
cd build  
cmake ..  
make

### **4\. Run the Application**

After a successful build, the executable CryptoQtApp will be located in the build directory.

./CryptoQtApp

## **Configuration**

The application's behavior for AES operations is determined by the config.json file. You can change the mode to cbc or ecb and the key\_size.

Example config.json:

```
{  
    "aes": {  
      "key\_size": 32,  
      "mode": "ecb"   
    },  
    "hmac": {  
      "key\_size": 32  
    }  
}
```
## **Usage**

1. **Select Operation:** Choose the cryptographic operation from the dropdown menu.  
2. **Upload File:** Use the "Upload" button to select a file for processing.  
3. **Enter Key (if applicable):** For AES and HMAC, you will need to enter the key in hexadecimal format.  
4. **Process:** Click the "Process" button to perform the selected operation. The output will be displayed in the text box.  
5. **Download Output:** Click "Download Output" to save the processed data (e.g., decrypted file, encrypted file) to a file.
