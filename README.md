# AESFile

**aesfile.py** is an open-source pure Python script for encrypting and decrypting files compatible with [AES Drive](https://www.aesdrive.com). It is intended as a simple proof-of-concept using only standard Python libraries.

 While AES Drive itself is proprietary, the file format it uses is open and documented, allowing the community to create and work with compatible files freely.

## Usage

Run `aesfile.py` from the command line to encrypt or decrypt files:

```bash
# Decrypt a file
python aesfile.py -d myfile.txt.aesf

# Decrypt multiple files
python aesfile.py -d C:\myfiles\*.aesf

# Encrypt a file
python aesfile.py -e myfile.txt

# Encrypt multiple files
python aesfile.py -e C:\myfiles\*.txt
```

## Format Specification

The structure and behavior of AESF files are defined in the open format documentation, available here:

[https://www.aesdrive.com](https://www.aesdrive.com)

This script adheres to the specification to ensure compatibility with AES Drive.

## License

This project is released under the MIT License.

## Attribution

This project is based on work from [janiko71](https://github.com/janiko71).
