"""
This Python script may be used to encrypt or decrypt files used by AES Drive.
This script does not use any proprietary code or libraries and is provided
as a reference implementation for dealing with AES Drive files independently
of the AES Drive application.

AES Drive is a proprietary program that provides a simple way to secure files by always 
keeping them encrypted on disk, while still allowing access to the decrypted
versions through a mounted virtual drive. More information about AES Drive
can be found at https://www.callback.com/aesdrive.

Error handling and other checks are simplified for clarity in this script. 
"""

import logging
import argparse
import io
import os
import hashlib
import binascii
import getpass
import sys
import glob

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

assert sys.version_info >= (3, 8), "Python 3.8 or higher is required."

parser = argparse.ArgumentParser()

encrypt_decrypt_group = parser.add_mutually_exclusive_group(required=True)
encrypt_decrypt_group.add_argument("-e", "--encrypt", action="store_true", help="encrypt the specified file(s)")
encrypt_decrypt_group.add_argument("-d", "--decrypt", action="store_true", help="decrypt the specified file(s)")

output_group = parser.add_mutually_exclusive_group()
output_group.add_argument("-o", "--outfile", default="", help="file to output to")
output_group.add_argument("-od", "--outdir", default="", help="directory to output to")

parser.add_argument("-w", "--overwrite", action="store_true", help="overwrite existing output file(s)")

verbosity_group = parser.add_mutually_exclusive_group()
verbosity_group.add_argument("-v", "--verbose", action="store_true", help="increase output verbosity (show debug messages)")
verbosity_group.add_argument("-q", "--quiet", action="store_true", help="run in quiet mode (only display warnings/errors)")

parser.add_argument("infile", nargs="+", help="filename(s) to encrypt or decrypt, space-separated")

input_args = parser.parse_args()

if input_args.quiet:
  log_level = "WARNING"
elif input_args.verbose:
  log_level = "DEBUG"
else:
  log_level = "INFO"

logging.basicConfig(format="%(levelname)s:\t%(message)s", level=log_level)
logger = logging.getLogger()

logger.debug("\targs: %s", input_args)

# ============================
# AESF file format constants
# ============================

BLOCK_SIZE = 512
HEADER_LEN = 144

FILE_FORMAT_VERSION_OFFSET = 4

CHECKSUM_OFFSET = 12
CHECKSUM_LEN = 4

GLOBAL_SALT_OFFSET = 16
FILE_SALT_OFFSET = 32
SALT_LEN = 16

GCM_HEADER_OFFSET = 48
GCM_HEADER_LEN = 80

GCM_AUTH_TAG_OFFSET = 128
GCM_AUTH_TAG_LEN = 16

GCM_KEY_LEN = 32
GCM_IV_LEN = 12

XTS_AES_KEY_OFFSET = 16
XTS_AES_KEY_SIZE = 32

# ============================
# Functions
# ============================

def encrypt(outfile: str, password: str, file_bytes: bytearray):
  """Encrypt bytes from file_bytes into output file.
  
  #### Parameters:
  - outfile : str -- path to output file
  - password : str -- password to encrypt file with
  - file_bytes : bytearray -- bytes to encrypt
  """

  # ------------------------------------------------ #
  # Construct header to store encryption information #
  # ------------------------------------------------ #
  
  logger.debug("\tConstructing header...")

  length                 = len(file_bytes)
  padding_len            = 0
  extra_padding_len      = 0
  encrypted_bytes        = []
  file_format_version    = 1 # Version 1 is the only currently supported value

  logger.debug("\tCalculating padding length...")
  # File format 1: Pad with random bytes instead of 0s, and pad exactly 512 trailing bytes
  if file_format_version == 1:
    if length % BLOCK_SIZE != 0:
      padding_len = BLOCK_SIZE - (length % BLOCK_SIZE)
    extra_padding_len = BLOCK_SIZE - padding_len
    encrypted_bytes = bytearray(HEADER_LEN + length + BLOCK_SIZE)
  # File format unsupported
  else:
    raise ValueError("Unsupported file format version")
  
  logger.debug("\tWriting magic string...")
  # 0-3 | AESF bytes
  encrypted_bytes[0:FILE_FORMAT_VERSION_OFFSET] = 'AESF'.encode('utf-8')

  logger.debug("\tWriting file format version...")
  # 4 | File format version
  encrypted_bytes[FILE_FORMAT_VERSION_OFFSET] = file_format_version
  
  logger.debug("\tGenerating salts...")
  # 16-31 | Global salt
  global_salt = os.urandom(SALT_LEN)
  encrypted_bytes[GLOBAL_SALT_OFFSET:(GLOBAL_SALT_OFFSET + SALT_LEN)] = global_salt
  # 32-47 | File specific salt
  file_salt = os.urandom(SALT_LEN)
  encrypted_bytes[FILE_SALT_OFFSET:(FILE_SALT_OFFSET + SALT_LEN)] = file_salt

  logger.debug("\tGenerating AES-GCM encrypted header...")
  # 48-127 | AES-GCM-encrypted header
  gcm_header = bytearray(GCM_HEADER_LEN)
  gcm_header[0:2] = padding_len.to_bytes(2, 'big')
  
  # AES-GCM encrypted header portion

  # XTS keys
  xts_keys = os.urandom(2 * XTS_AES_KEY_SIZE)
  gcm_header[XTS_AES_KEY_OFFSET:(XTS_AES_KEY_OFFSET + 2 * (XTS_AES_KEY_SIZE))] = xts_keys

  logger.debug("\tRunning PBKDF2...")
  # Use PBKDF2HMAC with SHA512 to get a derived key
  pbkdf = hashlib.pbkdf2_hmac(
    hash_name='sha512',
    password=password.encode('utf-8'),
    salt=global_salt,
    iterations=50000,
    dklen=32
  )
  
  logger.debug("\tSHA512 hashing to obtain AES-GCM key and IV...")
  # Combine derived key with file specific salt and hash with SHA512 to obtain AES-GCM key and IV
  key_iv = hashlib.sha512(file_salt + pbkdf).digest()
  gcm_key = key_iv[0:GCM_KEY_LEN]
  gcm_iv = key_iv[GCM_KEY_LEN:(GCM_KEY_LEN + GCM_IV_LEN)]

  logger.debug("\tEncrypting AES-GCM header portion...")
  # Use AES-GCM to encrypt encrypted header portion
  aesgcm = AESGCM(gcm_key)
  encrypted_bytes[GCM_HEADER_OFFSET:(GCM_HEADER_OFFSET + GCM_HEADER_LEN + GCM_AUTH_TAG_LEN)] = aesgcm.encrypt(gcm_iv, bytes(gcm_header), None)

  logger.debug("\tComputing and storing checksum...")
  # 12-15 | CRC32 checksum
  encrypted_bytes[CHECKSUM_OFFSET:(CHECKSUM_OFFSET + CHECKSUM_LEN)] = binascii.crc32(encrypted_bytes[0:HEADER_LEN]).to_bytes(4, 'big')

  # -------------------------------- #
  # Encrypt plaintext bytes with XTS #
  # -------------------------------- #

  outstream = io.BytesIO()

  logger.debug("\tStarting encryption...")

  # XTS requires encrypting with blocks, so we expand the stream used to read it to a multiple of BLOCK_SIZE
  blockedBytes = bytearray(length if (length % BLOCK_SIZE == 0) else ((length // BLOCK_SIZE) + 1) * BLOCK_SIZE)
  blockedBytes[0:length] = file_bytes

  stream = io.BytesIO(blockedBytes)
  stream.seek(0)

  xts(True, xts_keys, stream, len(blockedBytes), outstream)

  if file_format_version == 1:
    encrypted_bytes[(HEADER_LEN + length):(HEADER_LEN + length + padding_len)] = os.urandom(padding_len)
    encrypted_bytes[(HEADER_LEN + length + padding_len):] = os.urandom(extra_padding_len)
  else:
    raise ValueError("Unsupported file format version")

  logger.debug("\tWriting %s encrypted bytes...", len(encrypted_bytes))

  outstream.seek(0)
  encrypted_bytes[HEADER_LEN:(HEADER_LEN + length + padding_len)] = outstream.read(length + padding_len)

  with open(outfile, 'wb') as output_writer:
    output_writer.write(encrypted_bytes)
    
  logger.info("Done writing to %s\n", outfile)

def decrypt(outfile: str, password: str, file_bytes: bytearray):
  """Decrypt bytes from file_bytes into output file.
  
  #### Parameters:
  - outfile : str -- path to output file
  - password : str -- password to decrypt file with
  - file_bytes : bytearray -- bytes to decrypt (must be in AESF file format)
  """

  # -------------------------------------------------------- #
  # Decrypt header to obtain decryption information and keys #
  # -------------------------------------------------------- #

  logger.debug("\tDecrypting header...")
  
  header = file_bytes[0:HEADER_LEN]

  logger.debug("\tReading unencrypted header properties...")
  tag                    = header[0:4].decode('utf-8')
  if tag != "AESF":
    raise ValueError("File does not appear to be encrypted by AES Drive (missing AESF magic string).")
  file_format_version    = header[FILE_FORMAT_VERSION_OFFSET]
  header_checksum        = header[CHECKSUM_OFFSET:(CHECKSUM_OFFSET + CHECKSUM_LEN)]
  global_salt            = header[GLOBAL_SALT_OFFSET:(GLOBAL_SALT_OFFSET + SALT_LEN)]
  file_salt              = header[FILE_SALT_OFFSET:(FILE_SALT_OFFSET + SALT_LEN)]
  gcm_header             = header[GCM_HEADER_OFFSET:(GCM_HEADER_OFFSET + GCM_HEADER_LEN)]
  gcm_auth_tag           = header[GCM_AUTH_TAG_OFFSET:(GCM_AUTH_TAG_OFFSET + GCM_AUTH_TAG_LEN)]

  logger.debug("\tComputing checksum...")
  # Compute and check CRC32 checksum
  header_copy = header[0:CHECKSUM_OFFSET] + (b'\x00' * CHECKSUM_LEN) + header[(CHECKSUM_OFFSET + CHECKSUM_LEN):HEADER_LEN]
  calculated_checksum = binascii.crc32(header_copy)

  if (header_checksum != calculated_checksum.to_bytes(4, 'big')):
    raise ValueError("CRC32 checksum mismatch. Header may be corrupted or file may not be a well-formed AESF file.")
  else:
    logger.debug("\tChecksum match")

  logger.debug("\tProcessing AES-GCM encrypted header...")
  # AES-GCM encrypted header portion

  logger.debug("\tGenerating AES-GCM key and IV...")

  logger.debug("\tRunning PBKDF2...")
  # Use PBKDF2HMAC with SHA512 to get a derived key
  pbkdf = hashlib.pbkdf2_hmac(
    hash_name='sha512',
    password=password.encode('utf-8'),
    salt=global_salt,
    iterations=50000,
    dklen=32
  )

  logger.debug("\tSHA512 hashing to obtain AES-GCM key and IV...")
  # Combine derived key with file specific salt and hash with SHA512 to get AES-GCM key and IV
  key_iv = hashlib.sha512(file_salt + pbkdf).digest()
  gcm_key = key_iv[0:GCM_KEY_LEN]
  gcm_iv = key_iv[GCM_KEY_LEN:(GCM_KEY_LEN + GCM_IV_LEN)]

  logger.debug("\tDecrypting AES-GCM header portion...")
  # Use AES-GCM to decrypt encrypted header portion
  aesgcm = AESGCM(gcm_key)
  try:
    decrypted_gcm_header = aesgcm.decrypt(gcm_iv, bytes(gcm_header + gcm_auth_tag), None)
  except InvalidTag as e:
    logger.error(e)
    raise InvalidTag("AES GCM tag mismatch. Password may be incorrect.")
  
  padding_len = int.from_bytes(decrypted_gcm_header[0:2], 'big')

  # AES-XTS used in the cryptography package requires the concatenation of the two XTS-AES keys as a parameter
  xts_keys = decrypted_gcm_header[(XTS_AES_KEY_OFFSET):(XTS_AES_KEY_OFFSET + (2 * XTS_AES_KEY_SIZE))]

  # -------------------------------------------------- #
  # Decrypt remainder of file to obtain plaintext data #
  # -------------------------------------------------- #

  stream = io.BytesIO(file_bytes[HEADER_LEN:])
  outstream = io.BytesIO()

  logger.debug("\tCalculating padding length...")

  # File format 1: Pad with random bytes instead of 0s, and pad exactly 512 trailing bytes
  if file_format_version == 1:
    extra_data = BLOCK_SIZE - padding_len
  else:
    raise ValueError("Unsupported file format version")

  length = len(file_bytes) - HEADER_LEN - extra_data

  # XTS-AES decryption
  xts(False, xts_keys, stream, length, outstream)
  
  logger.debug("\tWriting %s bytes...", length - padding_len)

  outstream.seek(0)

  with open(outfile, 'wb') as output_writer:
    output_writer.write(outstream.read(length - padding_len))
  
  logger.info("Done writing to %s\n", outfile)

def xts(encrypt: bool, xts_keys: bytes | bytearray, stream: io.BytesIO, length: int, outstream: io.BytesIO):
  """Read bytes from stream, encrypt or decrypt with XTS-AES, and write to outstream.

    #### Parameters
    - encrypt : bool -- True to encrypt, False to decrypt
    - xts_keys : bytes | bytearray -- Concatenated XTS-AES keys
    - stream : io.BytesIO -- Stream containing bytes to en/decrypt
    - length : int -- Length of data to read (up to a multiple of 512)
    - outstream : io.BytesIO -- Stream to write data to
  """
  current_sector_offset = 0
  byte_offset = 0
  stream.seek(0)

  logger.debug("\tStarting XTS on %s bytes...", length)

  # XTS-AES encrypt or decrypt bytes from stream in blocks of 512
  while byte_offset < length:

    block = stream.read(BLOCK_SIZE)
    tweak = current_sector_offset.to_bytes(16, 'little')
    
    if block:
      if encrypt:
        encryptor = Cipher(algorithm=algorithms.AES(xts_keys), mode=modes.XTS(tweak)).encryptor()
        decrypted_block = encryptor.update(block)
      else:
        decryptor = Cipher(algorithm=algorithms.AES(xts_keys), mode=modes.XTS(tweak)).decryptor()
        decrypted_block = decryptor.update(block)

      byte_offset = byte_offset + BLOCK_SIZE

      outstream.write(decrypted_block)
      
      current_sector_offset += 1

    else:
      break
  
  logger.debug("\t%s blocks written", current_sector_offset)

def prompt_overwrite(filename: str) -> bool:
  """If filename exists, prompt user whether or not to overwrite filename.
  
  Returns True if overwrite was specified in input, user confirms, or no file already exists at filename. Returns False otherwise.
  """
  if input_args.overwrite:
    logger.info("%s already exists. File will be overwritten.", filename)
    return True
  if os.path.exists(filename):
    return input("\n%s already exists. Overwrite? (y/n) " % (filename)) in {'y', 'Y'}
  else:
    return True

def set_ext(out) -> str:
  """Append '.aesf' if encrypting or strip one extension if decrypting."""
  if input_args.encrypt:
    return out + '.aesf'
  elif input_args.decrypt:
    return os.path.splitext(out)[0]

def process_file(infile: str, outfile: str = "", outdir: str = ""):
  """Read file from infile and encrypt or decrypt into outfile or outdir.
  
  #### Parameters:
  - infile : str -- filepath to file to read
  - outfile : str -- filepath to file to write to (takes priority over outdir, if both are specified)
  - outdir : str -- directory to write to, using infile as base name
  """
  success = False

  try:

    # Read input file
    if not (os.path.exists(infile)):
      logger.warning("%s does not exist\n", infile)
      return
    
    if outfile:
      # If reading out_location as a file, leave as is
      out_location = set_ext(outfile)
    elif outdir:
      # If directory specified, output to file in that directory
      out_location = set_ext(os.path.join(outdir, os.path.basename(infile)))
    else:
      # If no output is specified, use the input filename with extension modified
      out_location = set_ext(infile)
    
    if not prompt_overwrite(out_location):
      print()
      return

    logger.info("Opening %s..." % (infile))
    with open(infile, "rb") as input_reader:
      file_bytes = bytearray(input_reader.read())
      logger.debug("\t%s bytes read", len(file_bytes))

      if input_args.encrypt: encrypt(out_location, password, file_bytes)
      elif input_args.decrypt: decrypt(out_location, password, file_bytes)
      else:
        raise ValueError("Neither encrypt or decrypt was specified")

      success = True
  
  except Exception as e:
    logger.error("%s\n", e)

  finally:
    processed_files.append(os.path.abspath(infile))
    written_files.append(os.path.abspath(out_location) if success else "Failed")

# ============================
# Main logic
# ============================

# Find files matching any input pattern
matched_files = {match for pattern in input_args.infile for match in glob.glob(pattern) if os.path.isfile(match)}

if len(matched_files) == 0:
  logger.info("No files matched\n")
  quit()
elif input_args.outfile:
  if len(matched_files) != 1:
    logger.error("Multiple files matched, but only one output file specified")
    quit()
  elif os.path.isdir(input_args.outfile):
    logger.error("Directory already exists. Cannot overwrite %s", input_args.outfile)
    quit()

password = getpass.getpass(prompt="\nEnter password to " + ("encrypt" if input_args.encrypt else "decrypt") + " file(s):" )
print()

processed_files = []
written_files = []

if input_args.outdir:
  os.makedirs(input_args.outdir, exist_ok=True)
  logger.info("Outputting to directory %s...\n", os.path.abspath(input_args.outdir))
for file in matched_files:
  process_file(file, input_args.outfile, input_args.outdir)

logger.info("All operations done\n")

if len(processed_files) > 0:
  max_str_len = max([len(path) for path in processed_files])
  result_str = "{0:<%d} -> {1}" % max_str_len

  for i in range(len(processed_files)):
    if i in range(len(written_files)):
      logger.info(result_str.format(processed_files[i], written_files[i]))

print()
