#!/usr/bin/env python3
#
# Android FDE Decryption
#
# Authors:  Thomas Cannon <tcannon@viaforensics.com>
#           Andrey Belenko <abelenko@viaforensics.com>
#           Cedric Halbronn <cedric.halbronn@sogeti.com>
# Requires: Python, M2Crypto (sudo apt-get install python-m2crypto)
#
# Parses the header for the encrypted userdata partition
# Decrypts the master key found in the header using a supplied password
# Decrypts the sectors of an encrypted userdata partition using the decrypted key
#
# --
# Revision 0.1 (released by Thomas)
# ------------
# Written for Nexus S (crespo) running Android 4.0.4
# Decrypts a given sector of an encrypted userdata partition using the decrypted key
# Header is located in file userdata_footer on the efs partition
#
# --
# Revision 0.2 (released by Cedric)
# ------------
# Rewritten to loop on all the sectors of the whole userdata partition
# Adapted to support HTC One running Android 4.2.2
# Header is located in "extra" partition located in mmcblk0p27
#

from collections import namedtuple
from Crypto.Cipher import DES
from fde import *

# Predefined odd parity table used to convert byte arrays
# Found here : https://github.com/humblejok/jok_des_tools/blob/master/src/des_tools/binary.py
ODD_PARITY_TABLE = [
    1,  1,  2,  2,  4,  4,  7,  7,  8,  8, 11, 11, 13, 13, 14, 14,
    16, 16, 19, 19, 21, 21, 22, 22, 25, 25, 26, 26, 28, 28, 31, 31,
    32, 32, 35, 35, 37, 37, 38, 38, 41, 41, 42, 42, 44, 44, 47, 47,
    49, 49, 50, 50, 52, 52, 55, 55, 56, 56, 59, 59, 61, 61, 62, 62,
    64, 64, 67, 67, 69, 69, 70, 70, 73, 73, 74, 74, 76, 76, 79, 79,
    81, 81, 82, 82, 84, 84, 87, 87, 88, 88, 91, 91, 93, 93, 94, 94,
    97, 97, 98, 98,100,100,103,103,104,104,107,107,109,109,110,110,
    112,112,115,115,117,117,118,118,121,121,122,122,124,124,127,127,
    128,128,131,131,133,133,134,134,137,137,138,138,140,140,143,143,
    145,145,146,146,148,148,151,151,152,152,155,155,157,157,158,158,
    161,161,162,162,164,164,167,167,168,168,171,171,173,173,174,174,
    176,176,179,179,181,181,182,182,185,185,186,186,188,188,191,191,
    193,193,194,194,196,196,199,199,200,200,203,203,205,205,206,206,
    208,208,211,211,213,213,214,214,217,217,218,218,220,220,223,223,
    224,224,227,227,229,229,230,230,233,233,234,234,236,236,239,239,
    241,241,242,242,244,244,247,247,248,248,251,251,253,253,254,254
]

# Apply the odd parity table to the given byte array
def DES_set_odd_parity(des_key):
    key = bytearray(8)
    for index in range(0,8):
        key[index] = ODD_PARITY_TABLE[des_key[index]]
    return key

def decrypt(encrypted_partition_files, sector_start, decrypted_key, outfile, debug=True, doogee=False, doogee_rid=None):

  outfd = open(outfile, 'wb')

  keySize = len(decrypted_key)
  assert(keySize == 16 or keySize == 32) # Other cases should be double checked
  if keySize == 16:
    algorithm='aes_128_cbc'
  elif keySize == 32:
    algorithm='aes_256_cbc'
  else:
    print('Error: unsupported keySize')
    return

  sector_offset = sector_start

  for encrypted_partition_file in encrypted_partition_files:

    # Check encrypted partition size is a multiple of sector size and open file
    fileSize = path.getsize(encrypted_partition_file)
    assert(fileSize % SECTOR_SIZE == 0)
    nb_sectors = fileSize // SECTOR_SIZE
    fd = open(encrypted_partition_file, 'rb')

    if doogee:
      # skip first 512 bytes
      encrypted_header = fd.read(SECTOR_SIZE)
      nb_sectors -= 1
      if doogee_rid is not None:
          with open(doogee_rid, 'rb') as ridfd:
              des_key = ridfd.read(8)
          des_key = DES_set_odd_parity(des_key)
          # Setup DES cipher in CFB mode, use des_key as IV
          cipher = DES.new(des_key, DES.MODE_CFB, iv=des_key, segment_size=64)
          decrypted_header = cipher.decrypt(encrypted_header)
          DOOGEE_HEADER_FORMAT = '<QI32sIc463s'
          doogee_header = namedtuple('DoogeeHeader', 'size file_count md5 encrypt unknown padding')
          header_dict = doogee_header._asdict(doogee_header._make(struct.unpack(DOOGEE_HEADER_FORMAT, decrypted_header)))
          md5_header = header_dict['md5'].decode('utf-8')
          print('md5 in header', md5_header)
          md5_computed = hashlib.md5(fd.read()).hexdigest()
          print('md5 computed ', md5_computed)
          assert (md5_header == md5_computed), f'Checksums {md5_header} and {md5_computed} do not match'
          fd.seek(SECTOR_SIZE) # reset file position

    # Decrypt one sector at a time
    for i in range(0, nb_sectors):

      # Read encrypted sector
      encrypted_data = fd.read(SECTOR_SIZE)
    
      # Calculate ESSIV
      # ESSIV mode is defined by:
      # SALT=Hash(KEY)
      # IV=E(SALT,sector_number)
      salt = hashlib.sha256(decrypted_key).digest()
      sector_number = struct.pack("<I", sector_offset) + b"\x00" * (BLOCK_SIZE - 4)
      
      # Since our ESSIV hash is SHA-256 we should use AES-256
      # We use ECB mode here (instead of CBC with IV of all zeroes) due to crypto lib weirdness
      # EVP engine PKCS7-pads data by default so we explicitly disable that
      cipher = EVP.Cipher(alg='aes_256_ecb', key=salt, iv=b'', padding=0, op=ENCRYPT)
      essiv = cipher.update(sector_number)
      essiv += cipher.final()
      
      if debug:
        print('SECTOR NUMBER  :', "0x" + sector_number.hex().upper())
        print('ESSIV SALT     :', "0x" + salt.hex().upper())
        print('ESSIV IV       :', "0x" + essiv.hex().upper())
        print('----------------')
      
      # Decrypt sector of userdata image
      decrypted_data = decrypt_data(decrypted_key, essiv, encrypted_data)
      
      # Print the decrypted data
      if debug:
        print('Decrypted Data :', "0x" + decrypted_data.hex().upper())
      outfd.write(decrypted_data)

      sector_offset += 1

    fd.close()
  outfd.close()

def main():

  parser = argparse.ArgumentParser(description='FDE for Android')

  parser.add_argument('input_encrypted_partition_files', help='The encrypted /data partition files', nargs='+')
  parser.add_argument('--input-metadata', required=True, help='The header file containing the encrypted key')
  parser.add_argument('--output-decrypted', required=True, help='The filename to save the decrypted partition')
  parser.add_argument('--password', help='Provided password. Default is "0000"', default='0000')
  parser.add_argument('--sector', help='Sector number for the first bytes in case there if only one file encrypted partition file. It allows to decrypt data dumped at a particular offset. Default is 0', default=0, type=int)
  parser.add_argument('--doogee', action='store_true', required=False, help='Indicate Doogee backup files')
  parser.add_argument('--input-doogee-rid', required=False, help='The Doogee /proc/rid file')
  args = parser.parse_args()

  outfile = args.output_decrypted
  header_file = args.input_metadata
  encrypted_partition_files = args.input_encrypted_partition_files
  doogee = args.doogee
  doogee_rid = args.input_doogee_rid
  assert path.isfile(header_file), "Header file '%s' not found." % header_file
  for encrypted_partition_file in encrypted_partition_files:
    assert path.isfile(encrypted_partition_file), "Encrypted partition '%s' not found." % encrypted_partition_file
  if doogee_rid:
    assert path.isfile(doogee_rid), "Doogee rid file '%s' not found." % doogee_rid
  password = args.password.encode('utf-8')
  sector_start = args.sector

  # Parse header
  encrypted_key, salt = parse_header(header_file)

  # Get decrypted key
  decrypted_key = get_decrypted_key(encrypted_key, salt, password)

  # Loop on sectors
  decrypt(encrypted_partition_files, sector_start, decrypted_key, outfile, debug=False, doogee=doogee, doogee_rid=doogee_rid)

  print('Decrypted partition written to: %s' % outfile)
  print('Done.')

if __name__ == "__main__":

  main()
