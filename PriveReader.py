#-*- coding : utf-8 -*-
import sys
import string
import os
import struct
import json
import bsddb3.db

'''
@writer: KHK
@brief: read a privaKey
@date: 2016.05.13
'''
class PrivReader:

  '''
  @writer: KHK
  @obj : constructor
  @param: this is file name
  @return: None
  '''
  def __init__(self, file_name):
    # self.wallet_filename = file_name
    self.decypted_priv_key = self._read_from_data(file_name)[0]
    self.part_enc_master_key = self.decypted_priv_key[-32:]
    self.file_path = os.path.abspath(file_name)
    self.iter_count = self._read_from_data(file_name)[3]
    self.method = self._read_from_data(file_name)[2]
    self.salt = self._read_from_data(file_name)[1]
# .decode("utf-8","ignore")
  # '''
  # @writer: hwisdom
  # @read_data : read a file name
  # @param: none
  # @return: absolute file path
  # '''
  # def _read_abs_path(self, filename):
  #   return os.path.abspath(filename)
  #   # return file_path

  # '''
  # @writer: hwisdom
  # @make_bk_env :
  # @param: file_path
  # @return:
  # '''
  # def make_bk_env(self, file_path):
  #   # import bsddb3.db
  #   db_env = bsddb3.db.DBEnv()
  #   try:
  #     db_env.open(os.path.dirname(self.wallet_filename), bsddb3.db.DB_CREATE | bsddb3.db.DB_INIT_MPOOL)
  #     db = bsddb3.db.DB(db_env)
  #     db.open(self.wallet_filename, b"main", bsddb3.db.DB_BTREE, bsddb3.db.DB_RDONLY)
  #   except UnicodeEncodeError:
  #     error_exit("the entire path and filename of Bitcoin Core wallets should be entirely ASCII")
  #   mkey = db.get(b"\x04mkey\x01\x00\x00\x00")
  #   db.close()
  #   db_env.close()

    '''
    @writer: KHK
    @obj : to get encrypted master key, salt, method, and iteration count
    @param: target filename
    @return: encrypted key, salt, method, and iteration count
    '''
  def _read_from_data(self, filename):
    db_env = bsddb3.db.DBEnv()
    try:
      db_env.open(os.path.dirname(filename), bsddb3.db.DB_CREATE | bsddb3.db.DB_INIT_MPOOL)
      db = bsddb3.db.DB(db_env)
      db.open(filename, b"main", bsddb3.db.DB_BTREE, bsddb3.db.DB_RDONLY)
    except UnicodeEncodeError:
      error_exit("the entire path and filename of Bitcoin Core wallets should be entirely ASCII")
    mkey = db.get(b"\x04mkey\x01\x00\x00\x00")
    encrypted_master_key, salt, method, iter_count = struct.unpack_from(b"< 49p 9p I I", mkey)
    db.close()
    db_env.close()
    return encrypted_master_key, salt, method, iter_count


if __name__=='__main__':
    file_name = sys.argv[1]
    resObj = PrivReader(file_name)
    print resObj.decypted_priv_key
    print resObj.salt
    print resObj.method
    print resObj.iter_count
