#-*- coding : utf-8 -*-

import sys, string, os,  struct, json
import Crypto.Cipher.AES
import itertools
import hashlib

def aes_cbc_decrypt(key, iv, cphertext):
    return Crypto.Cipher.AES.new(key, Crypto.Cipher.AES.MODE_CBC, iv).decrypt(ciphertext)

def load_from_filename(wallet_filename):
    wallet_filename = os.path.abspath(wallet_filename)
    import bsddb3.db
    db_env = bsddb3.db.DBEnv()
    try:
        db_env.open(os.path.dirname(wallet_filename), bsddb3.db.DB_CREATE | bsddb3.db.DB_INIT_MPOOL)
        db = bsddb3.db.DB(db_env)
        db.open(wallet_filename, b"main", bsddb3.db.DB_BTREE, bsddb3.db.DB_RDONLY)
    except UnicodeEncodeError:
        error_exit("the entire path and filename of Bitcoin Core wallets should be entirely ASCII")
    mkey = db.get(b"\x04mkey\x01\x00\x00\x00")
    db.close()
    db_env.close()

    # if not mkey:
    #     raise ValueError("Encrypted master key #1 not found in the Bitcoin Core wallet file.\n"+
    #                      "(is this wallet encrypted? is this a standard Bitcoin Core wallet?)")
        # This is a little fragile because it assumes the encrypted key and salt sizes are
        # 48 and 8 bytes long respectively, which although currently true may not always be
        # (it will loudly fail if this isn't the case; if smarter it could gracefully succeed):
    # self = cls(loading=True)

    encrypted_master_key, salt, method, iter_count = struct.unpack_from(b"< 49p 9p I I", mkey)
    # print encrypted_master_key
    return encrypted_master_key, salt, method, iter_count
    # if method != 0: raise NotImplementedError("Unsupported Bitcoin Core key derivation method " + tstr(method))
    #
          # only need the final 2 encrypted blocks (half of it padding) plus the salt and iter_count saved above
    # self._part_encrypted_master_key = encrypted_master_key[-32:]
    # return self

def making_random_chars(chars, length):
    for length_pass in xrange(1, length+1):
        attemp = itertools.product(chars, repeat=length_pass)
        for att in attemp:
            brute = "".join(att)
            yield brute 

def return_password_or_false(passwords, salt, iteration_count, encrypted_m_key):
    sha_obj = hashlib.sha512
    encoded_passwords = itertools.imap(lambda p : p.encode("utf_8", "ignore"), passwords)

    for count, pass_word in enumerate(encoded_passwords, start=1):
        derived_key = pass_word+salt
        for i in xrange(iteration_count):
            derived_key = sha_obj(derived_key).digest()
        part_master_key = aes256_cbc_decrypt(derived_key[:32], encrypted_m_key[-32:][:16], encrypted_m_key[-32:][16:])

        if part_master_key == b"\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10":
            return pass_word, count
    return false, count

if __name__=='__main__':
    # wallet_filename = input("write \"filePath/filename\" : ")
    file_name = sys.argv[1]
    res = load_from_filename(file_name)
    print res[0].decode("utf-8", "ignore")
