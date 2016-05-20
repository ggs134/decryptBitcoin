import PassGenerator as pg
import PriveReader as pr
import argparse
import hashlib
import Crypto.Cipher.AES
import time

def main():
    sha512 = hashlib.sha512
    parser = argparse.ArgumentParser()
    parser.add_argument("file", help="file name or path", type=str)
    parser.add_argument("character", help="brute force target characters", type=str)
    parser.add_argument("length", help="target length of password", type=int)
    args = parser.parse_args()
    if args.file and args.character and args.length:
        reader = pr.PrivReader(str(args.file))
        gen_obj = pg.PassGenerator(args.character, args.length)
        pass_gen = gen_obj.pass_generator
        total_case = gen_obj.total_num_case
        salt = reader.salt
        count = reader.iter_count
        enc_master_key = reader.part_enc_master_key
        duration = 1
        for password in pass_gen:
            s_time=time.time()
            print("{}/{} {} attempt... {}H/sec second".format(gen_obj.offset,total_case,password,1.0/duration))
            derived_key = password+salt
            for i in xrange(count):
                derived_key = sha512(derived_key).digest()
            part_master_key = _aes256_cbc_decrypt(derived_key[:32], enc_master_key[:16], enc_master_key[16:])
            # print part_master_key
            if part_master_key == b"\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10":
                e_time = time.time()
                print("got it! : {}".format(password))
                return password, count
            else:
                e_time = time.time()
                duration = e_time-s_time
                pass
        print("fail...")
        return

def _aes256_cbc_decrypt(key, iv, ciphertext):
    new_aes = Crypto.Cipher.AES.new
    return new_aes(key, Crypto.Cipher.AES.MODE_CBC, iv).decrypt(ciphertext)

if __name__=="__main__":
    main()
