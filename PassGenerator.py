import itertools
import math


"""
 @owner : PJW
 @brief : to make password generator
 @date : 2016.05.13
"""
class PassGenerator:

  """
    @writer : JSH
    @obj: class constructor
    @param : target of chars written by user, target of password length
    @return : None
  """
  def __init__(self, target_chars, target_length):
    self.length = target_length
    self.target_chars = target_chars
    self.total_num_case = self._total_case(target_chars, target_length)
    self.pass_generator = iter(self.make_generator(target_length, target_chars))
    self.offset = 0

  """
    @writer : JSH
    @obj : to make password generator
    @param : target of length, target of characters
    @return : yield each password
  """
  def make_generator(self, target_length, target_chars):
    for length_pass in xrange(1, target_length+1):
      attempt = itertools.product(target_chars, repeat=length_pass)
      for att in attempt:
        brute = "".join(att)
        self.offset += 1
        yield brute

  """
    @writer : JSH
    @obj : to make total number of cases
    @param : length of chars, length of password
    @return : total number of cases
  """
  def _total_case(self, len_char, tar_len):
    len_char = len(len_char)
    return (len_char ** (tar_len + 1) - len_char) / (len_char - 1)


def test():
  test = PassGenerator('tes' , 3)
  print test.target_chars, test.length, test.total_num_case, [i for i in test.pass_generator], test.offset

if __name__ == "__main__":
  test()
