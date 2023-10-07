from sha256 import SHA256


def reconstitute_state(original_hash: bytes) -> list[int]:
  return [
      int.from_bytes(original_hash[offset:offset + 4], "big")
      for offset in range(0, len(original_hash), 4)
  ]


def length_extend(original_hash: bytes, original_len: int,
                  suffix: bytes) -> bytes:
  extended_len = original_len + len(SHA256.padding(original_len)) + len(suffix)
  new_padding = SHA256.padding(extended_len)
  padded_suffix = suffix + new_padding
  assert len(padded_suffix) % 64 == 0
  state = reconstitute_state(original_hash)
  for offset in range(0, len(padded_suffix), 64):
    SHA256.compress(state, padded_suffix[offset:offset + 64])
  return bytes().join(x.to_bytes(4, "big") for x in state)


def main() -> None:
  # pylint: disable=import-outside-toplevel
  import json
  import sys

  inputs = json.load(sys.stdin)
  outputs = {}

  # Problem 1: addition modulo 2^32
  outputs["problem1"] = [(x + y) & 0xffff_ffff for x, y in inputs["problem1"]]

  # Problem 2: bitwise right rotation
  outputs["problem2"] = [
      (x >> n) + (x << (32 - n)) & 0xffff_ffff for x, n in inputs["problem2"]
  ]

  # Problem 3: little_sigma0()
  x = inputs["problem3"]
  little_sigma0 = ((x >> 7 | x << 25) ^ (x >> 18 | x << 14) ^
                   (x >> 3)) & 0xffff_ffff
  outputs["problem3"] = little_sigma0

  # Problem 4: little_sigma1()
  x = inputs["problem4"]
  little_sigma1 = ((x >> 17 | x << 15) ^ (x >> 19 | x << 13) ^
                   (x >> 10)) & 0xffff_ffff
  outputs["problem4"] = little_sigma1

  # Problem 5: the message schedule
  outputs["problem5"] = SHA256.message_schedule(inputs["problem5"].encode())

  # Problem 6: big_sigma0()
  x = inputs["problem6"]
  big_sigma0 = ((x >> 2 | x << 30) ^ (x >> 13 | x << 19) ^
                (x >> 22 | x << 10)) & 0xffff_ffff
  outputs["problem6"] = big_sigma0

  # Problem 7: big_sigma1()
  x = inputs["problem7"]
  big_sigma1 = ((x >> 6 | x << 26) ^ (x >> 11 | x << 21) ^
                (x >> 25 | x << 7)) & 0xffff_ffff
  outputs["problem7"] = big_sigma1

  # Problem 8: choice()
  x, y, z = inputs["problem8"]
  choice = (x & y) ^ (~x & z)
  outputs["problem8"] = choice

  # Problem 9: majority()
  x, y, z = inputs["problem9"]
  majority = (x & y) ^ (x & z) ^ (y & z)
  outputs["problem9"] = majority

  # Problem 10: the round function
  state = inputs["problem10"]["state"].copy()
  round_constant = inputs["problem10"]["round_constant"]
  schedule_word = inputs["problem10"]["schedule_word"]
  SHA256.round(state, round_constant, schedule_word)
  outputs["problem10"] = state

  # Problem 11: the compression function
  state = inputs["problem11"]["state"].copy()
  block = inputs["problem11"]["block"].encode()
  SHA256.compress(state, block)
  outputs["problem11"] = state

  # Problem 12: padding
  outputs["problem12"] = [SHA256.padding(x).hex() for x in inputs["problem12"]]

  # Problem 13: the hash function
  outputs["problem13"] = []
  for x in inputs["problem13"]:
    sha256 = SHA256()
    sha256.update(x.encode())
    outputs["problem13"].append(sha256.hexdigest())

  # Problem 14: modeling the extended input
  original_input = inputs["problem14"]["original_input"].encode()
  chosen_suffix = inputs["problem14"]["chosen_suffix"].encode()
  outputs["problem14"] = (original_input + SHA256.padding(len(original_input)) +
                          chosen_suffix).hex()

  # Problem 15: recovering the state
  outputs["problem15"] = reconstitute_state(bytes.fromhex(inputs["problem15"]))

  # Problem 16: the length extension attack
  original_hash = bytes.fromhex(inputs["problem16"]["original_hash"])
  original_len = inputs["problem16"]["original_len"]
  chosen_suffix = inputs["problem16"]["chosen_suffix"].encode()
  outputs["problem16"] = length_extend(original_hash, original_len,
                                       chosen_suffix).hex()

  json.dump(outputs, sys.stdout)


if __name__ == "__main__":
  main()
