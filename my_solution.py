#!/usr/bin/env python3

ROUND_CONSTANTS = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
    0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
]

IV = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c,
    0x1f83d9ab, 0x5be0cd19
]


def add32(*args: int) -> int:
  return sum(args) & 0xffff_ffff


def rightrotate32(x: int, n: int) -> int:
  return add32(x >> n, x << (32 - n))


def little_sigma0(x: int) -> int:
  return rightrotate32(x, 7) ^ rightrotate32(x, 18) ^ (x >> 3)


def little_sigma1(x: int) -> int:
  return rightrotate32(x, 17) ^ rightrotate32(x, 19) ^ (x >> 10)


def big_sigma0(x: int) -> int:
  return rightrotate32(x, 2) ^ rightrotate32(x, 13) ^ rightrotate32(x, 22)


def big_sigma1(x: int) -> int:
  return rightrotate32(x, 6) ^ rightrotate32(x, 11) ^ rightrotate32(x, 25)


def message_schedule(block: bytes) -> list[int]:
  w = []
  for i in range(64):
    if i < 16:
      w.append(int.from_bytes(block[4 * i:4 * i + 4], "big"))
    else:
      s0 = little_sigma0(w[i - 15])
      s1 = little_sigma1(w[i - 2])
      w.append(add32(w[i - 16], s0, w[i - 7], s1))
  return w


def choice(x: int, y: int, z: int) -> int:
  return (x & y) ^ (~x & z)


def majority(x: int, y: int, z: int) -> int:
  return (x & y) ^ (x & z) ^ (y & z)


# pylint: disable-next=redefined-builtin
def round(state: list[int], round_constant: int,
          schedule_word: int) -> list[int]:
  ch = choice(state[4], state[5], state[6])
  temp1 = add32(state[7], big_sigma1(state[4]), ch, round_constant,
                schedule_word)
  maj = majority(state[0], state[1], state[2])
  temp2 = add32(big_sigma0(state[0]), maj)
  new_state = [
      add32(temp1, temp2),
      state[0],
      state[1],
      state[2],
      add32(state[3], temp1),
      state[4],
      state[5],
      state[6],
  ]
  return new_state


def compress(input_state: list[int], block: bytes) -> list[int]:
  w = message_schedule(block)
  state = input_state.copy()
  for i in range(64):
    state = round(state, ROUND_CONSTANTS[i], w[i])
  for i in range(8):
    state[i] = add32(state[i] + input_state[i])
  return state


def padding(message_length: int) -> bytes:
  remainder_bytes = (message_length + 8) % 64
  filler_bytes = 64 - remainder_bytes
  padding_bytes = bytearray(filler_bytes + 8)
  padding_bytes[0] = 0x80
  padding_bytes[filler_bytes:filler_bytes + 8] = (message_length * 8).to_bytes(
      8, "big")
  return bytes(padding_bytes)


def sha256(message: bytes) -> bytes:
  padded_message = message + padding(len(message))
  assert len(padded_message) % 64 == 0
  state = IV.copy()
  for offset in range(0, len(padded_message), 64):
    state = compress(state, padded_message[offset:offset + 64])
  return bytes().join(x.to_bytes(4, "big") for x in state)


def synthesize(original_input: bytes, chosen_suffix: bytes) -> bytes:
  return original_input + padding(len(original_input)) + chosen_suffix


def reconstitute_state(original_hash: bytes) -> list[int]:
  return [
      int.from_bytes(original_hash[offset:offset + 4], "big")
      for offset in range(0, len(original_hash), 4)
  ]


def length_extend(original_hash: bytes, original_len: int,
                  suffix: bytes) -> bytes:
  extended_len = original_len + len(padding(original_len)) + len(suffix)
  new_padding = padding(extended_len)
  padded_suffix = suffix + new_padding
  assert len(padded_suffix) % 64 == 0
  state = reconstitute_state(original_hash)
  for offset in range(0, len(padded_suffix), 64):
    state = compress(state, padded_suffix[offset:offset + 64])
  return bytes().join(x.to_bytes(4, "big") for x in state)


def main() -> None:
  # pylint: disable=import-outside-toplevel
  import json
  import sys

  inputs = json.load(sys.stdin)
  outputs = {}

  outputs["problem1"] = [add32(x, y) for x, y in inputs["problem1"]]
  outputs["problem2"] = [rightrotate32(x, n) for x, n in inputs["problem2"]]
  outputs["problem3"] = little_sigma0(inputs["problem3"])
  outputs["problem4"] = little_sigma1(inputs["problem4"])
  outputs["problem5"] = message_schedule(inputs["problem5"].encode())
  outputs["problem6"] = big_sigma0(inputs["problem6"])
  outputs["problem7"] = big_sigma1(inputs["problem7"])
  outputs["problem8"] = choice(*inputs["problem8"])
  outputs["problem9"] = majority(*inputs["problem9"])
  outputs["problem10"] = round(inputs["problem10"]["state"],
                               inputs["problem10"]["round_constant"],
                               inputs["problem10"]["schedule_word"])
  outputs["problem11"] = compress(inputs["problem11"]["state"],
                                  inputs["problem11"]["block"].encode())
  outputs["problem12"] = [padding(x).hex() for x in inputs["problem12"]]
  outputs["problem13"] = [sha256(x.encode()).hex() for x in inputs["problem13"]]
  outputs["problem14"] = synthesize(
      inputs["problem14"]["original_input"].encode(),
      inputs["problem14"]["chosen_suffix"].encode()).hex()
  outputs["problem15"] = reconstitute_state(bytes.fromhex(inputs["problem15"]))
  outputs["problem16"] = length_extend(
      bytes.fromhex(inputs["problem16"]["original_hash"]),
      inputs["problem16"]["original_len"],
      inputs["problem16"]["chosen_suffix"].encode()).hex()

  json.dump(outputs, sys.stdout)


if __name__ == "__main__":
  main()
