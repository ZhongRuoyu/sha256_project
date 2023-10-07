#!/usr/bin/env python3


class SHA256:
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

  _state: list[int]
  _block: bytearray
  _length: int

  def __init__(self) -> None:
    self._state = SHA256.IV.copy()
    self._block = bytearray(64)
    self._length = 0

  @staticmethod
  def message_schedule(block: bytes) -> list[int]:
    w = []
    for i in range(64):
      if i < 16:
        w.append(int.from_bytes(block[4 * i:4 * i + 4], "big"))
      else:
        s0 = ((w[i - 15] >> 7 | w[i - 15] << 25) ^
              (w[i - 15] >> 18 | w[i - 15] << 14) ^
              (w[i - 15] >> 3)) & 0xffff_ffff
        s1 = ((w[i - 2] >> 17 | w[i - 2] << 15) ^
              (w[i - 2] >> 19 | w[i - 2] << 13) ^
              (w[i - 2] >> 10)) & 0xffff_ffff
        w.append((w[i - 16] + s0 + w[i - 7] + s1) & 0xffff_ffff)
    return w

  @staticmethod
  def round(state: list[int], round_constant: int, schedule_word: int) -> None:
    choice = (state[4] & state[5]) ^ (~state[4] & state[6])
    big_sigma1 = ((state[4] >> 6 | state[4] << 26) ^
                  (state[4] >> 11 | state[4] << 21) ^
                  (state[4] >> 25 | state[4] << 7)) & 0xffff_ffff
    temp1 = (state[7] + big_sigma1 + choice + round_constant +
             schedule_word) & 0xffff_ffff
    majority = (state[0] & state[1]) ^ (state[0] & state[2]) ^ (
        state[1] & state[2])
    big_sigma0 = ((state[0] >> 2 | state[0] << 30) ^
                  (state[0] >> 13 | state[0] << 19) ^
                  (state[0] >> 22 | state[0] << 10)) & 0xffff_ffff
    temp2 = (big_sigma0 + majority) & 0xffff_ffff
    state[7] = state[6]
    state[6] = state[5]
    state[5] = state[4]
    state[4] = (state[3] + temp1) & 0xffff_ffff
    state[3] = state[2]
    state[2] = state[1]
    state[1] = state[0]
    state[0] = (temp1 + temp2) & 0xffff_ffff

  @staticmethod
  def compress(state: list[int], block: bytes) -> None:
    w = SHA256.message_schedule(block)
    input_state = state.copy()
    for i in range(64):
      SHA256.round(state, SHA256.ROUND_CONSTANTS[i], w[i])
    for i in range(8):
      state[i] = (state[i] + input_state[i]) & 0xffff_ffff

  @staticmethod
  def padding(message_length: int) -> bytes:
    remainder_bytes = (message_length + 8) % 64
    filler_bytes = 64 - remainder_bytes
    padding_bytes = bytearray(filler_bytes + 8)
    padding_bytes[0] = 0x80
    padding_bytes[filler_bytes:filler_bytes + 8] = (message_length *
                                                    8).to_bytes(8, "big")
    return bytes(padding_bytes)

  def update(self, data: bytes) -> None:
    for i in range(len(data)):
      self._block[self._length % 64] = data[i]
      self._length += 1
      if self._length % 64 == 0:
        SHA256.compress(self._state, self._block)

  def digest(self) -> bytes:
    padded_buffer = self._block[:self._length % 64] + SHA256.padding(
        self._length)
    assert len(padded_buffer) in (64, 128)
    state = self._state.copy()
    for offset in range(0, len(padded_buffer), 64):
      SHA256.compress(state, padded_buffer[offset:offset + 64])
    return bytes().join(x.to_bytes(4, "big") for x in state)

  def hexdigest(self) -> str:
    return self.digest().hex()

  def copy(self) -> "SHA256":
    # pylint: disable=protected-access
    new_copy = SHA256()
    new_copy._state = self._state.copy()
    new_copy._block = self._block.copy()
    new_copy._length = self._length
    return new_copy


def main() -> None:
  import sys

  # pylint: disable-next=invalid-name
  BUFFER_SIZE = 2**20  # 1 MiB

  sha256 = SHA256()
  while True:
    buffer = sys.stdin.buffer.read(BUFFER_SIZE)
    if not buffer:
      break
    sha256.update(buffer)
  print(sha256.hexdigest())


if __name__ == "__main__":
  main()
