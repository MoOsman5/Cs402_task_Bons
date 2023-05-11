import string
import collections

from typing import Iterable, List, Optional, Tuple


def is_space(char: int) -> bool:
   return char == 0x00 or chr(char) in string.ascii_letters


def xor(a: bytearray, b: bytearray) -> List[int]:
    return [c ^ d for c, d in zip(a, b)]


def track_spaces(text: List[int]) -> collections.Counter:
    counter: collections.Counter = collections.Counter()
    for index, char in enumerate(text):
        if is_space(char):
            counter[index] += 1

    return counter


def recover_partial_key(ciphertexts):
    shortest_text = min(len(text) for text in ciphertexts)
    key: List[Optional[int]] = [None for _ in range(shortest_text)]

    for main_index, main_ciphertext in enumerate(ciphertexts):
        main_counter: collections.Counter = collections.Counter()

        for secondary_index, secondary_ciphertext in enumerate(ciphertexts):
            if main_index != secondary_index:
                main_counter.update(track_spaces(xor(main_ciphertext, secondary_ciphertext)))

        for index, count in main_counter.items():
            if count == len(ciphertexts) - 1:
                key[index] = ord(' ') ^ main_ciphertext[index]

    return key


def recover_key(ciphertexts: Iterable[bytearray]) -> List[Optional[int]]:
    sorted_ciphertexts = sorted(ciphertexts, key=len)
    key: List[Optional[int]] = []

    while len(sorted_ciphertexts) > 1:
        key += recover_partial_key(sorted_ciphertexts)

        string_length = len(sorted_ciphertexts[0])
        sorted_ciphertexts = sorted_ciphertexts[1:]
        for i in range(len(sorted_ciphertexts)):
            sorted_ciphertexts[i] = sorted_ciphertexts[i][string_length:]

    return key


c = open('ct.txt').read().splitlines()
cb = list(map(bytearray.fromhex, c))
key = recover_key(cb)
xx = [format(k, '02x') if k is not None else '??' for k in key]
p = [[chr(int(k, 16) ^ ct) if (k is not None and k != '??') else '?' for k, ct in zip(xx, cbt)] for cbt in cb]
print('-', end='')
print('\n\n\n-'. join([' '.join(i) for i in p]))