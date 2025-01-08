from itertools import accumulate, batched

from Cryptodome.Cipher import DES


class Block:
    def __init__(self, string_or_bytes: str | bytes, is_binary_string: bool = False):
        if is_binary_string:
            bit_size = len(string_or_bytes)
            block = string_or_bytes
        else:
            bit_size = len(string_or_bytes) * 8
            block = int.from_bytes(string_or_bytes, byteorder='big')
            block = bin(block)[2:].zfill(bit_size)
        self.block = block
        self.bit_size = bit_size

    def __str__(self):
        return self.block

    def __xor__(self, other):
        if self.bit_size != other.bit_size:
            raise ValueError("Blocks must have the same bit size!")
        value = int(self.block, 2) ^ int(other.block, 2)
        binary_string = bin(value)[2:].zfill(self.bit_size)
        return Block(binary_string, is_binary_string=True)

    def __getitem__(self, index):
        return self.block[index]

    def __lshift__(self, n):
        return Block(self.block[n:] + self.block[:n], is_binary_string=True)

    def __add__(self, other):
        return Block(self.block + other.block, is_binary_string=True)

    def bytes(self) -> bytes:
        return int(self.block, 2).to_bytes(self.bit_size // 8, byteorder='big')

    def map_with_table(self, table: list[int]) -> 'Block':
        binary_string = ''.join(map(lambda x: self[x - 1], table))
        return Block(binary_string, is_binary_string=True)


class MyDES:
    def __init__(self, key: bytes):
        self.key = key

    def encrypt(self, plaintext: bytes) -> bytes:
        return self.encrypt_or_decrypt(plaintext)

    def decrypt(self, ciphertext: bytes) -> bytes:
        return self.encrypt_or_decrypt(ciphertext, is_encrypt=False)

    def encrypt_or_decrypt(self, data: bytes, is_encrypt: bool = True) -> bytes:
        key_block = Block(self.key)
        data_block = Block(data)
        round_key_blocks = MyDES.get_round_keys(key_block)
        if not is_encrypt:
            round_key_blocks.reverse()
        L, R = MyDES.IP(data_block)
        for round_key_block in round_key_blocks:
            L, R = R, L ^ MyDES.f(R, round_key_block)
        L, R = R, L
        data_block = MyDES.IP_inverse(L + R)
        return data_block.bytes()

    @staticmethod
    def PC1(block: Block) -> tuple[Block, Block]:
        table = [57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, 10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36, 63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4]
        block = block.map_with_table(table)
        half_block_size = block.bit_size // 2
        return Block(block[:half_block_size], is_binary_string=True), Block(block[half_block_size:], is_binary_string=True)

    @staticmethod
    def PC2(block: Block) -> Block:
        table = [14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2, 41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32]
        return block.map_with_table(table)

    @staticmethod
    def get_round_keys(key_block: Block) -> list[Block]:
        table = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]
        L, R = MyDES.PC1(key_block)
        L_R_pairs = map(lambda x: (L << x, R << x), accumulate(table))
        round_keys = list(map(lambda L_R_pair: MyDES.PC2(L_R_pair[0] + L_R_pair[1]), L_R_pairs))
        return round_keys

    @staticmethod
    def IP(block: Block) -> tuple[Block, Block]:
        table = [58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4, 62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8, 57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3, 61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7]
        block = block.map_with_table(table)
        half_block_size = block.bit_size // 2
        return Block(block[:half_block_size], is_binary_string=True), Block(block[half_block_size:], is_binary_string=True)

    @staticmethod
    def E(block: Block) -> Block:
        table = [32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17, 16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25, 24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1]
        return block.map_with_table(table)

    @staticmethod
    def S(block: Block) -> Block:
        tables = [
            [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7, 0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8, 4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0, 15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13],
            [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10, 3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5, 0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15, 13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9],
            [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8, 13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1, 13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7, 1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12],
            [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15, 13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9, 10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4, 3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14],
            [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9, 14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6, 4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14, 11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3],
            [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11, 10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8, 9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6, 4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13],
            [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1, 13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6, 1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2, 6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12],
            [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7, 1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2, 7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8, 2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11],
        ]
        row_col_pairs = map(lambda batch: (int(batch[0] + batch[-1], 2), int(''.join(batch[1:-1]), 2)), batched(block, 6))
        output_indexes = map(lambda row_col_pair: row_col_pair[0] * 16 + row_col_pair[1], row_col_pairs)
        output_values = map(lambda table_output_index_pair: tables[table_output_index_pair[0]][table_output_index_pair[1]], enumerate(output_indexes))
        output_string = ''.join(map(lambda x: bin(x)[2:].zfill(4), output_values))
        return Block(output_string, is_binary_string=True)

    @staticmethod
    def P(block: Block) -> Block:
        table = [16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10, 2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25]
        return block.map_with_table(table)

    @staticmethod
    def f(R: Block, round_key_block: Block) -> Block:
        R = MyDES.E(R)
        R ^= round_key_block
        R = MyDES.S(R)
        R = MyDES.P(R)
        return R

    @staticmethod
    def IP_inverse(block: Block) -> Block:
        table = [40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31, 38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29, 36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27, 34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25]
        return block.map_with_table(table)


if __name__ == '__main__':
    key = "12345678".encode()
    data = 'abcdefgh'.encode()
    my_des = MyDES(key)
    des = DES.new(key, DES.MODE_ECB)
    encrypted_data1 = my_des.encrypt(data)
    encrypted_data2 = des.encrypt(data)
    print(encrypted_data1.hex())
    print(encrypted_data2.hex())
    decrypted_data1 = my_des.decrypt(encrypted_data1)
    decrypted_data2 = des.decrypt(encrypted_data2)
    print(decrypted_data1.hex())
    print(decrypted_data2.hex())
