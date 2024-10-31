from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QLineEdit, QPushButton, QLabel, QComboBox, QScrollArea, QWidget as QScrollWidget, QHBoxLayout

class S_AES:
    def __init__(self, key):
        if len(key) != 16 or not all(c in '01' for c in key):
            raise ValueError("密钥必须是16位二进制数")
        self.key = key
        self.round_keys = []
        self.s_box = [
            ["1001", "0100", "1010", "1011"],
            ["1101", "0001", "1000", "0101"],
            ["0110", "0010", "0000", "0011"],
            ["1100", "1110", "1111", "0111"]
        ]
        self.inv_s_box = [
            ["1010", "0101", "1001", "1011"],
            ["0001", "0111", "1000", "1111"],
            ["0110", "0000", "0010", "0011"],
            ["1100", "0100", "1101", "1110"]
        ]
        self.rcon = ['10000000', '00110000']
        self.key_expansion()

    def xor_strings(self, string, key):
        """对两个二进制字符串进行异或操作。"""
        return ''.join(['0' if s == k else '1' for s, k in zip(string, key)])

    def key_expansion(self):
        """扩展密钥为多个轮密钥"""
        self.round_keys = [self.key[i:i + 8] for i in range(0, 16, 8)]
        self.round_keys.append(self.xor_strings(self.round_keys[0], self.g(self.round_keys[1], 1)))
        self.round_keys.append(self.xor_strings(self.round_keys[1], self.round_keys[2]))
        self.round_keys.append(self.xor_strings(self.round_keys[2], self.g(self.round_keys[3], 2)))
        self.round_keys.append(self.xor_strings(self.round_keys[3], self.round_keys[4]))

    def multiply(self, binary_str, n):
        """对输入的二进制字符串进行GF(2^4)乘法运算"""
        multiplication_table = {
            2: [0, 2, 4, 6, 8, 10, 12, 14, 3, 1, 7, 5, 11, 9, 15, 13],
            4: [0, 4, 8, 12, 3, 7, 11, 15, 6, 2, 14, 10, 5, 1, 13, 9],
            9: [0, 9, 1, 8, 2, 11, 3, 10, 4, 13, 5, 12, 6, 15, 7, 14]
        }
        int_value = int(binary_str, 2)
        return '{:04b}'.format(multiplication_table[n][int_value])

    def g(self, w, n):
        """生成轮密钥"""
        substituted = self.substitute_bytes(w[4:8], 1) + self.substitute_bytes(w[0:4], 1)
        return self.xor_strings(substituted, self.rcon[n - 1])

    def substitute_bytes(self, nibble, mode):
        """替换字节"""
        row = int(nibble[:2], 2)
        col = int(nibble[2:], 2)
        if mode == 1:
            return self.s_box[row][col]
        else:
            return self.inv_s_box[row][col]

    def byte_substitution(self, binary_str, mode):
        """对输入的16位字符串进行半字节替代"""
        substituted = ''
        for i in range(4):
            substituted += self.substitute_bytes(binary_str[i * 4:(i + 1) * 4], mode)
        return substituted

    def column_mixing(self, binary_str, mode):
        """进行列混淆操作"""
        mixed = ""
        for i in range(4):
            if mode == 1:  # 第一轮列混淆
                if i % 2:  # 单数1，3
                    mixed += self.xor_strings(binary_str[i * 4:(i + 1) * 4], self.multiply(binary_str[(i - 1) * 4:i * 4], 4))
                else:
                    mixed += self.xor_strings(binary_str[i * 4:(i + 1) * 4], self.multiply(binary_str[(i + 1) * 4:(i + 2) * 4], 4))
            elif mode == 2:  # 第二轮列混淆
                if i % 2:
                    mixed += self.xor_strings(self.multiply(binary_str[(i - 1) * 4:i * 4], 2), self.multiply(binary_str[i * 4:(i + 1) * 4], 9))
                else:
                    mixed += self.xor_strings(self.multiply(binary_str[i * 4:(i + 1) * 4], 9), self.multiply(binary_str[(i + 1) * 4:(i + 2) * 4], 2))
        return mixed

    def row_shift(self, binary_str):
        """行移位操作"""
        return binary_str[0:4] + binary_str[12:16] + binary_str[8:12] + binary_str[4:8]

    def encrypt(self, plaintext):
        """加密函数"""
        if len(plaintext) != 16 or not all(c in '01' for c in plaintext):
            raise ValueError("明文必须是16位二进制数")
        
        state = self.xor_strings(plaintext, self.round_keys[0] + self.round_keys[1])  # 轮密钥加
        # 第一轮
        state = self.byte_substitution(state, 1)
        state = self.row_shift(state)
        state = self.column_mixing(state, 1)
        state = self.xor_strings(state, self.round_keys[2] + self.round_keys[3])  # 轮密钥加
        # 第二轮
        state = self.byte_substitution(state, 1)
        state = self.row_shift(state)
        ciphertext = self.xor_strings(state, self.round_keys[4] + self.round_keys[5])  # 轮密钥加
        return ciphertext

    def decrypt(self, ciphertext):
        """解密函数"""
        if len(ciphertext) != 16 or not all(c in '01' for c in ciphertext):
            raise ValueError("密文必须是16位二进制数")
        
        state = self.xor_strings(ciphertext, self.round_keys[4] + self.round_keys[5])  # 轮密钥加
        state = self.row_shift(state)
        state = self.byte_substitution(state, 2)
        state = self.xor_strings(state, self.round_keys[2] + self.round_keys[3])  # 轮密钥加
        state = self.column_mixing(state, 2)
        state = self.row_shift(state)
        state = self.byte_substitution(state, 2)
        plaintext = self.xor_strings(state, self.round_keys[0] + self.round_keys[1])  # 轮密钥加
        return plaintext

def single_use_encrypt(plaintext, key):
    """单重加密"""
    aes = S_AES(key)
    return aes.encrypt(plaintext)

def single_use_decrypt(ciphertext, key):
    """单重解密"""
    aes = S_AES(key)
    return aes.decrypt(ciphertext)

def double_use_encrypt(plaintext, key):
    """双重加密"""
    aes1 = S_AES(key[:16])
    aes2 = S_AES(key[16:32])
    intermediate = aes1.encrypt(plaintext)
    return aes2.encrypt(intermediate)

def double_use_decrypt(ciphertext, key):
    """双重解密"""
    aes1 = S_AES(key[:16])
    aes2 = S_AES(key[16:32])
    intermediate = aes2.decrypt(ciphertext)
    return aes1.decrypt(intermediate)

def triple_use_encrypt(plaintext, key):
    """三重加密"""
    aes1 = S_AES(key[:16])
    aes2 = S_AES(key[16:32])
    aes3 = S_AES(key[32:48])
    r1 = aes1.encrypt(plaintext)
    r2 = aes2.encrypt(r1)
    return aes3.encrypt(r2)

def triple_use_decrypt(ciphertext, key):
    """三重解密"""
    aes1 = S_AES(key[:16])
    aes2 = S_AES(key[16:32])
    aes3 = S_AES(key[32:48])
    d1 = aes3.decrypt(ciphertext)
    d2 = aes2.decrypt(d1)
    return aes1.decrypt(d2)

def yihuo(string1, string2):
    """对两个二进制字符串进行异或操作"""
    return ''.join(['0' if s == k else '1' for s, k in zip(string1, string2)])

class SAESApp(QWidget):
    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        self.setWindowTitle('S-AES 加密解密工具')

        self.layout = QVBoxLayout()

        self.plaintext_input = QLineEdit(self)
        self.plaintext_input.setPlaceholderText('输入明文（16位二进制）')
        self.layout.addWidget(self.plaintext_input)

        self.key_input = QLineEdit(self)
        self.key_input.setPlaceholderText('输入密钥（48位二进制）')
        self.layout.addWidget(self.key_input)

        self.encryption_type = QComboBox(self)
        self.encryption_type.addItems(['单重加密', '双重加密', '三重加密', 'CBC 加密'])
        self.layout.addWidget(self.encryption_type)

        self.encrypt_button = QPushButton('加密', self)
        self.encrypt_button.clicked.connect(self.encrypt_text)
        self.layout.addWidget(self.encrypt_button)

        self.decryption_type = QComboBox(self)
        self.decryption_type.addItems(['单重解密', '双重解密', '三重解密', 'CBC 解密'])
        self.layout.addWidget(self.decryption_type)

        self.decrypt_button = QPushButton('解密', self)
        self.decrypt_button.clicked.connect(self.decrypt_text)
        self.layout.addWidget(self.decrypt_button)

        # 中间相遇攻击部分
        self.middle_attack_layout = QVBoxLayout()
        self.middle_attack_input = QLineEdit(self)
        self.middle_attack_input.setPlaceholderText('输入明文（16位二进制，空格分隔）')
        self.middle_attack_layout.addWidget(self.middle_attack_input)

        self.middle_attack_ciphertext_input = QLineEdit(self)
        self.middle_attack_ciphertext_input.setPlaceholderText('输入密文（16位二进制，空格分隔）')
        self.middle_attack_layout.addWidget(self.middle_attack_ciphertext_input)

        self.middle_attack_button = QPushButton('中间相遇攻击', self)
        self.middle_attack_button.clicked.connect(self.perform_attack)
        self.middle_attack_layout.addWidget(self.middle_attack_button)

        self.layout.addLayout(self.middle_attack_layout)

        self.result_scroll_area = QScrollArea(self)
        self.result_scroll_area.setWidgetResizable(True)
        self.result_widget = QScrollWidget()
        self.result_layout = QVBoxLayout()
        self.result_widget.setLayout(self.result_layout)
        self.result_scroll_area.setWidget(self.result_widget)
        self.layout.addWidget(self.result_scroll_area)

        self.setLayout(self.layout)

    def encrypt_text(self):
        plaintext = self.plaintext_input.text().strip()
        key = self.key_input.text().strip()
        mode = self.encryption_type.currentText()

        try:
            if mode == '单重加密':
                result = single_use_encrypt(plaintext, key)
            elif mode == '双重加密':
                result = double_use_encrypt(plaintext, key)
            elif mode == '三重加密':
                result = triple_use_encrypt(plaintext, key)
            elif mode == 'CBC 加密':
                result = self.cbc_encrypt(plaintext, key)
            self.add_result('结果: ' + result)
        except Exception as e:
            self.add_result(f'错误: {e}')

    def decrypt_text(self):
        ciphertext = self.plaintext_input.text().strip()
        key = self.key_input.text().strip()
        mode = self.decryption_type.currentText()

        try:
            if mode == '单重解密':
                result = single_use_decrypt(ciphertext, key)
            elif mode == '双重解密':
                result = double_use_decrypt(ciphertext, key)
            elif mode == '三重解密':
                result = triple_use_decrypt(ciphertext, key)
            elif mode == 'CBC 解密':
                result = self.cbc_decrypt(ciphertext, key)
            self.add_result('结果: ' + result)
        except Exception as e:
            self.add_result(f'错误: {e}')

    def cbc_encrypt(self, plaintext, key):
        """CBC 加密"""
        iv = '0000000000000000'  # 初始化向量
        ciphertext = ''
        previous_block = iv
        for i in range(0, len(plaintext), 16):
            block = plaintext[i:i + 16].ljust(16, '0')  # 填充至16位
            block = yihuo(block, previous_block)  # 与上一个密文块异或
            previous_block = single_use_encrypt(block, key)  # 加密
            ciphertext += previous_block
        return ciphertext

    def cbc_decrypt(self, ciphertext, key):
        """CBC 解密"""
        iv = '0000000000000000'  # 初始化向量
        plaintext = ''
        previous_block = iv
        for i in range(0, len(ciphertext), 16):
            block = ciphertext[i:i + 16]  # 取出密文块
            decrypted_block = single_use_decrypt(block, key)  # 解密
            plaintext += yihuo(decrypted_block, previous_block)  # 与上一个密文块异或
            previous_block = block  # 更新上一个密文块
        return plaintext

    def perform_attack(self):
        """进行中间相遇攻击"""
        plaintexts = self.middle_attack_input.text().strip()
        ciphertexts = self.middle_attack_ciphertext_input.text().strip()

        # 检查明文和密文的有效性
        if not plaintexts or not ciphertexts:
            self.add_result('错误: 请提供明文和密文')
            return

        # 进行中间相遇攻击
        try:
            results = attack(plaintexts, ciphertexts)
            if results:
                result_strings = ', '.join([f'({k1}, {k2})' for k1, k2 in results])
                self.add_result('找到的候选密钥: ' + result_strings)
            else:
                self.add_result('未找到候选密钥')
        except Exception as e:
            self.add_result(f'错误: {e}')

    def add_result(self, result_text):
        label = QLabel(result_text)
        self.result_layout.addWidget(label)

def attack(plaintexts: str, ciphertexts: str) -> list:
    plaintexts = plaintexts.split()
    ciphertexts = ciphertexts.split()

    possible_keys = {}

    # 遍历第一个明密文对，生成初步候选密钥
    plain = int(plaintexts[0], 2)
    cipher = int(ciphertexts[0], 2)

    for k1 in range(0x10000):
        k1_bin = '{:016b}'.format(k1)
        mid_value = single_use_encrypt('{:016b}'.format(plain), k1_bin)
        possible_keys[mid_value] = k1_bin  # 存储为16位字符串

    found_keys = []

    for k2 in range(0x10000):
        k2_bin = '{:016b}'.format(k2)
        mid_value = single_use_decrypt('{:016b}'.format(cipher), k2_bin)
        if mid_value in possible_keys:
            found_keys.append((possible_keys[mid_value], k2_bin))  # 存储为16位字符串
            if len(found_keys) >= 100:
                break

    for i in range(1, len(plaintexts)):
        plain = int(plaintexts[i], 2)
        cipher = int(ciphertexts[i], 2)
        found_keys = [
            (k1, k2) for k1, k2 in found_keys
            if single_use_encrypt('{:016b}'.format(plain), '{:048b}'.format(k1)) == single_use_decrypt('{:016b}'.format(cipher), '{:048b}'.format(k2))
        ]
        if len(found_keys) >= 100:
            found_keys = found_keys[:100]
            break

    return found_keys

if __name__ == '__main__':
    import sys
    app = QApplication(sys.argv)
    ex = SAESApp()
    ex.show()
    sys.exit(app.exec_())
