from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QLineEdit, QPushButton, QLabel, QComboBox

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
    aes3 = S_AES(key[32:])
    r1 = aes1.encrypt(plaintext)
    r2 = aes2.encrypt(r1)
    return aes3.encrypt(r2)

def triple_use_decrypt(ciphertext, key):
    """三重解密"""
    aes1 = S_AES(key[:16])
    aes2 = S_AES(key[16:32])
    aes3 = S_AES(key[32:])
    d1 = aes3.decrypt(ciphertext)
    d2 = aes2.decrypt(d1)
    return aes1.decrypt(d2)

class SAESApp(QWidget):
    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        self.setWindowTitle('S-AES 加解密程序')
        layout = QVBoxLayout()

        # 输入框和标签
        self.plaintext_input = QLineEdit(self)
        self.plaintext_input.setPlaceholderText('输入明文或者密文（16位二进制）')
        layout.addWidget(self.plaintext_input)

        self.key_input = QLineEdit(self)
        self.key_input.setPlaceholderText('输入密钥（16位二进制）')
        layout.addWidget(self.key_input)

        # 加密模式下拉框
        self.mode_combo = QComboBox(self)
        self.mode_combo.addItems(['单重加密', '双重加密', '三重加密'])
        layout.addWidget(self.mode_combo)

        # 加密按钮
        self.encrypt_button = QPushButton('加密')
        self.encrypt_button.clicked.connect(self.encrypt)
        layout.addWidget(self.encrypt_button)

        # 解密按钮
        self.decrypt_button = QPushButton('解密')
        self.decrypt_button.clicked.connect(self.decrypt)
        layout.addWidget(self.decrypt_button)

        # 结果标签
        self.result_label = QLabel('')
        layout.addWidget(self.result_label)

        self.setLayout(layout)

    def encrypt(self):
        plaintext = self.plaintext_input.text()
        key = self.key_input.text()
        
        # 检查输入是否为16位二进制数
        if len(plaintext) != 16 or not all(c in '01' for c in plaintext):
            self.result_label.setText('明文必须是16位二进制数！')
            return
        
        if len(key) != 16 or not all(c in '01' for c in key):
            self.result_label.setText('密钥必须是16位二进制数！')
            return
        
        if self.mode_combo.currentText() == '单重加密':
            ciphertext = single_use_encrypt(plaintext, key)
        elif self.mode_combo.currentText() == '双重加密':
            ciphertext = double_use_encrypt(plaintext, key)
        elif self.mode_combo.currentText() == '三重加密':
            ciphertext = triple_use_encrypt(plaintext, key)

        self.result_label.setText(f'密文: {ciphertext}')

    def decrypt(self):
        ciphertext = self.plaintext_input.text()
        key = self.key_input.text()
        
        # 检查输入是否为16位二进制数
        if len(ciphertext) != 16 or not all(c in '01' for c in ciphertext):
            self.result_label.setText('密文必须是16位二进制数！')
            return
        
        if len(key) != 16 or not all(c in '01' for c in key):
            self.result_label.setText('密钥必须是16位二进制数！')
            return
        
        if self.mode_combo.currentText() == '单重加密':
            plaintext = single_use_decrypt(ciphertext, key)
        elif self.mode_combo.currentText() == '双重解密':
            plaintext = double_use_decrypt(ciphertext, key)
        elif self.mode_combo.currentText() == '三重解密':
            plaintext = triple_use_decrypt(ciphertext, key)

        self.result_label.setText(f'明文: {plaintext}')

if __name__ == '__main__':
    app = QApplication([])
    ex = SAESApp()
    ex.show()
    app.exec_()
