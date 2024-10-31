# naninani_S-AES
# S-AES
S-AES算法实现
## 一、项目简介
本项目是为学习S-AES算法而编写的Python代码，同时完成重庆大学2022级“信息安全导论”课程的作业。S-AES（Simplified AES）是一种简化的高级加密标准（AES），旨在帮助学习和理解 AES 算法的基本概念。虽然 S-AES 保留了 AES 的一些核心特性，但其结构和操作都进行了简化，使其更适合教学和实验。通过 S-AES，用户可以掌握加密和解密的关键步骤，理解如何利用轮密钥进行数据保护。这对于深入学习更复杂的加密方法，如标准 AES，具有重要的帮助作用。程序会根据用户的输入执行相应的加密或解密操作，并在界面上展示结果。

## 二、S-AES程序结构

#### 导入模块
导入 PyQt5 相关模块，拟构建图形用户界面（GUI）
#### S_AES 类
目的：实现简化的 AES 加密算法
#### 成员变量
key：存储原始密钥。
round_keys：存储扩展后的轮密钥。
s_box：加密过程中使用的 S 盒。
inv_s_box：解密过程中使用的反 S 盒。
rcon：轮常量，用于密钥扩展。
#### 构造函数 (__init__)
初始化密钥及其验证，初始化 S 盒和轮常量，调用密钥扩展方法。
#### 异或操作方法 (xor_strings)
对两个二进制字符串执行逐位异或操作。
#### 密钥扩展方法 (key_expansion)
通过原始密钥生成多个轮密钥。
#### 生成轮密钥的方法 (g)
生成轮密钥的一部分，涉及 S 盒替代和轮常量异或。
#### 字节替代方法 (substitute_bytes)
根据输入半字节使用 S 盒或反 S 盒进行字节替代。
#### 加密和解密方法 (encrypt 和 decrypt)
加密和解密过程，涉及字节替代、行移位、列混淆和轮密钥加等步骤。
#### 双重和三重加密解密方法
提供多次加密和解密的功能，以增强加密强度。
#### 中间相遇攻击相关的方法 (attack)
实现针对 S-AES 的中间相遇攻击，用于枚举和匹配可能的密钥。
#### SAESApp 类
目的：构建用户界面，使用户能够进行加密和解密操作。
#### 界面组件
输入框、按钮、下拉菜单等用户交互组件设置，加密和解密流程的连接。
#### 事件处理
定义加密、解密和中间相遇攻击的事件处理方法。

分为核心加密算法和用户界面两大部分。S_AES 类专注于实现加密的逻辑，而 SAESApp 类则负责用户交互的展示和实现。


## 三、实现功能

1. **提供GUI解密支持用户交互**：输入可以是16bit的数据和16bit的密钥，输出是16bit的密文。
2. **跨平台一致性**：实现跨平台一致性，保证程序在不同平台上运行结果一致。
3. **扩展功能**：加密算法的数据输入可以是ASII编码字符串(分组为2 Bytes)，对应地输出也可以是ACII字符串。
4. **多重加密**：双重加密、中间相遇攻击以及三重加密均能实现。
5. **CBC模式**：较长的明文消息进行加密、初始向量的生成，解密双方共享。


## 四、代码实现
##### S_AES 类及其构造函数
密钥校验：检查输入密钥的长度为 16 位，并且仅包含 '0' 和 '1'。
S-BOX 和 RCON 初始化：定义 S-BOX 和反 S-BOX，用于字节替代。定义轮常量 rcon，用于密钥扩展。
调用密钥扩展方法：进行密钥扩展，生成多个轮密钥。
```python
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
```
##### 异或操作方法
对输入的两个二进制字符串执行逐位异或操作，返回异或结果。
如果两个位相同，返回 '0'; 如果不同，返回 '1'。
```python
def xor_strings(self, string, key):
    """对两个二进制字符串进行异或操作。"""
    return ''.join(['0' if s == k else '1' for s, k in zip(string, key)])

```
##### 密钥扩展方法
将原始密钥分为两个 8 位的轮密钥。
通过异或操作和辅助函数 g 生成更多轮密钥。
```python
def key_expansion(self):
    """扩展密钥为多个轮密钥"""
    self.round_keys = [self.key[i:i + 8] for i in range(0, 16, 8)]
    self.round_keys.append(self.xor_strings(self.round_keys[0], self.g(self.round_keys[1], 1)))
    self.round_keys.append(self.xor_strings(self.round_keys[1], self.round_keys[2]))
    self.round_keys.append(self.xor_strings(self.round_keys[2], self.g(self.round_keys[3], 2)))
    self.round_keys.append(self.xor_strings(self.round_keys[3], self.round_keys[4]))
```
##### 生成轮密钥的方法
用于生成轮密钥中的一个部分。
对输入的子密钥 w 执行字节替代，使用 S-BOX 进行转换。
通过异或操作与轮常量 rcon 结合生成新的轮密钥。
```python
def g(self, w, n):
    """生成轮密钥"""
    substituted = self.substitute_bytes(w[4:8], 1) + self.substitute_bytes(w[0:4], 1)
    return self.xor_strings(substituted, self.rcon[n - 1])
```
##### 字节替代方法
根据指定模式执行字节替代操作。
对输入的半字节（4 位）进行行列查找，从 S-BOX 或反 S-BOX 中获得替代值。
```python
def substitute_bytes(self, nibble, mode):
    """替换字节"""
    row = int(nibble[:2], 2)
    col = int(nibble[2:], 2)
    if mode == 1:
        return self.s_box[row][col]
    else:
        return self.inv_s_box[row][col]

```
##### 加密和解密方法
接收 16 位的明文，并进行加密处理。
执行轮密钥加、字节替代、行移位和列混淆等步骤，经过两轮处理后得到密文。
```python
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

```

解密过程类似于加密，使用反操作和轮密钥还原明文。
```python
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


```
##### 双重和三重加密解密方法
这些函数（如 double_use_encrypt，triple_use_encrypt）使用多个 S_AES 实例进行加密和解密，以提高安全性，依次对明文进行加密或解密。

##### 中间相遇攻击相关的方法
实现中间相遇攻击的方法，通过枚举可能的密钥 k1 和 k2 来寻找匹配的中间值，从而推导出密钥。
```python
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

```

整个 S_AES 类提供了 AES 加密算法的简化实现，包括密钥生成、字节替代、行移位、列混淆等核心功能。

## 五、项目测试
#### 第1关：根据S-AES算法编写和调试程序，提供GUI解密支持用户交互。输入可以是16bit的数据和16bit的密钥，输出是16bit的密文。

![1 1](https://github.com/user-attachments/assets/77d74c6f-a33c-4807-9385-00cf95c7fdea)

![1 2](https://github.com/user-attachments/assets/a66c4f20-8143-40ff-bc4b-6c4c2f3627cd)


经测试，该程序能够快速实现二进制模式下的加解密。




#### 第2关：交叉测试: 检测算法和程序是否可以在异构的系统或平台上都可以正常运行。


设有A和B两组位同学(选择相同的密钥K)；则A、B组同学编写的程序对明文P进行加密得到相同的密文C；或者B组同学接收到A组程序加密的密文C，使用B组程序进行解密可得到与A相同的P


我们与其他组进行了交叉测试：


二进制加密选择相同的明文P为：111111111111111  选择相同的密钥K为：1111111111110000



二进制解密选择相同的密文P为：000000000001111  选择相同的密钥K为：1111111111110000

![2 1](https://github.com/user-attachments/assets/e1439fc5-d3b3-42d0-b360-cfc4dd281ae3)
![2 2](https://github.com/user-attachments/assets/06dd2a67-efcb-4f15-b5c2-e57d1c22519c)

![2 3](https://github.com/user-attachments/assets/c3e69eb8-cf4c-49db-a621-46fa87c23e7f)
![2 4](https://github.com/user-attachments/assets/1af7cde3-2a70-48fb-942e-efa5b0513c65)



经检测，我们组结果与另外一组结果相同，通过交叉检测。







#### 第3关：扩展功能考虑到向实用性扩展，加密算法的数据输入可以是ASII编码字符串(分组为1 Byte)，对应地输出也可以是ACII字符串(很可能是乱码)。



经测试，该程序能够完成功能扩展，实现ASCII编码的加解密。




#### 第4关：多重加密。


![4 1](https://github.com/user-attachments/assets/226beea8-0cd4-4eb5-93ea-80c1c83c0101)
![4 2](https://github.com/user-attachments/assets/6fb33eec-12fd-4e70-af6a-a390cab7219f)
![4 3](https://github.com/user-attachments/assets/153748f5-17cd-4bfa-baa2-689c16cfc49d)
![4 4](https://github.com/user-attachments/assets/45957bc1-4a69-4f6d-8c56-210d77ca0353)

经测试，该程序能够实现多重加密

#### 第5关：工作模式
基于S-AES算法，使用密码分组链(CBC)模式对较长的明文消息进行加密。注意初始向量(16 bits) 的生成，并需要加解密双方共享
![5 1](https://github.com/user-attachments/assets/25affe1f-43cf-4f57-94de-232369993e26)

![5 2](https://github.com/user-attachments/assets/892a686c-853b-4cf4-b958-151f5a2092c6)


经测试，该程序能够在CBC模式下进行加密，并尝试对密文分组进行替换或修改，然后进行解密。

## 六、总结
构建了一个简化版的 AES 加密框架的基础，主要包含密钥的验证、生成 S-盒和反 S-盒、以及轮密钥的扩展过程。这些元素构成了加密算法的核心，为后续的加密和解密功能提供了必要的支持。
#### 项目改进部分
1. 增加文档字符串和注释
完整的文档字符串：虽然一些方法有基本的文档字符串，但可以更详细地记录每个参数的意义、返回值，以及方法的功能。这有助于其他开发者更容易理解代码。
注释：在复杂的逻辑部分添加更多注释，解释代码的实现逻辑。
2. 密钥扩展的改进
灵活的密钥长度支持：当前实现支持固定的 16 位密钥，考虑允许更长的密钥，以及动态处理不同长度密钥的功能，这将提升算法的灵活性。
改进密钥生成算法：可以考虑优化密钥扩展算法，以支持更多的轮密钥生成策略。
3. 错误处理
更细致的错误处理：目前对密钥和明文的验证比较基础，可以增强错误提示的详细程度，比如指明哪个部分出错，或者提供更智能的异常处理。
输入检查：检查用户输入的格式，例如在 GUI 应用程序中确认是否是有效的二进制字符串，并在用户输入时报错误。
4. 安全性增强
使用安全的随机数生成器：如果将来实现随机密钥生成，应使用安全的随机数生成器而非简单的字节固定。
实现更多加密模式：除了单重、双重以及三重加密，还可以实现如 CBC（Cipher Block Chaining）模式、CTR（Counter Mode）等其他加密模式，以提高安全性。
5. 优化性能
使用 NumPy 或其他库：在处理大数组或矩阵时，使用 NumPy 会极大地提高性能，特别是在列混淆和行移位等操作中。
6. 增强用户体验
改进用户界面：在图形用户界面的设计上可以提供更多的提示信息和功能，例如输入有效性检查、历史记录、或者明确的结果展示等。
7. 添加单元测试
单元测试：实现单元测试框架，以确保每个功能模块都能正常工作。这将有助于确保代码在修改或重构后的正确性。

## 七、开发团队
- 小组：什么什么组
- 团队成员： 刘恺祺、郭宇
- 单位：重庆大学大数据与软件学院大数据01班
