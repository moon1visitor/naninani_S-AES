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
https://github.com/moon1visitor/naninani_S-AES/blob/4c9400a44eff3a186912b191ee9d1ad84867975e/jpgs/1.1.png



经测试，该程序能够快速实现二进制模式下的加解密。




#### 第2关：交叉测试: 检测算法和程序是否可以在异构的系统或平台上都可以正常运行。


设有A和B两组位同学(选择相同的密钥K)；则A、B组同学编写的程序对明文P进行加密得到相同的密文C；或者B组同学接收到A组程序加密的密文C，使用B组程序进行解密可得到与A相同的P。


我们与其他组进行了交叉测试：


二进制加密选择相同的明文P为：10110010  选择相同的密钥K为：1110001010



二进制解密选择相同的密文P为：10010010  选择相同的密钥K为：1110001010

![对比1](https://github.com/user-attachments/assets/7a5ac13f-c5ea-4aa2-a00f-1502bf906284)


![对比2](https://github.com/user-attachments/assets/b844cc33-e365-4f5a-ab35-c5dd8a5da3fa)




经检测，我们组结果与另外一组结果相同，通过交叉检测。







#### 第3关：扩展功能考虑到向实用性扩展，加密算法的数据输入可以是ASII编码字符串(分组为1 Byte)，对应地输出也可以是ACII字符串(很可能是乱码)。

![ui](https://github.com/user-attachments/assets/68b09324-c7ff-4c43-97b3-464f36c7ae38)



经测试，该程序能够完成功能扩展，实现ASCII编码的加解密。




#### 第4关：暴力破解：检测是否能够实现暴力破解，且设置时间戳，记录暴力破解时间。

![暴力破解](https://github.com/user-attachments/assets/106a2098-a552-4564-9c9a-ba266fde45f0)


经测试，该程序能够实现暴力破解

#### 第5关：封闭测试：分析是否存在多个密钥可以生成相同的密文

![暴力破解](https://github.com/user-attachments/assets/080d83e6-c2d1-4629-93a0-82ac588c587a)


经测试，该程序能够在较短时间内分析是否存在多个密钥可以生成相同的密文。

## 六、总结
本项目成功实现了S-DES加密算法，并提供了一个用户友好的图形用户界面（GUI），使得加密和解密过程更加直观和便捷。通过详细的算法描述和关键代码实现，项目满足了课程的基本要求，还通过多模式加解密、跨平台一致性测试、扩展功能实现、暴力破解和封闭测试等相关测试。
#### 项目改进部分
性能优化：当前的加解密速度已经相当不错，但还有优化的空间。例如，我们可以通过并行化处理来提高速度，特别是在处理大量数据时。此外，我们也可以考虑优化算法的实现，如通过减少不必要的计算或使用更高效的数据结构等方法来提高速度。另外，暴力破解的过程可以进一步优化，例如通过更智能的密钥搜索策略，而不仅仅是遍历所有可能的密钥。


安全性增强：虽然S-DES算法本身的安全性有限（因为它只是一个教学用的简化模型），但我们仍然可以探索一些增强安全性的方法。例如，我们可以实现一些基本的防篡改机制，如对输入的完整性进行检查。此外，我们也可以考虑增加一些防止暴力破解的机制，如限制短时间内的尝试次数等。


用户界面改进：虽然当前的用户界面已经相当直观和用户友好，但仍有改进的空间。例如，我们可以添加一些更详细的说明和提示，以帮助用户更好地理解和使用程序。此外，我们也可以改进界面的布局和设计，使其更加美观和现代化。另外，我们还可以考虑添加一些新的功能，如保存和加载数据、复制和粘贴结果等，以提高用户的使用体验。


## 七、开发团队
- 小组：什么什么组
- 团队成员： 刘恺祺、郭宇
- 单位：重庆大学大数据与软件学院大数据01班_S-AES
