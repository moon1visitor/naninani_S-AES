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

1. **多模式加解密**：支持ASCII模式和二进制模式下8-bit数据和10-bit密钥的加密和解密。
2. **跨平台一致性**：实现跨平台一致性，保证程序在不同平台上运行结果一致。
3. **扩展功能**：支持ASCII编码字符串的加密和解密。
4. **暴力破解**：支持暴力破解，通过尝试所有可能的密钥来解密已加密的消息。
5. **封闭测试**：判断是否存在多个密钥可以生成相同的密文。


## 四、代码实现
##### 生成密钥函数
generate_all_keys: 生成所有可能的10位二进制密钥，共1024种可能性。
try_key: 尝试用给定密钥解密，如果解密结果与明文匹配则返回该密钥。
brute_force: 使用多线程进行暴力破解，遍历所有密钥以找到匹配的结果。
```python
def generate_all_keys():
    return [[int(bit) for bit in format(i, '010b')] for i in range(1024)]

# 尝试用给定的密钥解密密文，如果解密结果与明文匹配，则返回该密钥
def try_key(key, plaintext, ciphertext):
    if decrypt(ciphertext, key) == plaintext:
        return key

# 使用所有可能的密钥尝试解密，返回所有成功的密钥及其对应的时间
def brute_force(plaintext, ciphertext):
    keys = generate_all_keys()
    successful_keys = []

    # 使用多线程来加速破解
    with concurrent.futures.ThreadPoolExecutor() as executor:
        future_to_key = {executor.submit(try_key, key, plaintext, ciphertext): key for key in keys}
        for future in concurrent.futures.as_completed(future_to_key):
            key = future_to_key[future]
            if future.result() is not None:
                successful_keys.append((key, time.time()))

    return successful_keys
```
##### 加密与解密算法
encrypt: 实现S-DES的加密过程，分为多个步骤，包括密钥扩展、初始置换、轮函数操作和逆初始置换。
decrypt: 实现S-DES的解密过程，与加密过程相反，使用不同的子密钥顺序。
```python
# S-DES 加密函数
def encrypt(plaintext, key):
    k1, k2 = key_expansion(key)

    # 初始置换 IP
    IP_plaintext = permute(plaintext, IP)

    L0, R0 = IP_plaintext[:4], IP_plaintext[4:]

    # 第一轮 F 函数
    L1 = R0
    r0 = f(R0, k1)  
    R1 = xor(L0, r0) 

    # 交换左右
    L2 = R1
    r1 = f(L1, k2)  
    R2 = xor(L2, r1)  

    combined = R2 + L1  

    # 逆初始置换 IP_inv
    ciphertext = permute(combined, IP_inv)

    return ciphertext

def decrypt(ciphertext, key):
    k1, k2 = key_expansion(key)

    # 初始置换 IP
    IP_ciphertext = permute(ciphertext, IP)

    L0, R0 = IP_ciphertext[:4], IP_ciphertext[4:]

    # 第一轮 F 函数
    L1 = R0
    r0 = f(R0, k2)  
    R1 = xor(L0, r0) 

    # 交换左右
    L2 = R1
    r1 = f(L1, k1)  
    R2 = xor(L2, r1)

    combined = R2 + L1 

    # 逆初始置换 IP_inv
    plaintext = permute(combined, IP_inv)

    return plaintext
```
##### 轮函数 f_k
这个函数实现了S-DES的轮函数操作。
```python
def f(R, k):
    # EP 置换
    permuted_R = permute(R, EP)

    # 与子密钥 k 进行异或
    xor_result = xor(permuted_R, k)

    # S-Box 输入
    left_sbox_input = xor_result[:4]
    right_sbox_input = xor_result[4:]

    # S-Box 替换
    row1 = (left_sbox_input[0] << 1) | left_sbox_input[3]  
    col1 = (left_sbox_input[1] << 1) | left_sbox_input[2]  
    sbox1_output = SBox1[row1][col1]

    row2 = (right_sbox_input[0] << 1) | right_sbox_input[3]  
    col2 = (right_sbox_input[1] << 1) | right_sbox_input[2]  
    sbox2_output = SBox2[row2][col2]

    # S-Box 输出转换为二进制
    sbox_output = [int(x) for x in f'{sbox1_output:02b}'] + [int(x) for x in f'{sbox2_output:02b}']

    # P4 置换
    return permute(sbox_output, P4)

```

## 五、项目测试
#### 第1关：根据S-DES算法编写和调试程序，提供GUI解密支持用户交互。输入可以是8bit的数据和10bit的密钥，输出是8bit的密文

![加密](https://github.com/user-attachments/assets/670bb478-154a-4a13-b81c-958083a47592)

![解密](https://github.com/user-attachments/assets/705b24c7-9091-4108-a099-a3e1dc3b9a28)


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
