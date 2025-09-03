# notp4j - Java One-Time Password Library

🔒 轻量级Java库，实现**HOTP**(RFC 4226)和**TOTP**(RFC 6238)一次性密码算法，提供双因素认证(2FA)解决方案，兼容Google Authenticator等主流验证器。

> **安全提示**
> - 🚨 **密钥存储**：禁止硬编码密钥，推荐使用环境变量或密钥管理服务
> - 🔐 **Base32编码**：使用安全的随机数生成器创建密钥

## DEMO地址

[notp4j 动态口令生成器](https://notp.5567890.xyz/docs/)

---

## 目录

- [核心特性](#核心特性)
- [安装指南](#安装指南)
- [快速开始](#快速开始)
- [API参考](#api参考)
- [算法支持](#算法支持)
- [兼容性](#兼容性)
- [贡献指南](#贡献指南)
- [常见问题](#常见问题)
- [许可证](#许可证)

---

## 核心特性

- 🔐 **标准化实现**  
  严格遵循 [RFC 4226](https://tools.ietf.org/html/rfc4226) (HOTP) 和 [RFC 6238](https://tools.ietf.org/html/rfc6238) (TOTP) 规范
- ⚡ **多环境支持**  
  Java 8+ | Spring Boot 集成  
  提供Maven依赖管理
- 🌐 **跨平台兼容**  
  ✅ Google Authenticator ✅ Microsoft Authenticator ✅ Authy
- 🛡️ **安全增强**  
  支持SHA-1哈希算法，提供验证窗口动态调整
- 📦 **零依赖**  
  仅依赖Java标准库，无第三方依赖

---

## 安装指南

### Maven

```xml
<dependency>
    <groupId>com.yutons</groupId>
    <artifactId>notp4j</artifactId>
    <version>1.0.0</version>
</dependency>
```

### Gradle

```gradle
implementation 'com.yutons:notp4j:1.0.0'
```

---

## 快速开始

### 1. 生成TOTP验证码

```java
import com.yutons.notp.core.HOTP;
import com.yutons.notp.core.TOTP;
import com.yutons.notp.utils.CommonUtils;
import org.junit.jupiter.api.Test;

import java.time.Instant;

public class HOTPTest {
  @Test
  void totp() throws Exception {
    String secret = "PPXUID6JTHXHU6GIOX3OENRN7L7WEIPB";
    long currentTime = Instant.now().getEpochSecond();
    TOTP.Option option = new TOTP.Option();
    option.setSecret(secret);
    option.setTimestamp(currentTime);
    option.setDigits(6);
    System.out.println("生成 TOTP (使用当前时间戳)");
    System.out.println("=== TOTP (Timestamp=" + currentTime + ") ===");
    for (CommonUtils.Algorithm algorithm : CommonUtils.Algorithm.values()) {
      option.setAlgorithm(algorithm.name());
      // 生成TOTP验证码
      String totp = TOTP.generate(option);
      System.out.println("TOTP: " + totp);
      option.setCode(totp);
      // 验证TOTP令牌
      System.out.println("验证结果: " + TOTP.verify(option));

    }
  }
}
```

---

## API参考

### TOTP.generate(secret)

生成基于当前时间的TOTP令牌

**参数**: 
- [secret](file://D:\Users\yutons\Desktop\notp4j\src\main\java\com\yutons\notp\core\TOTP.java#L16-L16) (String): Base32编码的密钥

**返回值**: `String` (一次性密码)

### TOTP.generate(option)

生成自定义配置的TOTP令牌

**参数**:
- [secret](file://D:\Users\yutons\Desktop\notp4j\src\main\java\com\yutons\notp\core\TOTP.java#L16-L16) (String): Base32编码的密钥
- [algorithm](file://D:\Users\yutons\Desktop\notp4j\src\main\java\com\yutons\notp\core\TOTP.java#L28-L28) (String): 哈希算法 (默认: "SHA1")
- [digits](file://D:\Users\yutons\Desktop\notp4j\src\main\java\com\yutons\notp\core\TOTP.java#L24-L24) (int): 验证码位数 (默认: 6)
- [period](file://D:\Users\yutons\Desktop\notp4j\src\main\java\com\yutons\notp\core\TOTP.java#L20-L20) (int): 时间步长(秒) (默认: 30)

**返回值**: `String` (一次性密码)

### TOTP.verify(option)

验证TOTP令牌

**参数**:
- `token` (String): 待验证的令牌
- [secret](file://D:\Users\yutons\Desktop\notp4j\src\main\java\com\yutons\notp\core\TOTP.java#L16-L16) (String): Base32编码的密钥

**返回值**: `boolean`

### TOTP.verify(option)

验证自定义配置的TOTP令牌

**参数**:
- `token` (String): 待验证的令牌
- [secret](file://D:\Users\yutons\Desktop\notp4j\src\main\java\com\yutons\notp\core\TOTP.java#L16-L16) (String): Base32编码的密钥
- [window](file://D:\Users\yutons\Desktop\notp4j\src\main\java\com\yutons\notp\core\TOTP.java#L40-L40) (int): 时间窗口容差 (默认: 1)
- [algorithm](file://D:\Users\yutons\Desktop\notp4j\src\main\java\com\yutons\notp\core\TOTP.java#L28-L28) (String): 哈希算法 (默认: "SHA1")
- [digits](file://D:\Users\yutons\Desktop\notp4j\src\main\java\com\yutons\notp\core\TOTP.java#L24-L24) (int): 验证码位数 (默认: 6)
- [period](file://D:\Users\yutons\Desktop\notp4j\src\main\java\com\yutons\notp\core\TOTP.java#L20-L20) (int): 时间步长(秒) (默认: 30)

**返回值**: `boolean`

### HOTP.generate(option)

生成HOTP令牌

**参数**:
- [secret](file://D:\Users\yutons\Desktop\notp4j\src\main\java\com\yutons\notp\core\TOTP.java#L16-L16) (String): Base32编码的密钥
- [counter](file://D:\Users\yutons\Desktop\notp4j\src\main\java\com\yutons\notp\core\HOTP.java#L22-L22) (long): 计数器值

**返回值**: `String` (一次性密码)

### HOTP.generate(option)

生成自定义配置的HOTP令牌

**参数**:
- [secret](file://D:\Users\yutons\Desktop\notp4j\src\main\java\com\yutons\notp\core\TOTP.java#L16-L16) (String): Base32编码的密钥
- [counter](file://D:\Users\yutons\Desktop\notp4j\src\main\java\com\yutons\notp\core\HOTP.java#L22-L22) (long): 计数器值
- [algorithm](file://D:\Users\yutons\Desktop\notp4j\src\main\java\com\yutons\notp\core\TOTP.java#L28-L28) (String): 哈希算法 (默认: "SHA1")
- [digits](file://D:\Users\yutons\Desktop\notp4j\src\main\java\com\yutons\notp\core\TOTP.java#L24-L24) (int): 验证码位数 (默认: 6)

**返回值**: `String` (一次性密码)

### HOTP.verify(option)

验证HOTP令牌

**参数**:
- `token` (String): 待验证的令牌
- [secret](file://D:\Users\yutons\Desktop\notp4j\src\main\java\com\yutons\notp\core\TOTP.java#L16-L16) (String): Base32编码的密钥
- [counter](file://D:\Users\yutons\Desktop\notp4j\src\main\java\com\yutons\notp\core\HOTP.java#L22-L22) (long): 计数器值

**返回值**: `HOTP.Result` { success: boolean, delta: long }

### HOTP.verify(option)

验证自定义配置的HOTP令牌

**参数**:
- `token` (String): 待验证的令牌
- [secret](file://D:\Users\yutons\Desktop\notp4j\src\main\java\com\yutons\notp\core\TOTP.java#L16-L16) (String): Base32编码的密钥
- [counter](file://D:\Users\yutons\Desktop\notp4j\src\main\java\com\yutons\notp\core\HOTP.java#L22-L22) (long): 计数器值
- [window](file://D:\Users\yutons\Desktop\notp4j\src\main\java\com\yutons\notp\core\TOTP.java#L40-L40) (int): 时间窗口容差 (默认: 1)
- [algorithm](file://D:\Users\yutons\Desktop\notp4j\src\main\java\com\yutons\notp\core\TOTP.java#L28-L28) (String): 哈希算法 (默认: "SHA1")
- [digits](file://D:\Users\yutons\Desktop\notp4j\src\main\java\com\yutons\notp\core\TOTP.java#L24-L24) (int): 验证码位数 (默认: 6)

**返回值**: `HOTP.Result` { success: boolean, delta: long }

---

## 算法支持

| 算法      | 安全性     | Google认证器兼容 | 推荐场景      |
|---------|---------|-------------|-----------|
| SHA-1   | ⚠️ 一般   | ✅ 完全兼容      | 兼容性要求高的场景 |

---

## 贡献指南

我们欢迎所有形式的贡献！参与流程：

1. 提交Issue说明问题/建议
2. Fork仓库并创建分支：`git checkout -b fix/issue-123`
3. 遵循编码规范：新增功能需包含单元测试
4. 提交Pull Request并关联Issue

---

## 常见问题

### ❓ 如何生成安全的Base32密钥？

```java
import com.yutons.notp.util.SecretGenerator;

// 生成20字节的安全随机密钥
String secret = SecretGenerator.generateSecret(20);
System.out.println(secret); // 输出示例: JBSWY3DPEHPK3PXP
```

### ❓ 验证窗口(window)如何设置？

- 默认值`1`（当前+前后两个30秒窗口）
- 高延迟网络建议设为`3`：

```java
TOTP.verify(token, secret, 3);
```

---

## 许可证

[MIT License](https://github.com/yutons/notp4j/blob/main/LICENSE) ©yutons  
允许商业使用、修改和私有部署，需保留版权声明。