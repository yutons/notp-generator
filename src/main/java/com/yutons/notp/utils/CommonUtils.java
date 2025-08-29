package com.yutons.notp.utils;

import java.security.SecureRandom;

public class CommonUtils {
    private static final String BASE32_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

    public enum Algorithm {
        SHA1("HmacSHA1", 20),
        SHA256("HmacSHA256", 20),
        SHA512("HmacSHA512", 20),
        SM3("HmacSM3", 20);

        private final String algorithm;
        private final Integer length;

        Algorithm(String algorithm, Integer length) {
            this.algorithm = algorithm;
            this.length = length;
        }

        public Integer getLength() {
            return length;
        }

        public String getAlgorithm() {
            return algorithm;
        }
    }

    public static String generateSecret(Integer length) {
        // 1. 生成安全的随机字节
        byte[] bytes = new byte[length];
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(bytes);

        // 2. 转换为Base32字符串
        StringBuilder base32 = new StringBuilder();

        // 缓冲区处理机制
        int buffer = 0;
        int bitCount = 0;

        for (byte b : bytes) {
            // 将当前字节加入缓冲区（取低8位）
            buffer = (buffer << 8) | (b & 0xFF);
            bitCount += 8;

            // 每次提取5位处理
            while (bitCount >= 5) {
                // 提取高5位：从缓冲区顶部取5位
                int index = (buffer >> (bitCount - 5)) & 0x1F;
                base32.append(BASE32_CHARS.charAt(index));
                bitCount -= 5;
                // 清除已处理的高5位（保留剩余位）
                buffer &= (1 << bitCount) - 1;
            }
        }

        // 处理剩余位（不足5位时，末尾补0）
        if (bitCount > 0) {
            // 左移补0至5位
            int index = (buffer << (5 - bitCount)) & 0x1F;
            base32.append(BASE32_CHARS.charAt(index));
        }

        return base32.toString();
    }

    public static void validateAlgorithm(String algorithm) {
        boolean flag = false;
        for (Algorithm alg : Algorithm.values()) {
            String algo = alg.getAlgorithm();
            if (algo.equals(algorithm)) {
                flag = true;
                break;
            }
        }
        if (!flag) {
            throw new RuntimeException("Unsupported algorithm: " + algorithm);
        }
    }
}
