package com.yutons.notp.core;

import com.yutons.notp.utils.CommonUtils;
import com.yutons.notp.utils.HmacSM3Utils;
import lombok.Data;
import org.apache.commons.codec.binary.Base32;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class HOTP {

    @Data
    public static class Option {
        private String secret;         // Base32 编码密钥
        private long counter;          // 计数器（建议 long，避免溢出）
        private int digits = 6;        // 验证码位数
        private String algorithm = CommonUtils.Algorithm.SHA1.name(); // 算法
        private String code;           // 用户输入的验证码
        private int window = 0;        // 容错窗口（单侧或双侧）
        private boolean bidirectionalWindow = false; // 是否启用双向窗口（前后各 window）
    }

    /**
     * 生成 HOTP 一次性密码
     */
    public static String generate(Option option) throws Exception {
        // 1. 解码 Base32 密钥
        Base32 base32 = new Base32();
        byte[] keyBytes = base32.decode(option.secret);

        // 2. 转换计数器为 8 字节大端序
        byte[] counterBytes = HmacSM3Utils.intTo8Bytes(option.counter);

        // 3. 计算 HMAC
        byte[] hash = calculateHmac(keyBytes, counterBytes, option.algorithm);

        // 4. 动态截断 (Dynamic Truncation)
        int offset = hash[hash.length - 1] & 0x0F;
        int binary = ((hash[offset] & 0x7F) << 24) |
                ((hash[offset + 1] & 0xFF) << 16) |
                ((hash[offset + 2] & 0xFF) << 8) |
                (hash[offset + 3] & 0xFF);

        int mod = (int) Math.pow(10, option.digits);
        int otp = binary % mod;
        return String.format("%0" + option.digits + "d", otp);
    }

    /**
     * 计算 HMAC 值（支持 SHA1/SHA256/SHA512/SM3）
     */
    private static byte[] calculateHmac(byte[] key, byte[] data, String algorithm) throws Exception {
        String upperAlg = algorithm.toUpperCase();
        String jceAlg = CommonUtils.Algorithm.valueOf(upperAlg).getAlgorithm();

        if (CommonUtils.Algorithm.SM3.name().equals(upperAlg)) {
            String result = HmacSM3Utils.hmacSm3(data, key);
            return HmacSM3Utils.hexToBytes(result);
        } else {
            Mac mac = Mac.getInstance(jceAlg);
            mac.init(new SecretKeySpec(key, jceAlg));
            return mac.doFinal(data);
        }
    }

    /**
     * 验证 HOTP（支持双向/单向窗口）
     * 默认：单向窗口 [counter, counter + window]
     * 若 bidirectionalWindow=true：使用 [counter - window, ..., counter + window]
     */
    public static boolean verify(Option option) throws Exception {
        int window = option.window;
        boolean bidirectional = option.bidirectionalWindow;

        long start = bidirectional ? option.counter - window : option.counter;
        long end = option.counter + window;

        for (long counter = start; counter <= end; counter++) {
            if (counter < 0) continue; // 防止负数计数器

            Option attempt = new Option();
            attempt.secret = option.secret;
            attempt.counter = counter;
            attempt.digits = option.digits;
            attempt.algorithm = option.algorithm;
            attempt.code = option.code; // 不用于 generate，但保留

            if (generate(attempt).equals(option.code)) {
                return true;
            }
        }
        return false;
    }

    /**
     * 验证并返回建议更新的计数器（防止重放攻击）
     * @return 成功时返回最大有效 counter，失败返回 -1
     */
    public static long verifyAndSuggestNewCounter(Option option) throws Exception {
        int window = option.window;
        boolean bidirectional = option.bidirectionalWindow;

        long start = bidirectional ? option.counter - window : option.counter;
        long end = option.counter + window;

        long maxValidCounter = -1;
        for (long counter = start; counter <= end; counter++) {
            if (counter < 0) continue;

            Option attempt = new Option();
            attempt.secret = option.secret;
            attempt.counter = counter;
            attempt.digits = option.digits;
            attempt.algorithm = option.algorithm;

            if (generate(attempt).equals(option.code)) {
                maxValidCounter = Math.max(maxValidCounter, counter);
            }
        }

        return maxValidCounter; // >0 表示成功，可用于更新服务端 counter
    }
}