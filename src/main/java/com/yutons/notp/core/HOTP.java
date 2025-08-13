package com.yutons.notp.core;

import com.yutons.notp.utils.CommonUtils;
import lombok.Data;
import org.apache.commons.codec.binary.Base32;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;

public class HOTP {


    @Data
    public static class Option {
        /**
         * Base32编码的密钥
         */
        private String secret;
        /**
         * 计数器
         */
        private Long counter;
        /**
         * 验证码位数，默认6位
         */
        private Integer digits = 6;
        /**
         * HMAC算法，默认HMAC-SHA1
         */
        private String algorithm = CommonUtils.Algorithm.SHA1.getAlgorithm();
        /**
         * 验证码
         */
        private String code;
        /**
         * 验证窗口期，默认0
         */
        private Integer window = 0;
    }

    public static String generate(Option option) throws Exception {
        // 1. 解码Base32密钥
        Base32 base32 = new Base32();
        byte[] keyBytes = base32.decode(option.secret);

        // 2. 转换计数器为8字节大端序数组
        byte[] counterBytes = ByteBuffer.allocate(8).putLong(option.counter).array();

        // 3. 计算HMAC
        String algorithm = option.algorithm;
        Mac mac = Mac.getInstance(algorithm);
        mac.init(new SecretKeySpec(keyBytes, algorithm));
        byte[] hash = mac.doFinal(counterBytes);

        // 4. 动态截取生成OTP
        int offset = hash[hash.length - 1] & 0x0F;
        int binary = ((hash[offset] & 0x7F) << 24) |
                ((hash[offset + 1] & 0xFF) << 16) |
                ((hash[offset + 2] & 0xFF) << 8) |
                (hash[offset + 3] & 0xFF);
        Integer digits = option.digits;
        int otp = binary % (int) Math.pow(10, digits);
        return String.format("%0" + digits + "d", otp); // 补足前导零
    }

    // 验证HOTP
    // 建议（支持容错窗口）
    public static boolean verify(Option option) throws Exception {
        for (int i = 0; i <= option.window; i++) {
            String candidate = generate(option);
            if (candidate.equals(option.code)) {
                return true;
            }
        }
        return false;
    }
}
