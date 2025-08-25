package com.yutons.notp.code;

import com.yutons.notp.core.HOTP;
import com.yutons.notp.core.TOTP;
import com.yutons.notp.utils.CommonUtils;
import org.junit.jupiter.api.Test;

import java.time.Instant;

public class NOTPGeneratorTest {
    @Test
    void hotp() throws Exception {
        String secret = "newcapec"; // Base32密钥
        long counter = 0;
        Integer digits = 6;

        HOTP.Option option = new HOTP.Option();
        option.setSecret(secret);
        option.setCounter(counter);
        option.setDigits(digits);

        System.out.println("生成 32 位Base32密钥");
        System.out.println("=== 生成 32 位Base32密钥 ===");
        System.out.println(CommonUtils.generateSecret(20));

        System.out.println("生成 HOTP (使用计数器 0)");
        System.out.println("=== HOTP (Counter=0) ===");

        for (CommonUtils.Algorithm algorithm : CommonUtils.Algorithm.values()) {
            option.setAlgorithm(algorithm.getAlgorithm());
            String hotp = HOTP.generate(option);
            System.out.println("HOTP: " + hotp); // 示例：755224
            option.setCode(hotp);
            option.setWindow(5);
            System.out.println(String.format("%s HOTP：%s ;验证结果：%s", algorithm.getAlgorithm(), hotp, HOTP.verify(option)));
        }
    }

    @Test
    void totp() throws Exception {
        String secret = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        long currentTime = Instant.now().getEpochSecond();
        TOTP.Option option = new TOTP.Option();
        option.setSecret(secret);
        option.setTimestamp(currentTime);
        option.setDigits(6);
        System.out.println("生成 TOTP (使用当前时间戳)");
        System.out.println("=== TOTP (Timestamp=" + currentTime + ") ===");
        for (CommonUtils.Algorithm algorithm : CommonUtils.Algorithm.values()) {
            option.setAlgorithm(algorithm.getAlgorithm());
            String totp = TOTP.generate(option);
            System.out.println("TOTP: " + totp);
            option.setCode(totp);
            System.out.println("验证结果: " + TOTP.verify(option));

        }
    }
}
