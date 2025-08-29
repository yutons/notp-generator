package com.yutons.notp.core;


import com.yutons.notp.utils.CommonUtils;
import lombok.Data;

import java.time.Instant;

public class TOTP {
    private static final int TIME_STEP = 30; // 30秒步长

    @Data
    public static class Option {
        /**
         * Base32编码的密钥
         */
        private String secret;
        /**
         * 时间步长（秒），默认30秒
         */
        private Long period;
        /**
         * 验证码位数，默认6位
         */
        private Integer digits = 6;
        /**
         * HMAC算法，默认HMAC-SHA1
         */
        private String algorithm = CommonUtils.Algorithm.SHA1.getAlgorithm();
        /**
         * 指定时间的时间戳（毫秒）
         */
        private Long timestamp = Instant.now().getEpochSecond();
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
        CommonUtils.validateAlgorithm(option.algorithm);
        long timeCounter = option.timestamp / TIME_STEP;
        HOTP.Option hotpOption = new HOTP.Option();
        hotpOption.setSecret(option.secret);
        hotpOption.setCounter(timeCounter);
        hotpOption.setDigits(option.digits);
        hotpOption.setAlgorithm(option.algorithm);
        hotpOption.setWindow(option.window);
        return HOTP.generate(hotpOption);
    }

    public static boolean verify(Option option) throws Exception {
        long currentTime = Instant.now().getEpochSecond();
        long timeCounter = currentTime / TIME_STEP;
        // 检查当前时间窗口
        HOTP.Option hotpOption = new HOTP.Option();
        hotpOption.setAlgorithm(option.algorithm);
        hotpOption.setSecret(option.secret);
        hotpOption.setCounter(timeCounter);
        hotpOption.setDigits(option.digits);
        String candidate = HOTP.generate(hotpOption);
        if (candidate.equals(option.getCode())) {
            return true;
        }
        // 检查前后两个时间窗口（共3个值）
        /*for (int i = -1; i <= 1; i++) {
            HOTP.Option hotpOption = new HOTP.Option();
            hotpOption.setAlgorithm(option.algorithm);
            hotpOption.setSecret(option.secret);
            hotpOption.setCounter(timeCounter + i);
            hotpOption.setDigits(option.digits);
            String candidate = HOTP.generate(hotpOption);
            if (candidate.equals(option.getCode())) {
                return true;
            }
        }*/
        return false;
    }
}
