package com.yutons.notp.utils;


import org.apache.commons.codec.binary.Base32;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;

public class HmacSM3Utils {

    public static String hmacSm3(byte[] counterBytes, byte[] key) throws Exception {
        Mac mac = Mac.getInstance("HmacSM3", new BouncyCastleProvider());
        SecretKeySpec keySpec = new SecretKeySpec(key, "HmacSM3");
        mac.init(keySpec);
        // 注意，此处需要进行二次转换
        byte[] result = mac.doFinal(bytesToHex(counterBytes).getBytes());
        return bytesToHex(result);
    }

    /**
     * 将字节数组转换为小写十六进制字符串
     *
     * @param bytes 字节数组
     * @return 十六进制表示的字符串（小写）
     */
    public static String bytesToHex(byte[] bytes) {
        if (bytes == null || bytes.length == 0) {
            return "";
        }
        StringBuilder hex = new StringBuilder();
        for (byte b : bytes) {
            hex.append(String.format("%02x", b & 0xFF));
        }
        return hex.toString();
    }


    public static byte[] hexToBytes(String hex) {
        int len = hex.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                    + Character.digit(hex.charAt(i + 1), 16));
        }
        return data;
    }

    /**
     * 将 long 型计数器转换为 8 字节大端序（Big-Endian）字节数组
     *
     * @param counter 计数器值，范围 0 ~ 2^64-1
     * @return 8 字节的 byte[]，高位在前
     */
    public static byte[] intTo8Bytes(long counter) {
        return ByteBuffer.allocate(8)
                .order(ByteOrder.BIG_ENDIAN)  // 明确指定大端序
                .putLong(counter)
                .array();
    }

    public static void main(String[] args) throws Exception {
        String message = bytesToHex(intTo8Bytes(0));
        String secret = "JBSWY3DPEHPK3PXP";
        String keyHex = bytesToHex(new Base32().decode(secret));
        String expected = "5c690e2b822a514017f1ccb9a61b6738714dbd17dbd6fdbc2fa662d122b6885d";

        String result = hmacSm3(message.getBytes(StandardCharsets.UTF_8), hexToBytes(keyHex));
        System.out.println("Result: " + result);
        System.out.println("Match: " + result.equals(expected));
    }
}