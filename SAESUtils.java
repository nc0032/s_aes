import java.util.ArrayList;
import java.util.List;

public class SAESUtils {
    // 将ASCII字符串转换为16位数据块
    public static List<Integer> asciiToBlocks(String text) {
        List<Integer> blocks = new ArrayList<>();
        int i = 0;
        while (i < text.length()) {
            int block = 0;
            // 第一个字符作为高8位
            if (i < text.length()) {
                block |= (text.charAt(i) & 0xFF) << 8;
                i++;
            }
            // 第二个字符作为低8位
            if (i < text.length()) {
                block |= text.charAt(i) & 0xFF;
                i++;
            }
            blocks.add(block);
        }
        return blocks;
    }
    
    // 将数据块转换为ASCII字符串
    public static String blocksToAscii(List<Integer> blocks) {
        StringBuilder sb = new StringBuilder();
        for (Integer block : blocks) {
            // 高8位
            sb.append((char)((block >> 8) & 0xFF));
            // 低8位
            sb.append((char)(block & 0xFF));
        }
        return sb.toString();
    }
    
    // 将数据块转换为16进制字符串
    public static String blocksToHex(List<Integer> blocks) {
        StringBuilder sb = new StringBuilder();
        for (Integer block : blocks) {
            sb.append(String.format("%04X", block));
        }
        return sb.toString();
    }
    
    // 将16进制字符串转换为数据块列表
    public static List<Integer> hexToBlocks(String hexString) {
        List<Integer> blocks = new ArrayList<>();
        // 确保字符串长度为偶数
        if (hexString.length() % 4 != 0) {
            throw new IllegalArgumentException("16进制字符串长度必须是4的倍数");
        }
        
        for (int i = 0; i < hexString.length(); i += 4) {
            String blockHex = hexString.substring(i, i + 4);
            blocks.add(Integer.parseInt(blockHex, 16));
        }
        return blocks;
    }
    
    // 使用CBC模式加密多块数据
    public static List<Integer> encryptCBC(List<Integer> plaintextBlocks, int key, int iv) {
        List<Integer> ciphertextBlocks = new ArrayList<>();
        int previousBlock = iv;
        
        for (Integer block : plaintextBlocks) {
            // 当前块与前一个密文块（或IV）异或
            int xoredBlock = block ^ previousBlock;
            // 加密异或后的块
            int cipherBlock = SAESCore.encrypt(xoredBlock, key)[0];
            ciphertextBlocks.add(cipherBlock);
            previousBlock = cipherBlock;
        }
        
        return ciphertextBlocks;
    }
    
    // 使用CBC模式解密多块数据
    public static List<Integer> decryptCBC(List<Integer> ciphertextBlocks, int key, int iv) {
        List<Integer> plaintextBlocks = new ArrayList<>();
        int previousBlock = iv;
        
        for (Integer block : ciphertextBlocks) {
            // 解密当前块
            int decryptedBlock = SAESCore.decrypt(block, key);
            // 与前一个密文块（或IV）异或得到明文
            plaintextBlocks.add(decryptedBlock ^ previousBlock);
            previousBlock = block;
        }
        
        return plaintextBlocks;
    }
    
    // 使用CBC模式进行双重加密
    public static List<Integer> doubleEncryptCBC(List<Integer> plaintextBlocks, int key1, int key2, int iv) {
        List<Integer> ciphertextBlocks = new ArrayList<>();
        int previousBlock = iv;
        
        for (Integer block : plaintextBlocks) {
            // 当前块与前一个密文块（或IV）异或
            int xoredBlock = block ^ previousBlock;
            // 双重加密异或后的块
            int cipherBlock = SAESCore.doubleEncrypt(xoredBlock, key1, key2);
            ciphertextBlocks.add(cipherBlock);
            previousBlock = cipherBlock;
        }
        
        return ciphertextBlocks;
    }
    
    // 使用CBC模式进行双重解密
    public static List<Integer> doubleDecryptCBC(List<Integer> ciphertextBlocks, int key1, int key2, int iv) {
        List<Integer> plaintextBlocks = new ArrayList<>();
        int previousBlock = iv;
        
        for (Integer block : ciphertextBlocks) {
            // 双重解密当前块
            int decryptedBlock = SAESCore.doubleDecrypt(block, key1, key2);
            // 与前一个密文块（或IV）异或得到明文
            plaintextBlocks.add(decryptedBlock ^ previousBlock);
            previousBlock = block;
        }
        
        return plaintextBlocks;
    }
    
    // 使用CBC模式进行三重加密
    public static List<Integer> tripleEncryptCBC(List<Integer> plaintextBlocks, int key1, int key2, int key3, int iv) {
        List<Integer> ciphertextBlocks = new ArrayList<>();
        int previousBlock = iv;
        
        for (Integer block : plaintextBlocks) {
            // 当前块与前一个密文块（或IV）异或
            int xoredBlock = block ^ previousBlock;
            // 三重加密异或后的块
            int cipherBlock = SAESCore.tripleEncrypt(xoredBlock, key1, key2, key3);
            ciphertextBlocks.add(cipherBlock);
            previousBlock = cipherBlock;
        }
        
        return ciphertextBlocks;
    }
    
    // 使用CBC模式进行三重解密
    public static List<Integer> tripleDecryptCBC(List<Integer> ciphertextBlocks, int key1, int key2, int key3, int iv) {
        List<Integer> plaintextBlocks = new ArrayList<>();
        int previousBlock = iv;
        
        for (Integer block : ciphertextBlocks) {
            // 三重解密当前块
            int decryptedBlock = SAESCore.tripleDecrypt(block, key1, key2, key3);
            // 与前一个密文块（或IV）异或得到明文
            plaintextBlocks.add(decryptedBlock ^ previousBlock);
            previousBlock = block;
        }
        
        return plaintextBlocks;
    }
}