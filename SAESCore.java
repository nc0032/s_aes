public class SAESCore {
    // S盒定义
    private static final int[][] S_BOX = {
        {0x9, 0x4, 0xA, 0xB},
        {0xD, 0x1, 0x8, 0x5},
        {0x6, 0x2, 0x0, 0x3},
        {0xC, 0xE, 0xF, 0x7}
    };
    
    // 逆S盒
    private static final int[][] INV_S_BOX = {
        {0xA, 0x5, 0x9, 0xB},
        {0x1, 0x7, 0x8, 0xF},
        {0x6, 0x0, 0x2, 0x3},
        {0xC, 0x4, 0xD, 0xE}
    };
    
    // 加密函数，返回数组[密文, 第一轮中间结果]
    public static int[] encrypt(int plaintext, int key) {
        // 密钥扩展
        int[] w = keyExpansion(key);
        
        // 初始轮密钥加
        int state = plaintext ^ ((w[0] << 8) | w[1]);
        
        // 第一轮
        System.out.println("\n--- 第一轮开始 ---");
        state = subNibbles(state);
        state = mixColumns(state);
        state ^= ((w[2] << 8) | w[3]);
        
        // 保存第一轮中间结果
        int intermediateResult = state;
        
        // 第二轮
        state = subNibbles(state);
        state = shiftRows(state);
        state ^= ((w[4] << 8) | w[5]);
        
        return new int[]{state, intermediateResult};
    }
    
    // 解密函数
    public static int decrypt(int ciphertext, int key) {
        // 密钥扩展
        int[] w = keyExpansion(key);
        
        // 初始轮密钥加
        int state = ciphertext ^ ((w[4] << 8) | w[5]);
        
        // 第一轮逆操作
        state = invShiftRows(state);
        state = invSubNibbles(state);
        state ^= ((w[2] << 8) | w[3]);
        state = invMixColumns(state);
        
        // 第二轮逆操作
        state = invShiftRows(state);
        state = invSubNibbles(state);
        state ^= ((w[0] << 8) | w[1]);
        
        return state;
    }
    
    // 双重加密：使用key1加密后用key2再加密
    public static int doubleEncrypt(int plaintext, int key1, int key2) {
        int firstEncrypt = encrypt(plaintext, key1)[0];
        return encrypt(firstEncrypt, key2)[0];
    }
    
    // 双重解密：使用key2解密后用key1再解密
    public static int doubleDecrypt(int ciphertext, int key1, int key2) {
        int firstDecrypt = decrypt(ciphertext, key2);
        return decrypt(firstDecrypt, key1);
    }
    
    // 三重加密：使用key1加密，key2解密，key3加密 (Encrypt-Decrypt-Encrypt)
    public static int tripleEncrypt(int plaintext, int key1, int key2, int key3) {
        int firstEncrypt = encrypt(plaintext, key1)[0];
        int decrypt = decrypt(firstEncrypt, key2);
        return encrypt(decrypt, key3)[0];
    }
    
    // 三重解密：使用key3解密，key2加密，key1解密 (Decrypt-Encrypt-Decrypt)
    public static int tripleDecrypt(int ciphertext, int key1, int key2, int key3) {
        int firstDecrypt = decrypt(ciphertext, key3);
        int encrypt = encrypt(firstDecrypt, key2)[0];
        return decrypt(encrypt, key1);
    }
    
    // 密钥扩展
    private static int[] keyExpansion(int key) {
        int[] w = new int[6];
        w[0] = (key >> 8) & 0xFF;
        w[1] = key & 0xFF;
        
        // 计算w2和w3
        int temp = w[1];
        temp = rotNib(temp);
        temp = subNib(temp);
        temp ^= 0x80; // RCON(1) = 10000000
        w[2] = w[0] ^ temp;
        w[3] = w[1] ^ w[2];
        
        // 计算w4和w5
        temp = w[3];
        temp = rotNib(temp);
        temp = subNib(temp);        
        temp ^= 0x30; // RCON(2) = 00110000
        w[4] = w[2] ^ temp;
        w[5] = w[3] ^ w[4];
        
        return w;
    }
    
    // 半字节替代
    private static int subNibbles(int state) {
        int[] nibbles = new int[4];
        nibbles[0] = (state >> 12) & 0xF;
        nibbles[1] = (state >> 8) & 0xF;
        nibbles[2] = (state >> 4) & 0xF;
        nibbles[3] = state & 0xF;
        
        // 对每个半字节应用S盒
        for (int i = 0; i < 4; i++) {
            int row = (nibbles[i] >> 2) & 0x3;
            int col = nibbles[i] & 0x3;
            nibbles[i] = S_BOX[row][col];
        }
        
        return (nibbles[0] << 12) | (nibbles[1] << 8) | (nibbles[2] << 4) | nibbles[3];
    }
    
    // 逆半字节替代
    private static int invSubNibbles(int state) {
        int[] nibbles = new int[4];
        nibbles[0] = (state >> 12) & 0xF;
        nibbles[1] = (state >> 8) & 0xF;
        nibbles[2] = (state >> 4) & 0xF;
        nibbles[3] = state & 0xF;
        
        // 对每个半字节应用逆S盒
        for (int i = 0; i < 4; i++) {
            int row = (nibbles[i] >> 2) & 0x3;
            int col = nibbles[i] & 0x3;
            nibbles[i] = INV_S_BOX[row][col];
        }
        
        return (nibbles[0] << 12) | (nibbles[1] << 8) | (nibbles[2] << 4) | nibbles[3];
    }
    
    // 行移位
    private static int shiftRows(int state) {
        // 提取四个半字节
        int s00 = (state >> 12) & 0xF;
        int s01 = (state >> 8) & 0xF;
        int s10 = (state >> 4) & 0xF;
        int s11 = state & 0xF;
        
        // 第二行左移一个位置（交换s10和s11）
        return (s00 << 12) | (s01 << 8) | (s11 << 4) | s10;
    }
    
    // 逆行移位
    private static int invShiftRows(int state) {
        // 逆操作与原操作相同，因为只交换一次
        return shiftRows(state);
    }
    
    // 列混淆
    private static int mixColumns(int state) {
        // 将状态表示为2x2矩阵
        // s00 s01
        // s10 s11
        int s00 = (state >> 12) & 0xF;  // 左上角
        int s01 = (state >> 8) & 0xF;   // 右上角
        int s10 = (state >> 4) & 0xF;   // 左下角
        int s11 = state & 0xF;          // 右下角
        
        // 应用列混淆公式
        int s00_prime = gmul(s00, 0x1) ^ gmul(s10, 0x4);  // s'00 = s00 异或 (4*s10)
        int s10_prime = gmul(s00, 0x4) ^ gmul(s10, 0x1);  // s'10 = (4*s00) 异或 s10
        int s01_prime = gmul(s01, 0x1) ^ gmul(s11, 0x4);  // 第二列的操作相同
        int s11_prime = gmul(s01, 0x4) ^ gmul(s11, 0x1);
        
        // 重新组合为16位状态
        return (s00_prime << 12) | (s01_prime << 8) | (s10_prime << 4) | s11_prime;
    }
    
    // 逆列混淆
    private static int invMixColumns(int state) {
        // 将状态表示为2x2矩阵
        int s00 = (state >> 12) & 0xF;
        int s01 = (state >> 8) & 0xF;
        int s10 = (state >> 4) & 0xF;
        int s11 = state & 0xF;
        
        // 应用逆列混淆公式
        int s00_prime = gmul(s00, 0x9) ^ gmul(s10, 0x2);  // 使用逆列混淆矩阵
        int s10_prime = gmul(s00, 0x2) ^ gmul(s10, 0x9);
        int s01_prime = gmul(s01, 0x9) ^ gmul(s11, 0x2);
        int s11_prime = gmul(s01, 0x2) ^ gmul(s11, 0x9);
        
        return (s00_prime << 12) | (s01_prime << 8) | (s10_prime << 4) | s11_prime;
    }
    
    // 半字节旋转
    private static int rotNib(int value) {
        return ((value & 0xF) << 4) | ((value >> 4) & 0xF);
    }
    
    // 单个半字节的S盒替代
    private static int subNib(int value) {
        int nib1 = (value >> 4) & 0xF;
        int nib2 = value & 0xF;
        
        int row1 = (nib1 >> 2) & 0x3;
        int col1 = nib1 & 0x3;
        int row2 = (nib2 >> 2) & 0x3;
        int col2 = nib2 & 0x3;
        
        return (S_BOX[row1][col1] << 4) | S_BOX[row2][col2];
    }
    
    // 伽罗瓦域GF(2^4)上的乘法
    private static int gmul(int a, int b) {
        int p = 0;
        int hi_bit_set;
        for (int i = 0; i < 4; i++) {
            if ((b & 1) != 0) {
                p ^= a;
            }
            hi_bit_set = a & 8;
            a <<= 1;
            if (hi_bit_set != 0) {
                a ^= 0x03; // 多项式x^4 + x + 1
            }
            a &= 0xF;
            b >>= 1;
        }
        return p;
    }
}