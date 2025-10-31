import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

public class SAESTool extends JFrame {
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
    
    // 列混淆矩阵
    private static final int[][] MIX_COLUMNS_MATRIX = {{0x1, 0x4}, {0x4, 0x1}};
    
    // 逆列混淆矩阵
    private static final int[][] INV_MIX_COLUMNS_MATRIX = {{0x9, 0x2}, {0x2, 0x9}};
    
    // 文本框组件
    private JTextField plaintextField, keyField, ciphertextField, intermediateField;
    
    public SAESTool() {
        // 设置窗口属性
        setTitle("S-AES加密工具");
        setSize(500, 300);
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setLayout(new GridLayout(6, 2, 10, 10));
        setLocationRelativeTo(null);
        
        // 添加组件
        add(new JLabel("明文 (16位 16进制):"));
        plaintextField = new JTextField();
        add(plaintextField);
        
        add(new JLabel("密钥 (16位 16进制):"));
        keyField = new JTextField();
        add(keyField);
        
        add(new JLabel("密文:"));
        ciphertextField = new JTextField();
        ciphertextField.setEditable(true);
        add(ciphertextField);
        
        add(new JLabel("第一轮中间结果:"));
        intermediateField = new JTextField();
        intermediateField.setEditable(false);
        add(intermediateField);
        
        JButton encryptButton = new JButton("加密");
        encryptButton.addActionListener(new EncryptAction());
        add(encryptButton);
        
        JButton decryptButton = new JButton("解密");
        decryptButton.addActionListener(new DecryptAction());
        add(decryptButton);
    }
    
    // 加密按钮事件处理
    private class EncryptAction implements ActionListener {
        @Override
        public void actionPerformed(ActionEvent e) {
            try {
                String plaintext = plaintextField.getText().trim();
                String key = keyField.getText().trim();
                
                // 验证输入
                if (plaintext.length() != 4 || key.length() != 4) {
                    JOptionPane.showMessageDialog(SAESTool.this, "请输入16位16进制数（4个16进制字符）");
                    return;
                }
                
                // 转换为二进制数据
                int plaintextValue = Integer.parseInt(plaintext, 16);
                int keyValue = Integer.parseInt(key, 16);
                
                // 加密
                int[] result = encrypt(plaintextValue, keyValue);
                int ciphertext = result[0];
                int intermediate = result[1];
                
                // 显示结果
                ciphertextField.setText(String.format("%04X", ciphertext));
                intermediateField.setText(String.format("%04X", intermediate));
                
            } catch (NumberFormatException ex) {
                JOptionPane.showMessageDialog(SAESTool.this, "请输入有效的16进制数");
            }
        }
    }
    
    // 解密按钮事件处理
    private class DecryptAction implements ActionListener {
        @Override
        public void actionPerformed(ActionEvent e) {
            try {
                String ciphertext = ciphertextField.getText().trim();
                String key = keyField.getText().trim();
                
                // 验证输入
                if (ciphertext.length() != 4 || key.length() != 4) {
                    JOptionPane.showMessageDialog(SAESTool.this, "请确保密文和密钥都是16位16进制数");
                    return;
                }
                
                // 转换为二进制数据
                int ciphertextValue = Integer.parseInt(ciphertext, 16);
                int keyValue = Integer.parseInt(key, 16);
                
                // 解密
                int plaintext = decrypt(ciphertextValue, keyValue);
                
                // 显示结果
                plaintextField.setText(String.format("%04X", plaintext));
                
            } catch (NumberFormatException ex) {
                JOptionPane.showMessageDialog(SAESTool.this, "请输入有效的16进制数");
            }
        }
    }
    
    // 加密函数，返回数组[密文, 第一轮中间结果]
    private int[] encrypt(int plaintext, int key) {
        // 密钥扩展
        int[] w = keyExpansion(key);
        System.out.println("密钥扩展结果: w0=" + String.format("%02X", w[0]) + ", w1=" + String.format("%02X", w[1]) + ", w2=" + String.format("%02X", w[2]) + ", w3=" + String.format("%02X", w[3]) + ", w4=" + String.format("%02X", w[4]) + ", w5=" + String.format("%02X", w[5]));
        // 初始轮密钥加
        int state = plaintext ^ ((w[0] << 8) | w[1]);
         System.out.println("初始轮密钥加后状态 (二进制): " + String.format("%16s", Integer.toBinaryString(state)).replace(' ', '0') + " (十六进制): " + String.format("%04X", state));
        // 第一轮
        state = subNibbles(state);
        System.out.println("第一轮半字节替代后状态 (二进制): " + String.format("%16s", Integer.toBinaryString(state)).replace(' ', '0') + " (十六进制): " + String.format("%04X", state));
        state = shiftRows(state);
        System.out.println("第一轮行移位后状态 (二进制): " + String.format("%16s", Integer.toBinaryString(state)).replace(' ', '0') + " (十六进制): " + String.format("%04X", state));
        state = mixColumns(state);
        System.out.println("第一轮列混淆后状态 (二进制): " + String.format("%16s", Integer.toBinaryString(state)).replace(' ', '0') + " (十六进制): " + String.format("%04X", state));
        state ^= ((w[2] << 8) | w[3]);
        
        // 保存第一轮中间结果
        int intermediateResult = state;
        
        // 第二轮
        state = subNibbles(state);
        System.out.println("第二轮半字节替代后状态 (二进制): " + String.format("%16s", Integer.toBinaryString(state)).replace(' ', '0') + " (十六进制): " + String.format("%04X", state));
        state = shiftRows(state);
        System.out.println("第二轮行移位后状态 (二进制): " + String.format("%16s", Integer.toBinaryString(state)).replace(' ', '0') + " (十六进制): " + String.format("%04X", state));
        state ^= ((w[4] << 8) | w[5]);
        System.out.println("第二轮轮密钥加后状态 (二进制): " + String.format("%16s", Integer.toBinaryString(state)).replace(' ', '0') + " (十六进制): " + String.format("%04X", state));
        
        return new int[]{state, intermediateResult};
    }
    
    // 解密函数
    private int decrypt(int ciphertext, int key) {
        // 密钥扩展
        int[] w = keyExpansion(key);
        
        // 初始轮密钥加
        int state = ciphertext ^ ((w[4] << 8) | w[5]);
        
        // 第一轮逆操作
        state = invShiftRows(state);
        System.out.println("第一轮逆行移位后状态 (二进制): " + String.format("%16s", Integer.toBinaryString(state)).replace(' ', '0') + " (十六进制): " + String.format("%04X", state));
        state = invSubNibbles(state);
        System.out.println("第一轮逆半字节替代后状态 (二进制): " + String.format("%16s", Integer.toBinaryString(state)).replace(' ', '0') + " (十六进制): " + String.format("%04X", state));
        state ^= ((w[2] << 8) | w[3]);
        System.out.println("第一轮逆轮密钥加后状态 (二进制): " + String.format("%16s", Integer.toBinaryString(state)).replace(' ', '0') + " (十六进制): " + String.format("%04X", state));
        state = invMixColumns(state);
        
        // 第二轮逆操作
        state = invShiftRows(state);
        System.out.println("第二轮逆行移位后状态 (二进制): " + String.format("%16s", Integer.toBinaryString(state)).replace(' ', '0') + " (十六进制): " + String.format("%04X", state));
        state = invSubNibbles(state);
        System.out.println("第二轮逆半字节替代后状态 (二进制): " + String.format("%16s", Integer.toBinaryString(state)).replace(' ', '0') + " (十六进制): " + String.format("%04X", state));
        state ^= ((w[0] << 8) | w[1]);
        System.out.println("第二轮逆轮密钥加后状态 (二进制): " + String.format("%16s", Integer.toBinaryString(state)).replace(' ', '0') + " (十六进制): " + String.format("%04X", state));
        
        return state;
    }
    
    // 密钥扩展
    private int[] keyExpansion(int key) {
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
    private int subNibbles(int state) {
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
    private int invSubNibbles(int state) {
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
    private int shiftRows(int state) {
        int nibble1 = (state >> 8) & 0xF;
        int nibble3 = (state >> 4) & 0xF;
        
        // 交换第二行的两个半字节
        state = (state & 0xF0F0) | (nibble3 << 8) | nibble1;
        return state;
    }
    
    // 逆行移位
    private int invShiftRows(int state) {
        // 逆操作与原操作相同，因为只交换一次
        return shiftRows(state);
    }
    
    // 列混淆
   private int mixColumns(int state) {
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
   private int invMixColumns(int state) {
    int[] columns = new int[2];
    columns[0] = (state >> 8) & 0xFF;
    columns[1] = state & 0xFF;
    
    int[] newColumns = new int[2];
    newColumns[0] = (gmul(columns[0] >> 4, 0x9) ^ gmul(columns[0] & 0xF, 0x2)) << 4 | 
                    (gmul(columns[1] >> 4, 0x2) ^ gmul(columns[1] & 0xF, 0x9));
    newColumns[1] = (gmul(columns[0] >> 4, 0x2) ^ gmul(columns[0] & 0xF, 0x9)) << 4 | 
                    (gmul(columns[1] >> 4, 0x9) ^ gmul(columns[1] & 0xF, 0x2));
    
    return (newColumns[0] << 8) | newColumns[1];
}
    // 半字节旋转
    private int rotNib(int value) {
        return ((value & 0xF) << 4) | ((value >> 4) & 0xF);
    }
    
    // 单个半字节的S盒替代
    private int subNib(int value) {
        int nib1 = (value >> 4) & 0xF;
        int nib2 = value & 0xF;
        
        int row1 = (nib1 >> 2) & 0x3;
        int col1 = nib1 & 0x3;
        int row2 = (nib2 >> 2) & 0x3;
        int col2 = nib2 & 0x3;
        
        return (S_BOX[row1][col1] << 4) | S_BOX[row2][col2];
    }
    
    // 伽罗瓦域GF(2^4)上的乘法
    private int gmul(int a, int b) {
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
    
    public static void main(String[] args) {
        // 在事件调度线程中创建和显示GUI
        SwingUtilities.invokeLater(new Runnable() {
            public void run() {
                new SAESTool().setVisible(true);
            }
        });
    }
}