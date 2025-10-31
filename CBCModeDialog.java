import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.List;
import javax.swing.*;

public class CBCModeDialog extends JDialog {
    private JTextField plaintextField, keyField, ivField, ciphertextField;
    private JComboBox<String> inputTypeComboBox, outputTypeComboBox;
    
    public CBCModeDialog(Frame owner) {
        super(owner, "CBC模式加密/解密", true);
        setSize(500, 400);
        setLayout(new GridLayout(8, 2, 10, 10));
        setLocationRelativeTo(owner);
        
        // 添加组件
        add(new JLabel("输入类型:"));
        String[] inputTypes = {"16进制", "ASCII字符串"};
        inputTypeComboBox = new JComboBox<>(inputTypes);
        add(inputTypeComboBox);
        
        add(new JLabel("输出类型:"));
        String[] outputTypes = {"16进制", "ASCII字符串"};
        outputTypeComboBox = new JComboBox<>(outputTypes);
        add(outputTypeComboBox);
        
        add(new JLabel("明文:", SwingConstants.RIGHT));
        plaintextField = new JTextField();
        add(plaintextField);
        
        add(new JLabel("密钥 (16位 16进制):", SwingConstants.RIGHT));
        keyField = new JTextField();
        add(keyField);
        
        add(new JLabel("初始化向量IV (16位 16进制):", SwingConstants.RIGHT));
        ivField = new JTextField();
        add(ivField);
        
        add(new JLabel("密文:", SwingConstants.RIGHT));
        ciphertextField = new JTextField();
        ciphertextField.setEditable(false);
        add(ciphertextField);
        
        // 添加加密解密按钮
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
                String iv = ivField.getText().trim();
                String inputType = (String) inputTypeComboBox.getSelectedItem();
                String outputType = (String) outputTypeComboBox.getSelectedItem();
                
                // 验证输入
                if (key.length() != 4) {
                    JOptionPane.showMessageDialog(CBCModeDialog.this, "请输入16位16进制密钥（4个16进制字符）");
                    return;
                }
                
                if (iv.length() != 4) {
                    JOptionPane.showMessageDialog(CBCModeDialog.this, "请输入16位16进制初始化向量");
                    return;
                }
                
                // 转换密钥和IV为整数
                int keyValue = Integer.parseInt(key, 16);
                int ivValue = Integer.parseInt(iv, 16);
                
                String result;
                
                // 根据输入类型处理
                if (inputType.equals("ASCII字符串")) {
                    // ASCII字符串处理
                    List<Integer> blocks = SAESUtils.asciiToBlocks(plaintext);
                    List<Integer> encryptedBlocks = SAESUtils.encryptCBC(blocks, keyValue, ivValue);
                    
                    // 根据输出类型格式化结果
                    if (outputType.equals("ASCII字符串")) {
                        result = SAESUtils.blocksToAscii(encryptedBlocks);
                    } else {
                        result = SAESUtils.blocksToHex(encryptedBlocks);
                    }
                } else {
                    // 16进制处理
                    if (plaintext.length() != 4) {
                        JOptionPane.showMessageDialog(CBCModeDialog.this, "请输入16位16进制数（4个16进制字符）");
                        return;
                    }
                    
                    int plaintextValue = Integer.parseInt(plaintext, 16);
                    List<Integer> blocks = new java.util.ArrayList<>();
                    blocks.add(plaintextValue);
                    
                    List<Integer> encryptedBlocks = SAESUtils.encryptCBC(blocks, keyValue, ivValue);
                    int ciphertextValue = encryptedBlocks.get(0);
                    
                    // 根据输出类型格式化结果
                    if (outputType.equals("ASCII字符串")) {
                        result = String.valueOf((char)((ciphertextValue >> 8) & 0xFF)) + 
                                String.valueOf((char)(ciphertextValue & 0xFF));
                    } else {
                        result = String.format("%04X", ciphertextValue);
                    }
                }
                
                // 显示结果
                ciphertextField.setText(result);
                
            } catch (NumberFormatException ex) {
                JOptionPane.showMessageDialog(CBCModeDialog.this, "请输入有效的16进制数");
                ex.printStackTrace();
            } catch (Exception ex) {
                JOptionPane.showMessageDialog(CBCModeDialog.this, "加密过程中出现错误: " + ex.getMessage());
                ex.printStackTrace();
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
                String iv = ivField.getText().trim();
                String inputType = (String) inputTypeComboBox.getSelectedItem();
                String outputType = (String) outputTypeComboBox.getSelectedItem();
                
                // 验证输入
                if (key.length() != 4) {
                    JOptionPane.showMessageDialog(CBCModeDialog.this, "请输入16位16进制密钥");
                    return;
                }
                
                if (iv.length() != 4) {
                    JOptionPane.showMessageDialog(CBCModeDialog.this, "请输入16位16进制初始化向量");
                    return;
                }
                
                // 转换密钥和IV为整数
                int keyValue = Integer.parseInt(key, 16);
                int ivValue = Integer.parseInt(iv, 16);
                
                String result;
                
                // 根据输入类型处理
                if (inputType.equals("ASCII字符串")) {
                    // 输入是ASCII字符串
                    List<Integer> encryptedBlocks = SAESUtils.asciiToBlocks(ciphertext);
                    List<Integer> decryptedBlocks = SAESUtils.decryptCBC(encryptedBlocks, keyValue, ivValue);
                    
                    // 根据输出类型格式化结果
                    if (outputType.equals("ASCII字符串")) {
                        result = SAESUtils.blocksToAscii(decryptedBlocks);
                    } else {
                        result = SAESUtils.blocksToHex(decryptedBlocks);
                    }
                } else {
                    // 输入是16进制
                    if (outputType.equals("ASCII字符串")) {
                        // 结果要输出为ASCII字符串
                        if (ciphertext.length() != 4) {
                            JOptionPane.showMessageDialog(CBCModeDialog.this, "请确保密文是16位16进制数");
                            return;
                        }
                        
                        int ciphertextValue = Integer.parseInt(ciphertext, 16);
                        List<Integer> encryptedBlocks = new java.util.ArrayList<>();
                        encryptedBlocks.add(ciphertextValue);
                        
                        List<Integer> decryptedBlocks = SAESUtils.decryptCBC(encryptedBlocks, keyValue, ivValue);
                        int plaintextValue = decryptedBlocks.get(0);
                        
                        // 转换为ASCII字符串
                        result = String.valueOf((char)((plaintextValue >> 8) & 0xFF)) + 
                                String.valueOf((char)(plaintextValue & 0xFF));
                    } else {
                        // 结果要输出为16进制
                        // 检查是否为多块数据
                        if (ciphertext.length() > 4 && ciphertext.length() % 4 == 0) {
                            // 多块数据
                            List<Integer> encryptedBlocks = SAESUtils.hexToBlocks(ciphertext);
                            List<Integer> decryptedBlocks = SAESUtils.decryptCBC(encryptedBlocks, keyValue, ivValue);
                            result = SAESUtils.blocksToHex(decryptedBlocks);
                        } else {
                            // 单块数据
                            if (ciphertext.length() != 4) {
                                JOptionPane.showMessageDialog(CBCModeDialog.this, "请确保密文是16位16进制数");
                                return;
                            }
                            
                            int ciphertextValue = Integer.parseInt(ciphertext, 16);
                            List<Integer> encryptedBlocks = new java.util.ArrayList<>();
                            encryptedBlocks.add(ciphertextValue);
                            
                            List<Integer> decryptedBlocks = SAESUtils.decryptCBC(encryptedBlocks, keyValue, ivValue);
                            int plaintextValue = decryptedBlocks.get(0);
                            result = String.format("%04X", plaintextValue);
                        }
                    }
                }
                
                // 显示结果
                plaintextField.setText(result);
                
            } catch (NumberFormatException ex) {
                JOptionPane.showMessageDialog(CBCModeDialog.this, "请输入有效的16进制数");
                ex.printStackTrace();
            } catch (Exception ex) {
                JOptionPane.showMessageDialog(CBCModeDialog.this, "解密过程中出现错误: " + ex.getMessage());
                ex.printStackTrace();
            }
        }
    }
}