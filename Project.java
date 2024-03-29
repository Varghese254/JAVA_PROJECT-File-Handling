import javax.swing.*;
import java.awt.event.*;
import java.io.*;
import java.util.Scanner;
import java.util.zip.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

public class Project {

    static Scanner scanner = new Scanner(System.in);

    public static void main(String[] args) {
        SwingUtilities.invokeLater(new Runnable() {
            public void run() {
                createAndShowGUI();
            }
        });
    }

    private static void createAndShowGUI() {
        JFrame frame = new JFrame("File Management System");
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.setSize(400, 200);
        frame.setLocationRelativeTo(null);

        JPanel panel = new JPanel();
        JButton encryptBtn = new JButton("Encrypt File");
        JButton decryptBtn = new JButton("Decrypt File");
        JButton compressBtn = new JButton("Compress File");
        JButton exitBtn = new JButton("Exit");

        panel.add(encryptBtn);
        panel.add(decryptBtn);
        panel.add(compressBtn);
        panel.add(exitBtn);

        frame.add(panel);

        encryptBtn.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                encryptFile();
            }
        });

        decryptBtn.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                decryptFile();
            }
        });

        compressBtn.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                compressFile();
            }
        });

        exitBtn.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                System.exit(0);
            }
        });

        frame.setVisible(true);
    }

    public static void encryptFile() {
        System.out.print("Enter the path of the input file: ");
        String inputFile = scanner.nextLine();
        System.out.print("Enter the path for the encrypted file: ");
        String encryptedFile = scanner.nextLine();

        try {
            String key = "ThisIsASecretKey"; // 16-character secret key for AES encryption
            try (FileInputStream fis = new FileInputStream(inputFile);
                 FileOutputStream fos = new FileOutputStream(encryptedFile)) {
                byte[] fileContent = Files.readAllBytes(Paths.get(inputFile));
                SecretKeySpec secretKey = new SecretKeySpec(key.getBytes(), "AES");
                Cipher cipher = Cipher.getInstance("AES");
                cipher.init(Cipher.ENCRYPT_MODE, secretKey);
                byte[] encryptedFileContent = cipher.doFinal(fileContent);
                fos.write(encryptedFileContent);
                System.out.println("File encrypted successfully.");
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void decryptFile() {
        System.out.print("Enter the path of the encrypted file: ");
        String encryptedInputFile = scanner.nextLine();
        System.out.print("Enter the path for the decrypted file: ");
        String decryptedOutputFile = scanner.nextLine();

        try {
            String key = "ThisIsASecretKey"; // 16-character secret key for AES encryption
            try (FileInputStream fis = new FileInputStream(encryptedInputFile);
                 FileOutputStream fos = new FileOutputStream(decryptedOutputFile)) {
                SecretKeySpec secretKey = new SecretKeySpec(key.getBytes(), "AES");
                Cipher cipher = Cipher.getInstance("AES");
                cipher.init(Cipher.DECRYPT_MODE, secretKey);
                byte[] decryptedFileContent = cipher.doFinal(Files.readAllBytes(Paths.get(encryptedInputFile)));
                fos.write(decryptedFileContent);
                System.out.println("File decrypted successfully.");
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void compressFile() {
        System.out.print("Enter the path of the file to compress: ");
        String inputFileToCompress = scanner.nextLine();
        System.out.print("Enter the path for the compressed file: ");
        String compressedFile = scanner.nextLine();

        try {
            try (FileInputStream fis = new FileInputStream(inputFileToCompress);
                 FileOutputStream fos = new FileOutputStream(compressedFile);
                 ZipOutputStream zos = new ZipOutputStream(fos)) {
                zos.putNextEntry(new ZipEntry(new File(inputFileToCompress).getName()));
                byte[] buffer = new byte[1024];
                int bytesRead;
                while ((bytesRead = fis.read(buffer)) > 0) {
                    zos.write(buffer, 0, bytesRead);
                }
                zos.closeEntry();
                System.out.println("File compressed successfully.");
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
