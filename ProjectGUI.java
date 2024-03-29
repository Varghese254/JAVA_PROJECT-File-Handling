import javax.swing.*;
import java.awt.event.*;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class ProjectGUI extends JFrame {
    private static final long serialVersionUID = 1L;
    private JButton userRegistrationBtn, loginBtn, exitBtn;
    private JPanel panel;

    public ProjectGUI() {
        setTitle("File Management System");
        setSize(400, 200);
        setDefaultCloseOperation(EXIT_ON_CLOSE);
        setLocationRelativeTo(null);

        panel = new JPanel();
        userRegistrationBtn = new JButton("User Registration");
        loginBtn = new JButton("Login");
        exitBtn = new JButton("Exit");

        panel.add(userRegistrationBtn);
        panel.add(loginBtn);
        panel.add(exitBtn);
        add(panel);

        userRegistrationBtn.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                userRegistration();
            }
        });

        loginBtn.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                login();
            }
        });

        exitBtn.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                System.exit(0);
            }
        });
    }

    public void userRegistration() {
        try {
            Class.forName("com.mysql.jdbc.Driver");
            String idStr = JOptionPane.showInputDialog("Enter id:");
            if (idStr == null) return; 
            int id;
            try {
                id = Integer.parseInt(idStr);
            } catch (NumberFormatException e) {
                JOptionPane.showMessageDialog(null, "Invalid id");
                return;
            }
        
            String username = JOptionPane.showInputDialog("Enter username:");
            if (username == null) return; 
        
            String password = JOptionPane.showInputDialog("Enter password:");
            if (password == null) return; 
        
            try (Connection con = DriverManager.getConnection("jdbc:mysql://localhost:3307/ems_db?CharacterEncoding=utf8", "root", "");
                 Statement st = con.createStatement()) {
                String query = "INSERT INTO tbl_reg VALUES(" + id + ", '" + username + "', '" + password + "')";
                int rowsAffected = st.executeUpdate(query);
                if (rowsAffected > 0) {
                    JOptionPane.showMessageDialog(null, "User registered successfully");
                } else {
                    JOptionPane.showMessageDialog(null, "Failed to register user");
                }
            } catch (SQLException e) {
                JOptionPane.showMessageDialog(null, "Error: " + e.getMessage());
            }
        } catch (ClassNotFoundException e) {
            JOptionPane.showMessageDialog(null, "Error: " + e.getMessage());
        }
    }
    

    public void login() {
        String username = JOptionPane.showInputDialog("Enter Username:");
        if (username == null) return; 

        String password = JOptionPane.showInputDialog("Enter Password:");
        if (password == null) return; 
        try {
            Class.forName("com.mysql.jdbc.Driver");
            try (Connection con = DriverManager.getConnection("jdbc:mysql://localhost:3307/ems_db?CharacterEncoding=utf8", "root", "");
                 Statement st = con.createStatement()) {
                String query = "SELECT * FROM tbl_reg WHERE uname = '" + username + "' AND password = '" + password + "'";
                try (ResultSet rs = st.executeQuery(query)) {
                    if (rs.next()) {
                        JOptionPane.showMessageDialog(null, "Login successful");
                        
                        Project.main(new String[0]);
                        dispose(); 
                    } else {
                        JOptionPane.showMessageDialog(null, "Invalid user");
                    }
                }
            }
        } catch (ClassNotFoundException | SQLException e) {
            JOptionPane.showMessageDialog(null, "Error: " + e.getMessage());
        }
    }

    public static void main(String[] args) {
        SwingUtilities.invokeLater(new Runnable() {
            public void run() {
                new ProjectGUI().setVisible(true);
            }
        });
    }
}
