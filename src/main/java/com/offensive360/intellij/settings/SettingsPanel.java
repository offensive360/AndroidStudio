package com.offensive360.intellij.settings;

import javax.swing.*;

/**
 * Settings panel UI for Offensive360 configuration.
 */
public class SettingsPanel {
    private JPanel mainPanel;
    private JTextField endpointTextField;
    private JPasswordField tokenPasswordField;
    private JLabel endpointLabel;
    private JLabel tokenLabel;
    private JLabel infoLabel;

    public SettingsPanel() {
        createComponents();
    }

    private void createComponents() {
        mainPanel = new JPanel();
        mainPanel.setLayout(new BoxLayout(mainPanel, BoxLayout.Y_AXIS));

        // Info label
        infoLabel = new JLabel("Configure your O360 SAST server credentials below:");
        infoLabel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        mainPanel.add(infoLabel);

        // Endpoint panel
        JPanel endpointPanel = new JPanel();
        endpointPanel.setLayout(new BoxLayout(endpointPanel, BoxLayout.X_AXIS));
        endpointPanel.setBorder(BorderFactory.createEmptyBorder(5, 10, 5, 10));

        endpointLabel = new JLabel("Server URL:");
        endpointLabel.setPreferredSize(new java.awt.Dimension(150, 30));
        endpointTextField = new JTextField("https://sast.offensive360.com");
        endpointTextField.setColumns(40);
        endpointPanel.add(endpointLabel);
        endpointPanel.add(Box.createHorizontalStrut(10));
        endpointPanel.add(endpointTextField);
        mainPanel.add(endpointPanel);

        // Token panel
        JPanel tokenPanel = new JPanel();
        tokenPanel.setLayout(new BoxLayout(tokenPanel, BoxLayout.X_AXIS));
        tokenPanel.setBorder(BorderFactory.createEmptyBorder(5, 10, 5, 10));

        tokenLabel = new JLabel("API Access Token:");
        tokenLabel.setPreferredSize(new java.awt.Dimension(150, 30));
        tokenPasswordField = new JPasswordField();
        tokenPasswordField.setColumns(40);
        tokenPanel.add(tokenLabel);
        tokenPanel.add(Box.createHorizontalStrut(10));
        tokenPanel.add(tokenPasswordField);
        mainPanel.add(tokenPanel);

        // Add helper text
        JLabel helperLabel = new JLabel("(Generated from O360 Dashboard → Settings → Tokens)");
        helperLabel.setBorder(BorderFactory.createEmptyBorder(0, 160, 10, 10));
        helperLabel.setFont(helperLabel.getFont().deriveFont(10f));
        mainPanel.add(helperLabel);

        // Add stretch
        mainPanel.add(Box.createVerticalGlue());
    }

    public JPanel getPanel() {
        return mainPanel;
    }

    public String getEndpoint() {
        return endpointTextField.getText();
    }

    public void setEndpoint(String endpoint) {
        endpointTextField.setText(endpoint);
    }

    public String getAccessToken() {
        return new String(tokenPasswordField.getPassword());
    }

    public void setAccessToken(String token) {
        tokenPasswordField.setText(token);
    }
}
