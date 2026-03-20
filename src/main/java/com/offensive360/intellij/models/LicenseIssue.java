package com.offensive360.intellij.models;

/**
 * Typed model for a license compliance issue.
 */
public class LicenseIssue {
    private String id;
    private String fileName;
    private String licenseName;
    private String licenseType;
    private String riskLevel;

    public LicenseIssue() {}

    public String getId() { return id; }
    public void setId(String id) { this.id = id; }

    public String getFileName() { return fileName; }
    public void setFileName(String fileName) { this.fileName = fileName; }

    public String getLicenseName() { return licenseName; }
    public void setLicenseName(String licenseName) { this.licenseName = licenseName; }

    public String getLicenseType() { return licenseType; }
    public void setLicenseType(String licenseType) { this.licenseType = licenseType; }

    public String getRiskLevel() { return riskLevel; }
    public void setRiskLevel(String riskLevel) { this.riskLevel = riskLevel; }
}
