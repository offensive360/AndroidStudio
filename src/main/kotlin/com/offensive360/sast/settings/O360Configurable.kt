package com.offensive360.sast.settings

import com.intellij.openapi.options.Configurable
import com.intellij.ui.components.JBCheckBox
import com.intellij.ui.components.JBLabel
import com.intellij.ui.components.JBPasswordField
import com.intellij.ui.components.JBTextField
import com.intellij.util.ui.FormBuilder
import javax.swing.JComponent
import javax.swing.JPanel

class O360Configurable : Configurable {

    private val endpointField = JBTextField()
    private val tokenField = JBPasswordField()
    private val scanDepsCheckbox = JBCheckBox("Include dependency vulnerability scanning (SCA)")
    private val scanLicensesCheckbox = JBCheckBox("Include open source license compliance scanning")
    private val scanMalwareCheckbox = JBCheckBox("Include malware detection scanning")

    private var panel: JPanel? = null

    override fun getDisplayName(): String = "O360 SAST"

    override fun createComponent(): JComponent {
        panel = FormBuilder.createFormBuilder()
            .addLabeledComponent(JBLabel("Endpoint:"), endpointField, 1, false)
            .addTooltip("O360 SAST server URL (e.g. https://your-server.com:1800)")
            .addLabeledComponent(JBLabel("Access Token:"), tokenField, 1, false)
            .addTooltip("Generated from O360 dashboard → Settings → Access Tokens")
            .addSeparator()
            .addComponent(scanDepsCheckbox, 1)
            .addComponent(scanLicensesCheckbox, 1)
            .addComponent(scanMalwareCheckbox, 1)
            .addComponentFillVertically(JPanel(), 0)
            .panel
        return panel!!
    }

    override fun isModified(): Boolean {
        val s = O360Settings.getInstance()
        return endpointField.text != s.endpoint ||
                String(tokenField.password) != s.accessToken ||
                scanDepsCheckbox.isSelected != s.scanDependencies ||
                scanLicensesCheckbox.isSelected != s.scanLicenses ||
                scanMalwareCheckbox.isSelected != s.scanMalware
    }

    override fun apply() {
        val s = O360Settings.getInstance()
        s.endpoint = endpointField.text.trimEnd('/')
        s.accessToken = String(tokenField.password)
        s.scanDependencies = scanDepsCheckbox.isSelected
        s.scanLicenses = scanLicensesCheckbox.isSelected
        s.scanMalware = scanMalwareCheckbox.isSelected
    }

    override fun reset() {
        val s = O360Settings.getInstance()
        endpointField.text = s.endpoint
        tokenField.text = s.accessToken
        scanDepsCheckbox.isSelected = s.scanDependencies
        scanLicensesCheckbox.isSelected = s.scanLicenses
        scanMalwareCheckbox.isSelected = s.scanMalware
    }
}
