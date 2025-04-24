from burp import IBurpExtender, ITab, IContextMenuFactory
from javax.swing import JPanel, JLabel, JButton, JTextField, JTextArea, JScrollPane, JMenuItem
from java.awt import BorderLayout, Font
from java.net import URL
from burp import IContextMenuInvocation


class BurpExtender(IBurpExtender, ITab, IContextMenuFactory):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Security Header Checker")

        # === UI Setup ===
        self.panel = JPanel(BorderLayout())
        top_panel = JPanel()

        self.url_label = JLabel("Target URL:")
        self.url_field = JTextField(30)
        self.toggle_button = JButton("Start", actionPerformed=self.toggleScan)
        self.clear_button = JButton("Clear Output", actionPerformed=self.clearOutput)
        self.status_label = JLabel("Status: Ready to scan")

        top_panel.add(self.url_label)
        top_panel.add(self.url_field)
        top_panel.add(self.toggle_button)
        top_panel.add(self.clear_button)

        self.text_area = JTextArea(25, 80)
        self.text_area.setFont(Font("Monospaced", Font.PLAIN, 20))
        self.text_area.setEditable(False)
        self.text_area.setLineWrap(True)  
        self.text_area.setWrapStyleWord(True)  
        self.scroll_pane = JScrollPane(self.text_area)

        self.panel.add(top_panel, BorderLayout.NORTH)
        self.panel.add(self.scroll_pane, BorderLayout.CENTER)
        self.panel.add(self.status_label, BorderLayout.SOUTH)

        callbacks.addSuiteTab(self)

        
        callbacks.registerContextMenuFactory(self)

        return

    def getTabCaption(self):
        return "Header Scanner"

    def getUiComponent(self):
        return self.panel

    def toggleScan(self, event):
        url_text = self.url_field.getText().strip()
        self.text_area.append("[*] Scanning URL: {}\n".format(url_text))
        self.status_label.setText("Status: Scanning...")

        if not url_text.startswith("http"):
            self.status_label.setText("Status: Invalid URL")
            self.text_area.append("[!] Please provide a URL starting with http or https.\n")
            return

        try:
            url = URL(url_text)
            connection = url.openConnection()
            connection.setRequestMethod("GET")
            connection.setConnectTimeout(5000)
            connection.setReadTimeout(5000)
            connection.connect()

            headers = {}
            idx = 1
            while True:
                key = connection.getHeaderFieldKey(idx)
                value = connection.getHeaderField(idx)
                if key is None and value is None:
                    break
                if key:
                    headers[key] = value
                idx += 1

            required = {
                "Strict-Transport-Security": "HSTS (Strict-Transport-Security)",
                "Content-Security-Policy": "CSP (Content-Security-Policy)",
                "X-Frame-Options": "X-Frame-Options",
                "X-Content-Type-Options": "X-Content-Type-Options",
                "Referrer-Policy": "Referrer-Policy",
                "Permissions-Policy": "Permissions-Policy"
            }

            result = ""
            for k, desc in required.items():
                if k not in headers:
                    result += "[-] Missing: {}\n".format(desc)
                else:
                    result += "[+] Present: {} -> {}\n".format(k, headers[k])

            self.text_area.append(result + "\n")
            self.status_label.setText("Status: Scan complete.")

        except Exception as e:
            self.text_area.append("[!] Error: {}\n".format(str(e)))
            self.status_label.setText("Status: Scan failed.")

    def clearOutput(self, event):
        self.text_area.setText("")
        self.status_label.setText("Status: Ready to scan")

    def createMenuItems(self, invocation):
        context = invocation.getInvocationContext()
        print("[DEBUG] Context: {}".format(context)) 

        menu_items = []

        if context == IContextMenuInvocation.CONTEXT_REPEATER:
            print("[DEBUG] Repeater context detected!")
            item = JMenuItem("Send to Header Scanner", actionPerformed=lambda e: self.sendToHeaderScanner(invocation))
            menu_items.append(item)
        else:
            print("[DEBUG] Not in Repeater context. Current context: {}".format(context))

        return menu_items

    def sendToHeaderScanner(self, invocation):
        request = invocation.getSelectedMessages()[0].getRequest()
        url = self._helpers.analyzeRequest(request).getUrl()

        self.url_field.setText(url.toString())
        self.text_area.append("[*] URL from Repeater: {}\n".format(url.toString()))
