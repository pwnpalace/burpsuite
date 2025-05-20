from burp import IBurpExtender, IHttpListener, IBurpExtenderCallbacks
from javax.swing import JOptionPane

STANDARD_HEADERS = [
    "host", "user-agent", "accept", "accept-encoding", "accept-language",
    "content-type", "content-length", "cookie", "connection", "upgrade-insecure-requests",
    "cache-control", "pragma", "referer", "origin", "authorization"
]

class BurpExtender(IBurpExtender, IHttpListener):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("-= WTHeader v1.0 =-")
        callbacks.registerHttpListener(self)
        # Prompt user for scope preference
        options = ["All traffic", "In-scope traffic only"]
        choice = JOptionPane.showOptionDialog(
            None,
            "Should WTHeader inspect all traffic or just in-scope traffic?",
            "-= WTHeader v1.0 =-",
            JOptionPane.DEFAULT_OPTION,
            JOptionPane.QUESTION_MESSAGE,
            None,
            options,
            options[0]
        )
        self.inspect_in_scope_only = (choice == 1)

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        # Only inspect Proxy traffic
        if toolFlag != IBurpExtenderCallbacks.TOOL_PROXY or not messageIsRequest:
            return

        # If in-scope only, check if URL is in scope
        if self.inspect_in_scope_only:
            url = self._helpers.analyzeRequest(messageInfo).getUrl()
            if not self._callbacks.isInScope(url):
                return

        request = messageInfo.getRequest()
        analyzed = self._helpers.analyzeRequest(request)
        headers = analyzed.getHeaders()
        unusual_headers = []

        for header in headers:
            if ":" in header:
                name = header.split(":", 1)[0].strip().lower()
                if name not in STANDARD_HEADERS:
                    unusual_headers.append(header)

        if unusual_headers:
            msg = "Unusual headers detected:\n{}\n\nSend this request to Repeater?".format(
                "\n".join(unusual_headers)
            )
            user_choice = JOptionPane.showConfirmDialog(
                None, msg, "-= WTHeader v1.0 =-", JOptionPane.YES_NO_OPTION
            )
            if user_choice == JOptionPane.YES_OPTION:
                self._callbacks.sendToRepeater(
                    messageInfo.getHttpService().getHost(),
                    messageInfo.getHttpService().getPort(),
                    messageInfo.getHttpService().getProtocol() == "https",
                    request,
                    None
                )
