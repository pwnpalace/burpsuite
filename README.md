# -= WTHeader =-
Burpsuite extension

This is a super simple extension that captures HTTP traffic that contains unusual or non-standard headers, then gives you the option to send it to repeater. This works seperately from "Intercept", so intercept does NOT need to be enabled for this extension to work. You can choose between capturing all traffic or just in-scope traffic. To reset this setting, simply unload then reload the extension

CHANGELOG

5/20/2025
- Added the ability to ignore captured headers in future HTTP requests
