# NSP-Client
A protocol that allows running OS commands on the web. <br>
NSP currently supports Windows, macOS and Linux. <br>
# How to use 
1. Run the NSP client
2. Open the website that requests a NSP action
3. Press the 'Allow' button on the message box that appears
# For developers
To use NSP in your website, send `X-NSP: true` and ``X-NSP-cmd: <command>`` to http://localhost:65535 <Br>
You will get a request back with the stdout, if it was a admin command, it will be restricted from running. <br>
