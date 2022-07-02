# unsafe-mode
 
 This repo is for a C# project centered around restarting a Windows machine to safe mode in order to bypass defences. This technique is detailed as [T1562.009](https://attack.mitre.org/techniques/T1562/009/) by Mitre Att&ck.  
 Specifically, the TTPs covered in this project is intended to emulate pre-encryption steps taken by the AvosLocker Ransomware group. However, this method is also used by REvil, and BlackMatter.   
 A simple echo command is used in the RunOnce registry key for a proof of concept, but that is typically where the encryption process starts for AvosLocker.  
    
 ---
 - https://news.sophos.com/en-us/2021/12/22/avos-locker-remotely-accesses-boxes-even-running-in-safe-mode/
 - https://www.trendmicro.com/vinfo/us/security/news/ransomware-spotlight/ransomware-spotlight-avoslocker
- https://www.bleepingcomputer.com/news/security/avoslocker-ransomware-reboots-in-safe-mode-to-bypass-security-tools/
- https://blog.malwarebytes.com/threat-intelligence/2021/07/avoslocker-enters-the-ransomware-scene-asks-for-partners/