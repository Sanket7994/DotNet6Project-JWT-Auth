using DemoProjectWithJWTAuth.Models;
using MailKit.Net.Smtp;
using MailKit.Security;
using Microsoft.AspNetCore.Mvc;
using MimeKit;
using MimeKit.Text;

namespace DemoProjectWithJWTAuth.Services.EmailServices
{
    public class EmailService : IEmailService
    {
        private readonly IConfiguration _configuration;
        public EmailService(IConfiguration configuration)
        {
            _configuration = configuration;
        }

        public void SendEmail(string userEmail, string subject, string body)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(userEmail) || !IsValidEmail(userEmail))
                {
                    throw new ArgumentException("Invalid email address");
                }

                var email = new MimeMessage();
                email.From.Add(MailboxAddress.Parse(_configuration.GetSection("EmailService:EmailUsername").Value));
                email.To.Add(MailboxAddress.Parse(userEmail));
                email.Subject = subject;
                email.Body = new TextPart(TextFormat.Text) { Text = body };

                using var smtp = new SmtpClient();
                smtp.Connect(
                    _configuration.GetSection("EmailService:EmailHost").Value, 587, SecureSocketOptions.StartTls
                );
                smtp.Authenticate(
                    _configuration.GetSection("EmailService:EmailUsername").Value,
                    _configuration.GetSection("EmailService:EmailPassword").Value
                );
                smtp.Send(email);
                smtp.Disconnect(true);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error sending email: {ex.Message}");
                throw; 
            }
        }

        private bool IsValidEmail(string email)
        {
            try
            {
                var addr = new System.Net.Mail.MailAddress(email);
                return addr.Address == email;
            }
            catch
            {
                return false;
            }
        }
    }
}
