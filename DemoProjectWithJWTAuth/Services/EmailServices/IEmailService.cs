using DemoProjectWithJWTAuth.Models;

namespace DemoProjectWithJWTAuth.Services.EmailServices
{
    public interface IEmailService
    {
        void SendEmail(string userEmail, string subject, string body);
    }
}
