using System.ComponentModel.DataAnnotations;

namespace DemoProjectWithJWTAuth.Models
{
    public class ForgotPassword
    {
        [Required(ErrorMessage = "Provide Email to find your profile!")]
        public string? Email { get; set; }
    }
}
