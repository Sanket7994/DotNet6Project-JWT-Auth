using DemoProjectWithJWTAuth.Context;
using DemoProjectWithJWTAuth.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.Security.Claims;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Cryptography;
using System.Text;
using Microsoft.EntityFrameworkCore;
using DemoProjectWithJWTAuth.Services.EmailServices;
using System.Collections.Concurrent;



namespace DemoProjectWithJWTAuth.Controllers
{
    [Route("[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly AppDB _dbContext;
        private readonly IConfiguration _configuration;
        private readonly IEmailService _emailService;

        public AuthController(AppDB dbContext, IConfiguration configuration, IEmailService emailService)
        {
            _dbContext = dbContext;
            _configuration = configuration;
            _emailService = emailService;
        }

        //Registeration
        [AllowAnonymous]
        [HttpPost("register")]
        public async Task<ActionResult<Users>> Register(UserRegistration request)
        {
            // Generate a random salt
            byte[] passwordSalt = GenerateSalt();

            // Create password hash using the generated salt
            CreatePasswordHash(request.Password, passwordSalt, out byte[] passwordHash);

            Users newUser = new Users
            {
                Username = request.Username,
                Email = request.Email,
                PasswordHash = passwordHash,
                PasswordSalt = passwordSalt
            };

            // Add the user to the database
            _dbContext.Users.Add(newUser);
            await _dbContext.SaveChangesAsync();

            // Return a response indicating success
            return Ok(newUser);
        }

        //Login
        [AllowAnonymous]
        [HttpPost("login")]
        public async Task<IActionResult> Login(UserLogin request)
        {
            try
            {
                // Retrieve the user from the database based on the provided username
                var user = await _dbContext.Users.FirstOrDefaultAsync(u => u.Username == request.Username);
                // Check users existence in db
                if (user == null)
                {
                    return Unauthorized(new { message = "Invalid username or password." });
                }
                // Verify the password using the user's salt
                if (!VerifyPasswordHash(request.Password, user.PasswordHash, user.PasswordSalt))
                {
                    return Unauthorized(new { message = "Invalid username or password." });
                }
                // Creating claims
                List<Claim> claims = new List<Claim>
                {
                    new Claim(ClaimTypes.Name, user.Username)
                };
                // Creating token
                var token = GenerateToken(user, claims);
                return Ok(new { token });
            }
            catch (Exception ex)
            {
                // Log the exception for debugging purposes
                return StatusCode(500, new { message = ex });
            }
        }

        //fetch_users_list
        [Authorize]
        [HttpGet("user/list")]
        public async Task<ActionResult<IEnumerable<Users>>> GetUsers()
        {
            if (_dbContext.Users == null)
            {
                return NotFound();
            }
            return await _dbContext.Users.ToListAsync();
        }

        // Fetch active user profile info by ID
        [Authorize]
        [HttpGet("user/{id}")]
        public async Task<ActionResult<Users>> GetUserProfile(int id)
        {
            // Check if the database context is null (this is unlikely to happen in practice)
            if (_dbContext == null)
            {
                return StatusCode(StatusCodes.Status500InternalServerError, "Database context is not available.");
            }
            // Attempt to find the user by ID
            var user = await _dbContext.Users.FindAsync(id);
            // Check if the user was not found
            if (user == null)
            {
                return NotFound("User not found.");
            }
            return Ok(user); 
        }

        // Forget Password
        private static readonly ConcurrentDictionary<string, string> 
            OtpPayloads = new ConcurrentDictionary<string, string>();
        [AllowAnonymous]
        [HttpPost("forgot-password")]
        public async Task<IActionResult> ForgotPassword(ForgotPassword request)
        {
            try
            {
                // Retrieve the user from the database based on the provided username
                var user = await _dbContext.Users.FirstOrDefaultAsync(u => u.Email == request.Email);
                // Check user existence in db
                if (user == null)
                {
                    return Unauthorized(new { message = "Provided Email doesn't exist in records" });
                }
                // Generate a random 6-digit number
                Random random = new Random();
                int otp = random.Next(100000, 999999);
                var userId = user.Id;
                var token = $"{userId}-{otp}";

                // Store the OTP and user id in the dictionary
                OtpPayloads.TryAdd(userId.ToString(), otp.ToString());

                // Send the email with the token to the user
                var subject = "Account Password Reset Notification";
                var body = $"Hi, Your verification code is: {token}";
                var userEmail = user.Email;
                if (userEmail != null)
                {
                    //Send the email
                    _emailService.SendEmail(userEmail, subject, body);
                }
                return Ok($"OTP verification email has been sent successfully");
            }
            catch (Exception ex)
            {
                // Log the exception for debugging purposes
                return StatusCode(500, new { message = ex });
            }
        }

        // Reset Password 
        [AllowAnonymous]
        [HttpPost("reset-password")]
        public IActionResult ResetPasswordwithOTP(ResetPassword request)
        {
            try
            {
                // Sanity check
                if (request.Otp == null || request.NewPassword == null)
                {
                    return BadRequest(new { message = "Invalid OTP or password entered" });
                }
                // Check if the new password and confirm password match
                if (request.NewPassword != request.ConfirmPassword)
                {
                    return BadRequest(new { message = "New password and confirm password do not match" });
                }

                // Extracting userId and OTP from the request
                string[] extracts = request.Otp.Split('-');
                if (extracts.Length == 2)
                {
                    if (int.TryParse(extracts[0], out int parsedUserId))
                    {
                        int extractedUserId = parsedUserId;
                        string extractedOtp = extracts[1];

                        // Retrieve the stored OTP for the user
                        if (OtpPayloads.TryGetValue(extractedUserId.ToString(), out string storedOtp))
                        {
                            if (storedOtp == extractedOtp)
                            {
                                // Retrieve the user from the database by user ID
                                var user = _dbContext.Users.FirstOrDefault(u => u.Id == extractedUserId);
                                if (user == null)
                                {
                                    return BadRequest(new { message = "User not found" });
                                }

                                // Generate a random salt
                                byte[] passwordSalt = GenerateSalt();

                                // Create password hash using the generated salt
                                CreatePasswordHash(request.NewPassword, passwordSalt, out byte[] passwordHash);

                                // Update the user's password salt and password hash in the database
                                user.PasswordSalt = passwordSalt;
                                user.PasswordHash = passwordHash;

                                // Save the changes to the database
                                _dbContext.SaveChanges();

                                // Sending Notification email for password reset
                                var subject = "Successful Account Password Reset Notification";
                                var body = "Hi, Your password has been successfully changed, Login On!";
                                var userEmail = user.Email;
                                if (!string.IsNullOrWhiteSpace(userEmail))
                                {
                                    _emailService.SendEmail(userEmail, subject, body);
                                }

                                return Ok(new { message = "Password reset successful" });
                            }
                            else
                            {
                                return BadRequest(new { message = "Invalid OTP" });
                            }
                        }
                        else
                        {
                            return BadRequest(new { message = "OTP not found" });
                        }
                    }
                    else
                    {
                        return BadRequest(new { message = "Invalid OTP format" });
                    }
                }
                else
                {
                    return BadRequest(new { message = "Invalid OTP format" });
                }
            }
            catch (Exception ex)
            {
                // Log the exception for debugging purposes
                return StatusCode(500, new { message = ex });
            }
        }


        // Password hashing is the process of taking a user's password and converting it into a
        private void CreatePasswordHash(string password, byte[] salt, out byte[] passwordHash)
        {
            using (var hmac = new HMACSHA512(salt))
            {
                passwordHash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));
            }
        }

        // A salt is a random value that is generated for each user when they create an account or change their password.
        // This salt is then combined with the user's password before hashing.
        // The purpose of the salt is to add randomness and uniqueness to the hashing process.
        // It ensures that even if two users have the same password, their hashes will be different due to the unique salt.
        private bool VerifyPasswordHash(string password, byte[] storedHash, byte[] salt)
        {
            using (var hmac = new HMACSHA512(salt))
            {
                var computedHash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));
                return computedHash.SequenceEqual(storedHash);
            }
        }

        //Generating random salts
        private byte[] GenerateSalt()
        {
            byte[] salt = new byte[16];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(salt);
            }
            return salt;
        }

        // Generate JWT Token with claims
        private string GenerateToken(Users user, List<Claim> claims)
        {
            // Get the JWT server secret from configuration
            var securitykey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JWT:ServerSecret"]));
            var credentials = new SigningCredentials(securitykey, SecurityAlgorithms.HmacSha512);
            var token = new JwtSecurityToken(
                _configuration["JWT:Issuer"],
                _configuration["JWT:Audience"],
                claims: claims,
                expires: DateTime.Now.AddMinutes(5),
                signingCredentials: credentials
                );
            return new JwtSecurityTokenHandler().WriteToken(token);
        }
    }
}
