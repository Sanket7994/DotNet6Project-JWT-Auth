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

namespace DemoProjectWithJWTAuth.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly AppDB _dbContext;
        private readonly IConfiguration _configuration;

        public AuthController(AppDB dbContext, IConfiguration configuration)
        {
            _dbContext = dbContext;
            _configuration = configuration;
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

        // Generate JWT Token with claims
        private string GenerateToken(Users user)
        {
            List<Claim> claims = new List<Claim> 
            {
                new Claim(ClaimTypes.Name, user.Username)
            };

            // Get the JWT server secret from configuration
            var securitykey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JWT:ServerSecret"]));
            var credentials = new SigningCredentials(securitykey, SecurityAlgorithms.HmacSha512);
            var token = new JwtSecurityToken(
                _configuration["JWT:Issuer"],
                _configuration["JWT:Audience"],
                claims,
                expires: DateTime.Now.AddMinutes(5),
                signingCredentials: credentials
                );
            return new JwtSecurityTokenHandler().WriteToken(token);
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
                var token = GenerateToken(user);
                return Ok(new { token });
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
    }
}
