using JWTWebApi.Models;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;

namespace JWTWebApi.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    // add [Authorize] in here to authorization
    public class AuthController : ControllerBase
    {
        private static User user = new();

        private readonly IConfiguration _configuration;

        private readonly IUserService _userService;

        public AuthController(IConfiguration configuration, IUserService userService)
        {
            _configuration = configuration;
            _userService = userService;

        }

        //this is not best practice
        //[HttpGet, Authorize]
        //public ActionResult<object> GetMe()
        //{
        //    string username = User?.Identity?.Name;
        //    var username2 = User.FindFirstValue(ClaimTypes.Name);
        //    var role = User.FindFirstValue(ClaimTypes.Role);
        //    return Ok(new {username, username2, role});
        //}

        [HttpGet, Authorize]
        public ActionResult<object> GetMe()
        {
            var result = _userService.GetMyName();
            return Ok(result);
        }




        [HttpPost("register")]
        public async Task<ActionResult<User>> Register(UserDTO req)
        {
            CreatePasswordHash(req.Password, out byte[] passwordHash, out byte[] passwordSalt);

            user.PasswordSalt = passwordSalt;
            user.PasswordHash = passwordHash;
            user.UserName = req.Username;

            return Ok(user);
        }

        [HttpPost("login")]
        public async Task<ActionResult<string>> Login(UserDTO req)
        {
            if (user.UserName != req.Username) return BadRequest("Username or Password wrong");

            if (!VerifyPasswordHash(req.Password, user.PasswordHash, user.PasswordSalt)) return BadRequest("Username or password wrong");

            string token = CreateToken(user);
            return Ok(token);
        }

        private void CreatePasswordHash(string password, out byte[] passwordHash, out byte[] passwordSalt)
        {
            using var hmac = new HMACSHA512();
            /* 
            The using statement ensures that Dispose() is called even if an exception occurs when you are creating objects and calling methods, properties and so on. Dispose() is a method that is present in the IDisposable interface that helps to implement custom Garbage Collection. instead of using try-catch-finally(dispose())
             */
            passwordSalt = hmac.Key;
            passwordHash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));
        }

        private bool VerifyPasswordHash(string password, byte[] passwordHash, byte[] passwordSalt)
        {
            using var hmac = new HMACSHA512(passwordSalt);
            var computedHash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));
            return computedHash.SequenceEqual(passwordHash);
        }

        private string CreateToken(User user)
        {
            List<Claim> claims = new()
            {
                new Claim(ClaimTypes.Name, user.UserName),
                new Claim(ClaimTypes.Role, "Admin"),
            };

            var key = new SymmetricSecurityKey(System.Text.Encoding.UTF8.GetBytes(
                _configuration.GetSection("AppSettings:Token").Value));

            var cred = new SigningCredentials(key, SecurityAlgorithms.HmacSha512Signature);

            var token = new JwtSecurityToken(
                claims: claims,
                expires: DateTime.Now.AddDays(1),
                signingCredentials: cred
                );

            var jwt = new JwtSecurityTokenHandler().WriteToken(token);

            return jwt;
        }
    }
}
