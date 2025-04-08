using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using System.Net.Http;
using System.Net.Http.Json;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.IdentityModel.Tokens;
using AuthServiceAPI.Models;
using Microsoft.AspNetCore.Authorization;

namespace AuthServiceAPI.Controllers
{
    [ApiController]
    [Route("api/auth")]
    public class LoginController : ControllerBase
    {
        private readonly IHttpClientFactory _clientFactory;
        private readonly IConfiguration _config;
        private readonly ILogger<LoginController> _logger;

        public LoginController(IHttpClientFactory clientFactory, IConfiguration config, ILogger<LoginController> logger)
        {
            _clientFactory = clientFactory;
            _config = config;
            _logger = logger;
        }

        
        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] Login login)
        {
            if (login == null || string.IsNullOrWhiteSpace(login.Username) || string.IsNullOrWhiteSpace(login.Password))
            {
                return BadRequest("Invalid login request.");
            }

            _logger.LogInformation("Login attempt for user: {Username}", login.Username);

            var client = _clientFactory.CreateClient();
            var userServiceUrl = _config["UserServiceUrl"];

            if (string.IsNullOrWhiteSpace(userServiceUrl))
            {
                _logger.LogError("UserServiceUrl is not configured correctly.");
                return StatusCode(500, "Internal configuration error.");
            }

            try
            {
                var validateUrl = $"{userServiceUrl}/users/validate";
                _logger.LogInformation("Sending login request to: {Url}", validateUrl);

                var response = await client.PostAsJsonAsync(validateUrl, login);
                _logger.LogInformation("Response from UserService: {StatusCode}", response.StatusCode);

                if (!response.IsSuccessStatusCode)
                {
                    var body = await response.Content.ReadAsStringAsync();
                    _logger.LogWarning("Login failed. Body: {Body}", body);
                    return Unauthorized("Invalid credentials");
                }

                var user = await response.Content.ReadFromJsonAsync<ValidatedUserResponse>();
                if (user == null)
                {
                    _logger.LogError("Deserialization failed: user is null.");
                    return StatusCode(500, "Could not parse user info from UserService.");
                }

                var token = GenerateJwtToken(user.Username);
                _logger.LogInformation("JWT token generated for user: {Username}", user.Username);

                return Ok(new { token });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Exception during login request.");
                return StatusCode(500, "An error occurred during login.");
            }
        }

        [Authorize]
        [HttpGet("validate")]
        public IActionResult ValidateToken()
        {
        var username = User.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value;

        if (string.IsNullOrEmpty(username))
            return Unauthorized("Token is missing or invalid.");

        return Ok($"Token is valid. Logged in as: {username}");
        }

      
        

        private string GenerateJwtToken(string username)
        {
            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config["Secret"]));
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

            var claims = new[]
            {
                new Claim(ClaimTypes.NameIdentifier, username)
            };

            var token = new JwtSecurityToken(
                _config["Issuer"],
                "http://localhost/",
                claims,
                expires: DateTime.Now.AddMinutes(15),
                signingCredentials: credentials);

            return new JwtSecurityTokenHandler().WriteToken(token);
        }
    }
}
