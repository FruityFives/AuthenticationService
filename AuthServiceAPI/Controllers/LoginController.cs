using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using System.Net.Http;
using System.Net.Http.Json;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.IdentityModel.Tokens;
using AuthServiceAPI.Models;

namespace AuthServiceAPI.Controllers
{
    [ApiController]
    [Route("api/auth")]
    public class LoginController : ControllerBase
    {
        private readonly IHttpClientFactory _clientFactory;
        private readonly IConfiguration _config;

        public LoginController(IHttpClientFactory clientFactory, IConfiguration config)
        {
            _clientFactory = clientFactory;
            _config = config;
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] Login login)
        {
            var client = _clientFactory.CreateClient(); // ✅ Her instantierer du en klient korrekt

            var userServiceUrl = _config["UserServiceUrl"];
            var response = await client.PostAsJsonAsync($"{userServiceUrl}/users/validate", login);

            if (!response.IsSuccessStatusCode)
                return Unauthorized("Invalid credentials");

            var user = await response.Content.ReadFromJsonAsync<ValidatedUserResponse>();
            var token = GenerateJwtToken(user.Username);

            return Ok(new { token });
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
