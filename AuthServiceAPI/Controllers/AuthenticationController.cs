using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using System.Net.Http;
using System.Threading.Tasks;

namespace authServiceAPI.Controllers
{
    [ApiController]
    [Route("api/auth")]
    public class AuthController : ControllerBase
    {
        private readonly HttpClient _httpClient;
        private readonly IConfiguration _config;
        private readonly ILogger<AuthController> _logger;

        public AuthController(ILogger<AuthController> logger, IConfiguration config, HttpClient httpClient)
        {
            _config = config;
            _logger = logger;
            _httpClient = httpClient;
        }

        // Her kan du tilføje dit login-endpoint senere
    }

    [ApiController]
    [Route("api/test")] // <- Du manglede denne attribut
    public class TestController : ControllerBase
    {
        [Authorize]
        [HttpGet]
        public async Task<IActionResult> Get()
        {
            return Ok("You're authorized");
        }
    }
}
