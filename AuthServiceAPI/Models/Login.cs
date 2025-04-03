using System.Text.Json.Serialization;

namespace AuthServiceAPI.Models
{
    public class Login
    {
        [JsonPropertyName("username")]
        public string? Username { get; set; }

        [JsonPropertyName("password")]
        public string? Password { get; set; }
    }
}
