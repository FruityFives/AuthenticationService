namespace AuthServiceAPI.Models
{
    
        public class ValidatedUserResponse
        {
            public Guid Id { get; set; }
            public string Username { get; set; }
            public string EmailAddress { get; set; }
            public string Role { get; set; }
        }

    
}
