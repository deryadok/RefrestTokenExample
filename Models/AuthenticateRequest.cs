using System.ComponentModel.DataAnnotations;

namespace RefreshTokenExample.Models
{
    public class AuthenticateRequest
    {
        [Required]
        public string Username { get; set; }
        
        [Required]
        public string Password { get; set; }
    }
}
