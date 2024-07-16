namespace CSharp.NET.JwtAuth.JwtWithIdentity.Models
{
    public class AppUser
    {
        public string? UserName { get; set; }
        public string? Password { get; set; }
        public string? Email { get; set; }
        public string? Roles { get; set; }
    }
}
