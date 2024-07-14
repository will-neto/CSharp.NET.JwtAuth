using CSharp.NET.JwtAuth.BasicAuth.Models;

namespace CSharp.NET.JwtAuth.BasicAuth.Services
{
    public interface ITokenService
    {
        string GenerateToken(User user);
        string GenerateTokenInvalido(User user);

    }
}
