using CSharp.NET.JwtAuth.JwtWithIdentity.Models;

namespace CSharp.NET.JwtAuth.JwtWithIdentity.Service
{
    public interface ITokenService
    {
        string GetToken(AppUser user);
    }
}
