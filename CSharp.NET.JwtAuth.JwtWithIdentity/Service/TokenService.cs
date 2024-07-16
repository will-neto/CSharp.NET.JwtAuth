using CSharp.NET.JwtAuth.JwtWithIdentity.Models;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace CSharp.NET.JwtAuth.JwtWithIdentity.Service
{
    public class TokenService : ITokenService
    {
        private readonly IConfiguration _configuration;
        public TokenService(IConfiguration configuration)
        {
            _configuration = configuration;
        }

        public string GetToken(AppUser user)
        {
            var tokenSecretKey = _configuration.GetSection("JwtToken")["Secret"];

            if (tokenSecretKey == null)
            {
                throw new ArgumentException("A secret key do token JWT não foi configurada...");
            }
 
            var jwtSecreKeyBytes = Encoding.UTF8.GetBytes(tokenSecretKey);
            
            var jwtHandler = new JwtSecurityTokenHandler();

            var roles = user.Roles
                .Split(",")
                .ToList()
                .Select(x => new Claim(ClaimTypes.Role, x.Trim()));

            var tokenDescriptor = new SecurityTokenDescriptor()
            {
                Expires = DateTime.UtcNow.AddDays(7),
                Audience = "Publico_Geral",
                Issuer = "CSharp.NET.JwtAuth",
                Subject = new ClaimsIdentity(new List<Claim>(roles)
                {
                    new Claim(ClaimTypes.Name, user.UserName)
                }),
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(jwtSecreKeyBytes), SecurityAlgorithms.HmacSha256)
            };

            var securityToken = jwtHandler.CreateToken(tokenDescriptor);

            return jwtHandler.WriteToken(securityToken);
        }
    }
}
