using CSharp.NET.JwtAuth.JwtWithIdentity.Models;
using CSharp.NET.JwtAuth.JwtWithIdentity.Service;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace CSharp.NET.JwtAuth.JwtWithIdentity.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly ITokenService _tokenService;
        public AuthController(ITokenService tokenService)
        {
            _tokenService = tokenService;
        }

        [HttpPost]
        [Route("login")]
        public ActionResult<dynamic> Login([FromBody] AppUser userModel)
        {
            var jwtToken = _tokenService.GetToken(userModel);

            return Ok();
        }
    }
}
