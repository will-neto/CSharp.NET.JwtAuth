using CSharp.NET.JwtAuth.BasicAuth.Models;
using CSharp.NET.JwtAuth.BasicAuth.Repositorio;
using CSharp.NET.JwtAuth.BasicAuth.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace CSharp.NET.JwtAuth.BasicAuth.Controllers
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
        [Route("/login")]
        public ActionResult<dynamic> Login([FromBody] User model)
        {
            var user = UserRepository.FindUser(model.Username, model.Password);

            if (user == null)
            {
                return NotFound(new { message = "Usuário ou senha inválidos" });
            }

            var jwtToken = _tokenService.GenerateToken(user);
            var jwtTokenInvalido = _tokenService.GenerateTokenInvalido(user);


            return Ok(new
            {
                user = user,
                token = jwtToken,
                token_invalido = jwtTokenInvalido
            });
        }


        [HttpGet]
        [Route("acesso-anoNimo")]
        [AllowAnonymous]
        public ActionResult AcessoAnonimo()
        {
            return Ok("Acesso Anonimo");
        }


        [HttpGet]
        [Route("cozinhar")]
        [Authorize(Roles = "geral,cozinhar")]
        public ActionResult Cozinhar()
        {
            return Ok("Cozinhando um Hambúrguer de Siri!!");
        }


        [HttpGet]
        [Route("pagar-salario")]
        [Authorize(Roles = "geral")]
        public ActionResult Pagar()
        {
            return Ok("Pagar o salário dos funcionários do Krusty Krab");
        }

    }
}
