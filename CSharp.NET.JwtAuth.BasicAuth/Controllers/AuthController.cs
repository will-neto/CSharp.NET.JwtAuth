using CSharp.NET.JwtAuth.BasicAuth.Models;
using CSharp.NET.JwtAuth.BasicAuth.Repositorio;
using CSharp.NET.JwtAuth.BasicAuth.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

namespace CSharp.NET.JwtAuth.BasicAuth.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly ITokenService _tokenService;
        private readonly IHttpContextAccessor _httpContextAccessor;

        public AuthController(ITokenService tokenService, IHttpContextAccessor httpContextAccessor)
        {
            _tokenService = tokenService;
            _httpContextAccessor = httpContextAccessor;
        }


        [HttpPost]
        [Route("login")]
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
            // As informações do usuário conectado estão vinculados a classe ClaimsPrincipal
            // A propriedade "User" do objeto de HttpContextAccessor permite a recuperação de dados relacionados ao usuário (que estão em claims)
            // A classe ControllerBase também possui um atalho a Propriedade "User"

            // Acesso ao usuário via Contexto
            var userHttpContextAccessor = _httpContextAccessor.HttpContext?.User;
            var userBaseController = User;

            var userClaimsHttpContextAccessor = _httpContextAccessor.HttpContext?.User?.Claims;
            var userClaimsBaseController = User.Claims;


            return Ok(@$"
                Cozinhando um Hambúrguer de Siri!!
                Nome do usuário via User - HttpContextAccessor: {userBaseController.FindFirst(ClaimTypes.Name)?.Value}
                Nome do usuário via User - BaseController) {userHttpContextAccessor?.FindFirst(ClaimTypes.Name)?.Value}
                Usuario: {userBaseController.ToString()}
                Comparando HashCode dos dois Objetos => {userBaseController.GetHashCode() == userHttpContextAccessor?.GetHashCode()}
            ");
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
