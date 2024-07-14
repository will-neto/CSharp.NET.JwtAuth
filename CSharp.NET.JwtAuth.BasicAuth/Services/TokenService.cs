
using CSharp.NET.JwtAuth.BasicAuth.Models;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace CSharp.NET.JwtAuth.BasicAuth.Services
{
    public class TokenService : ITokenService
    {
        private readonly IConfiguration _configuration;

        public TokenService(IConfiguration configuration)
        {
            _configuration = configuration;
        }

        public string GenerateToken(User user)
        {
            var appSecretKey = _configuration.GetSection("JwtSettings")["SecretKey"];

            if (string.IsNullOrEmpty(appSecretKey)) throw new ArgumentNullException(nameof(appSecretKey));


            var jwtSymetricKey= new SymmetricSecurityKey(
                         Encoding.UTF8.GetBytes(appSecretKey)        /*  Usar UTF8 se sua chave possuir acentos
                        Encoding.ASCII.GetBytes(appSecretKey)           Caso nao possua, utilizar ASCII         */
                         );
            /*
                JwtSecurityTokenHandler
                
                Classe responsavel para manipulacao de JWT Tokens
                Cria, valida e faz a leitura dos dados contidos em tokens
             */
            var jwtTokenHandler = new JwtSecurityTokenHandler();

            /*
                SecurityTokenDescriptor

                Classe responsavel pela definição de propriedades e claims que tokens de segurança trabalham
                Trabalha com Tokens como JWT, OAuth2 e SAML, etc.
                
             */
            var tokenDescriptor = new SecurityTokenDescriptor();

            /*
                Expires 
                É a Registered Claim que indica qual a Data e horário de expiração do Token.
                Ou seja, até quando ele é válido
             */
            tokenDescriptor.Expires = DateTime.UtcNow.AddHours(10);

            /*
                SigningCredentials
                Classe responsavel pela definição de como o token de credencial deve ser gerado.
                Espera receber 
                    - A chave usada para assinar o token, podendo ser uma chave-simétrica ou chave-assimétrica
                    - O algoritmo de assinatura (algoritmo de criptografia) que sera usado
                Trabalha com Tokens como JWT, SAML, etc.

                SymmetricSecurityKey
                Implementação da classe SecurityKey para uso de chave-simétrica
                Espera receber a chave que será usada
                
             */

            tokenDescriptor.SigningCredentials = new SigningCredentials(jwtSymetricKey, SecurityAlgorithms.HmacSha256);

            /*
                Claim
                Classe responsável por representar uma afirmação sobre o sujeito (usuário, entidade, etc). Cada Claim é uma declaração
                sobre a identidade do usuário.

                O conceito de claims é amplamente utilizado em sistemas de autenticação e autorização em várias tecnologias, não se limitando ao .NET

                São fundamentais para a autenticação de usuários e controle de acesso.

                
                ClaimTypes
                Classe estática que contém um conjunto de constantes para os tipos de claims mais comuns. Possuem como valor um padrão estabelecido
                por padrões de identidade da indústria. Esse URL refere-se a um namespace que foi estabelecido para claims em protocolos de autenticação
                e identidade.


                ClaimsIdentity - Subject
                É a classe que representa a identidade de um usuário/entidade que contém uma coleção de claims associadas a essa identidade.
                Nela inserimos as Claims registradas (padrões no JWT) e qualquer outra claim (que não passa de um conjunto chave-valor) que quisermos
                e que será incluido no Payload do JWT.
             
             */

            var subjectClaims = new List<Claim>()
            {
                new Claim(ClaimTypes.Name, user.Username),
                new Claim(ClaimTypes.Role, user.Role),
                new Claim("SejaQualForAClaimEstaraNoPayloadSeIncluidaAqui", "123")
            };

            tokenDescriptor.Subject = new ClaimsIdentity(subjectClaims);
            tokenDescriptor.Audience = "Publico_Geral";
            tokenDescriptor.Issuer = "CSharp.NET.JwtAuth";

            // Cria o objeto Token JWT
            var token = jwtTokenHandler.CreateToken(tokenDescriptor);


            // Converte em um Token em formato Json
            return jwtTokenHandler.WriteToken(token);
        }

        public string GenerateTokenInvalido(User user)
        {
            var appSecretKey = "secret_key_para_demonstrar_ValidateIssuerSigningKey_false";

            var jwtSymetricKey = new SymmetricSecurityKey(
                         Encoding.UTF8.GetBytes(appSecretKey)        /*  Usar UTF8 se sua chave possuir acentos
                        Encoding.ASCII.GetBytes(appSecretKey)           Caso nao possua, utilizar ASCII         */
                         );
            /*
                JwtSecurityTokenHandler
                
                Classe responsavel para manipulacao de JWT Tokens
                Cria, valida e faz a leitura dos dados contidos em tokens
             */
            var jwtTokenHandler = new JwtSecurityTokenHandler();

            /*
                SecurityTokenDescriptor

                Classe responsavel pela definição de propriedades e claims que tokens de segurança trabalham
                Trabalha com Tokens como JWT, OAuth2 e SAML, etc.
                
             */
            var tokenDescriptor = new SecurityTokenDescriptor();

            /*
                Expires 
                É a Registered Claim que indica qual a Data e horário de expiração do Token.
                Ou seja, até quando ele é válido
             */
            tokenDescriptor.Expires = DateTime.UtcNow.AddHours(10);

            /*
                SigningCredentials
                Classe responsavel pela definição de como o token de credencial deve ser gerado.
                Espera receber 
                    - A chave usada para assinar o token, podendo ser uma chave-simétrica ou chave-assimétrica
                    - O algoritmo de assinatura (algoritmo de criptografia) que sera usado
                Trabalha com Tokens como JWT, SAML, etc.

                SymmetricSecurityKey
                Implementação da classe SecurityKey para uso de chave-simétrica
                Espera receber a chave que será usada
                
             */

            tokenDescriptor.SigningCredentials = new SigningCredentials(jwtSymetricKey, SecurityAlgorithms.HmacSha256);

            /*
                Claim
                Classe responsável por representar uma afirmação sobre o sujeito (usuário, entidade, etc). Cada Claim é uma declaração
                sobre a identidade do usuário.

                O conceito de claims é amplamente utilizado em sistemas de autenticação e autorização em várias tecnologias, não se limitando ao .NET

                São fundamentais para a autenticação de usuários e controle de acesso.

                
                ClaimTypes
                Classe estática que contém um conjunto de constantes para os tipos de claims mais comuns. Possuem como valor um padrão estabelecido
                por padrões de identidade da indústria. Esse URL refere-se a um namespace que foi estabelecido para claims em protocolos de autenticação
                e identidade.


                ClaimsIdentity - Subject
                É a classe que representa a identidade de um usuário/entidade que contém uma coleção de claims associadas a essa identidade.
                Nela inserimos as Claims registradas (padrões no JWT) e qualquer outra claim (que não passa de um conjunto chave-valor) que quisermos
                e que será incluido no Payload do JWT.
             
             */

            var subjectClaims = new List<Claim>()
            {
                new Claim(ClaimTypes.Name, user.Username),
                new Claim(ClaimTypes.Role, user.Role),
                new Claim("SejaQualForAClaimEstaraNoPayloadSeIncluidaAqui", "123"),
            };

            tokenDescriptor.Subject = new ClaimsIdentity(subjectClaims);
            tokenDescriptor.Audience = "Publico_Geral";
            tokenDescriptor.Issuer = "CSharp.NET.JwtAuth";

            // Cria o objeto Token JWT
            var token = jwtTokenHandler.CreateToken(tokenDescriptor);


            // Converte em um Token em formato Json
            return jwtTokenHandler.WriteToken(token);
        }

    }
}
