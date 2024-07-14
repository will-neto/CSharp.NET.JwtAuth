using CSharp.NET.JwtAuth.BasicAuth.Models;

namespace CSharp.NET.JwtAuth.BasicAuth.Repositorio
{
    public static class UserRepository
    {
        private static List<User> _users = new List<User>() { 
            new User() { Id = 1, Username = "sirigueijo", Password = "seusiri", Role = "geral" },
            new User() { Id = 2, Username = "bobesponja", Password = "123", Role = "cozinhar" }
        };

        public static User FindUser(string username, string password)
        {
            var user = _users.FirstOrDefault(p => p.Username.ToLower().Equals(username) && p.Password.ToLower().Equals(password));

            return user;
        }
    }
}
