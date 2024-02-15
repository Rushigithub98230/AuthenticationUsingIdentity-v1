using AuthenticationUsingIdentity.Data.Models;
using Microsoft.AspNetCore.Identity;

namespace AuthenticationUsingIdentity.Service.Models.Authentication.User
{
    public class CreateUserResponse
    {
        public string Token { get; set; }

        public ApplicationUser User { get; set; }

    }
}
