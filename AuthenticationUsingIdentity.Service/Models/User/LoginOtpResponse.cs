

using Microsoft.AspNetCore.Identity;

namespace AuthenticationUsingIdentity.Service.Models.User
{
    public class LoginOtpResponse
    {
        public string Token { get; set; } = null!; //it should be non nullable
        public bool IsTwoFactorEnabled { get; set; }

        public IdentityUser User { get; set; } = null!; //it should be non nullable
    }
}
