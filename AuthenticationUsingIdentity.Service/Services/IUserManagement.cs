using AuthenticationUsingIdentity.Service.Models;
using AuthenticationUsingIdentity.Service.Models.Authentication.SignUp;
using Microsoft.AspNetCore.Identity;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AuthenticationUsingIdentity.Service.Services
{
    public interface IUserManagement
    {
        Task<ApiResponse<string>> CreateUserWithTokenAsync(RegisterUser request);
        Task<ApiResponse<List<string>>> AssignRoleToUserAsync(IEnumerable<string> roles, IdentityUser newUser);

    }
}
