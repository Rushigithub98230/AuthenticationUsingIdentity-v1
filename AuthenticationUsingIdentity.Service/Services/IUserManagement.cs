using AuthenticationUsingIdentity.Data.Models;
using AuthenticationUsingIdentity.Service.Models;
using AuthenticationUsingIdentity.Service.Models.Authentication.Login;
using AuthenticationUsingIdentity.Service.Models.Authentication.SignUp;
using AuthenticationUsingIdentity.Service.Models.Authentication.User;
using AuthenticationUsingIdentity.Service.Models.User;
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
        Task<ApiResponse<CreateUserResponse>> CreateUserWithTokenAsync(RegisterUser request);
        Task<ApiResponse<List<string>>> AssignRoleToUserAsync(List<string> roles, ApplicationUser newUser);
        Task<ApiResponse<LoginOtpResponse>> GetOtpByLoginAsync(LoginModel loginmodel);
        Task<ApiResponse<LoginResponse>> GetJwtTokenAsync(ApplicationUser user);
        Task<ApiResponse<LoginResponse>> LoginUserWithJWTokenAsync(string otp, string userName);//it checks whether otp is valid or not , if otp is valid then it will generate token otherwise is returns Invalid Otp
        Task<ApiResponse<LoginResponse>> RenewAccessTokenAsync(LoginResponse tokens);


    }
}
