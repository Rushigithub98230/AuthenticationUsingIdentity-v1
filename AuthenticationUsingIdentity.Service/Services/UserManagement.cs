using AuthenticationUsingIdentity.Service.Models;
using AuthenticationUsingIdentity.Service.Models.Authentication.Login;
using AuthenticationUsingIdentity.Service.Models.Authentication.SignUp;
using AuthenticationUsingIdentity.Service.Models.Authentication.User;
using AuthenticationUsingIdentity.Service.Models.User;
using Azure;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using System;
using System.Collections.Generic;
using System.Data;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AuthenticationUsingIdentity.Service.Services
{
    public class UserManagement : IUserManagement
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly SignInManager<IdentityUser> _signInManager;
        private readonly RoleManager<IdentityRole> _roleManager;

        public UserManagement(
            UserManager<IdentityUser> userManager,
            RoleManager<IdentityRole> roleManager,
            SignInManager<IdentityUser> signInManager,
            IConfiguration configuration,
            IEmailService emailService
            )
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _signInManager = signInManager;
        }

        public async Task<ApiResponse<CreateUserResponse>> CreateUserWithTokenAsync([FromBody] RegisterUser request)
        {

            // Check if the user already exists
            var existingUser = await _userManager.FindByEmailAsync(request.Email);
            if (existingUser != null)
            {
                return new ApiResponse<CreateUserResponse> { IsSuccess = true, StatusCode = 403, Message = "User Already exists!" };
            }

            // Create a new user
            var newUser = new IdentityUser
            {
                Email = request.Email,
                UserName = request.UserName,
                SecurityStamp = Guid.NewGuid().ToString(),
                TwoFactorEnabled = true
            };

            // Create the user
            var createUserResult = await _userManager.CreateAsync(newUser, request.Password);

            if (createUserResult.Succeeded)
            {

                //below we are sending email to user with token for confirmation of email
                var token = await _userManager.GenerateEmailConfirmationTokenAsync(newUser);
                //below "Authentication" is controller name
                /* var confirmationLink = Url.Action(nameof(ConfirmEmail), "Authentication", new { token, email = newUser.Email }, Request.Scheme);
                 var message = new Message(new String[] { newUser.Email! }, "Confirmation email Link", confirmationLink);
                 _emailService.sendEmail(message);*/

                return new ApiResponse<CreateUserResponse> { Response = new CreateUserResponse { Token = token, User = newUser }, IsSuccess = true, StatusCode = 200, Message = $"user created successfully" };


            }

            // Clean up and return error if user creation fails
            await _userManager.DeleteAsync(newUser);
            var userCreationErrorMessage = string.Join(", ", createUserResult.Errors.Select(error => error.Description));

            return new ApiResponse<CreateUserResponse> { IsSuccess = false, StatusCode = 500, Message = $"User creation failed: {userCreationErrorMessage}" };






            /* catch (Exception ex)
             {
                 return StatusCode(StatusCodes.Status500InternalServerError, new Response
                 {
                     Status = "Error",
                     Message = $"Internal Server Error: {ex.Message}"
                 });
             }*/
        }


        public async Task<ApiResponse<List<string>>> AssignRoleToUserAsync(List<string> roles, IdentityUser newUser)
        {
            var assignRoleResultList = new List<string>();
            foreach (var role in roles)
            {

                if (await _roleManager.RoleExistsAsync(role))
                {
                    if (!await _userManager.IsInRoleAsync(newUser, role))
                    {
                        await _userManager.AddToRoleAsync(newUser, role);
                        assignRoleResultList.Add(role);
                    }

                }
            }
            return new ApiResponse<List<string>> { IsSuccess = true, StatusCode = 200, Message = "Roles has been assigned", Response = assignRoleResultList };
        }

        public async Task<ApiResponse<LoginOtpResponse>> GetOtpByLoginAsync(LoginModel loginModel)
        {
            var user = await _userManager.FindByNameAsync(loginModel.UserName);
 
            if (user != null)
            {
                /*
                   * Signs out the user using the _signInManager.SignOutAsync method.
                    Signs in the user using the _signInManager.PasswordSignInAsync method with the user's email and password.
                    This logs the user in to the application.*/
                await _signInManager.SignOutAsync();
                await _signInManager.PasswordSignInAsync(user, loginModel.Password, false, true);

                if (user.TwoFactorEnabled)
                {
                    //generating two factor authentication token
                    var twoFacAuthToken = await _userManager.GenerateTwoFactorTokenAsync(user, "Email");

                    //sending two factor authentication via email
                    var twoFacAuthMessage = new Message(new string[] { user.Email! }, "otp confirmation ", twoFacAuthToken);
                    //_emailService.sendEmail(twoFacAuthMessage);
                    return new ApiResponse<LoginOtpResponse>
                    {
                        IsSuccess = true,
                        StatusCode = 200,
                        Message = $"Otp send to the email {user.Email}",
                        Response = new LoginOtpResponse
                        {
                            Token = twoFacAuthToken,
                            IsTwoFactorEnabled = user.TwoFactorEnabled,
                            User = user,
                            
                        }
                    };
                }
                else
                {
                    return new ApiResponse<LoginOtpResponse>
                    {
                        IsSuccess = true,
                        StatusCode = 200,
                        Message = $"2FA is not enabled",
                        Response = new LoginOtpResponse
                        {
                            Token = string.Empty,
                            IsTwoFactorEnabled = user.TwoFactorEnabled,
                            User = user
                        }
                    };
                }
            }
            else
            {
                return new ApiResponse<LoginOtpResponse>
                {
                    IsSuccess = false,
                    StatusCode = 404,
                    Message = $"User doesn't exist",

                };
            }

        }
    }
}
