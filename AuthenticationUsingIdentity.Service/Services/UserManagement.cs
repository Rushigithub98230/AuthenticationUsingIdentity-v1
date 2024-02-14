using AuthenticationUsingIdentity.Service.Models;
using AuthenticationUsingIdentity.Service.Models.Authentication.SignUp;
using AuthenticationUsingIdentity.Service.Models.Authentication.User;
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

    }
}
