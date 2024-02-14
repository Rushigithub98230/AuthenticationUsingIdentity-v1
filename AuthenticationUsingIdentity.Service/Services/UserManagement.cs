﻿using AuthenticationUsingIdentity.Service.Models;
using AuthenticationUsingIdentity.Service.Models.Authentication.SignUp;
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

        public async Task<ApiResponse<string>> CreateUserWithTokenAsync([FromBody] RegisterUser request)
        {

            // Check if the user already exists
            var existingUser = await _userManager.FindByEmailAsync(request.Email);
            if (existingUser != null)
            {
                return new ApiResponse<string> { IsSuccess = true, StatusCode = 403, Message = "User Already exists!" };
            }

            // Create a new user
            var newUser = new IdentityUser
            {
                Email = request.Email,
                UserName = request.UserName,
                SecurityStamp = Guid.NewGuid().ToString(),
                TwoFactorEnabled = true
            };

            // Check if the specified role exists
            if (await _roleManager.RoleExistsAsync(request.Role))
            {
                // Create the user
                var createUserResult = await _userManager.CreateAsync(newUser, request.Password);

                if (createUserResult.Succeeded)
                {
                    // Add the user to the specified role
                    var assignRoleResult = await _userManager.AddToRoleAsync(newUser, request.Role);

                    //below we are sending email to user with token for confirmation of email
                    var token = await _userManager.GenerateEmailConfirmationTokenAsync(newUser);
                    //below "Authentication" is controller name
                    /* var confirmationLink = Url.Action(nameof(ConfirmEmail), "Authentication", new { token, email = newUser.Email }, Request.Scheme);
                     var message = new Message(new String[] { newUser.Email! }, "Confirmation email Link", confirmationLink);
                     _emailService.sendEmail(message);*/


                    if (assignRoleResult.Succeeded)
                    {
                        return new ApiResponse<string> { IsSuccess = true, StatusCode = 201, Message = $"User created and assigned to role successfully! and email send to {newUser.Email}  successfully", Response = token };

                    }

                    // Clean up and return error if adding the user to the role fails
                    await _userManager.DeleteAsync(newUser);
                    var errorMessage = string.Join(", ", createUserResult.Errors.Select(error => error.Description));


                    return new ApiResponse<string> { IsSuccess = false, StatusCode = 500, Message = $"User creation successful, but role assignment failed: {errorMessage}" };
                }

                // Clean up and return error if user creation fails
                await _userManager.DeleteAsync(newUser);
                var userCreationErrorMessage = string.Join(", ", createUserResult.Errors.Select(error => error.Description));

                return new ApiResponse<string> { IsSuccess = false, StatusCode = 500, Message = $"User creation failed: {userCreationErrorMessage}" };


            }
            return new ApiResponse<string> { IsSuccess = false, StatusCode = 400, Message = $"Role '{request.Role}' does not exist" };


            /* catch (Exception ex)
             {
                 return StatusCode(StatusCodes.Status500InternalServerError, new Response
                 {
                     Status = "Error",
                     Message = $"Internal Server Error: {ex.Message}"
                 });
             }*/
        }


        public async Task<ApiResponse<List<string>>> AssignRoleToUserAsync(IEnumerable<string> roles, IdentityUser newUser)
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
