
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using AuthenticationUsingIdentity.Api.Models;
using AuthenticationUsingIdentity.Api.Models.Authentication.SignUp;
using AuthenticationUsingIdentity.Service.Services;
using AuthenticationUsingIdentity.Service.Models;
using AuthenticationUsingIdentity.Api.Models.Authentication.Login;
using System.Security.Claims;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using System.Data;
using Microsoft.AspNetCore.Authorization;
using System.ComponentModel.DataAnnotations;
using AuthenticationUsingIdentity.Api.Models.Authentication.Reset;
using Microsoft.EntityFrameworkCore.Metadata.Internal;

namespace AuthenticationUsingIdentity.Api.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthenticationController : ControllerBase
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly SignInManager<IdentityUser> _signInManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly IConfiguration _configuration;
        private readonly IEmailService _emailService;
        public AuthenticationController(
            UserManager<IdentityUser> userManager,
            RoleManager<IdentityRole> roleManager,
            SignInManager<IdentityUser> signInManager,
            IConfiguration configuration,
            IEmailService emailService
            )
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _configuration = configuration;
            _emailService = emailService;
            _signInManager = signInManager;
        }

        [HttpPost]
        public async Task<IActionResult> Register([FromBody] RegisterUser request, string role)
        {
            try
            {
                // Check if the user already exists
                var existingUser = await _userManager.FindByEmailAsync(request.Email);
                if (existingUser != null)
                {
                    return StatusCode(StatusCodes.Status403Forbidden, new Response
                    {
                        Status = "Error",
                        Message = "User already exists"
                    });
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
                if (await _roleManager.RoleExistsAsync(role))
                {
                    // Create the user
                    var createUserResult = await _userManager.CreateAsync(newUser, request.Password);

                    if (createUserResult.Succeeded)
                    {
                        // Add the user to the specified role
                        var assignRoleResult = await _userManager.AddToRoleAsync(newUser, role);

                        //below we are sending email to user with token for confirmation of email
                        var token = await _userManager.GenerateEmailConfirmationTokenAsync(newUser);
                        //below "Authentication" is controller name
                        var confirmationLink = Url.Action(nameof(ConfirmEmail), "Authentication", new { token, email = newUser.Email }, Request.Scheme);
                        var message = new Message(new String[] { newUser.Email! }, "Confirmation email Link", confirmationLink);
                        _emailService.sendEmail(message);


                        if (assignRoleResult.Succeeded)
                        {
                            return StatusCode(StatusCodes.Status201Created, new Response
                            {
                                Status = "Success",
                                Message = $"User created and assigned to role successfully! and email send to {newUser.Email}  successfully"
                            });
                        }

                        // Clean up and return error if adding the user to the role fails
                        await _userManager.DeleteAsync(newUser);
                        var errorMessage = string.Join(", ", createUserResult.Errors.Select(error => error.Description));
                        return StatusCode(StatusCodes.Status500InternalServerError, new Response
                        {
                            Status = "Error",
                            Message = $"User creation successful, but role assignment failed: {errorMessage}"
                        });
                    }

                    // Clean up and return error if user creation fails
                    await _userManager.DeleteAsync(newUser);
                    var userCreationErrorMessage = string.Join(", ", createUserResult.Errors.Select(error => error.Description));
                    return StatusCode(StatusCodes.Status500InternalServerError, new Response
                    {
                        Status = "Error",
                        Message = $"User creation failed: {userCreationErrorMessage}"
                    });
                }

                return StatusCode(StatusCodes.Status400BadRequest, new Response
                {
                    Status = "Error",
                    Message = $"Role '{role}' does not exist"
                });
            }
            catch (Exception ex)
            {
                return StatusCode(StatusCodes.Status500InternalServerError, new Response
                {
                    Status = "Error",
                    Message = $"Internal Server Error: {ex.Message}"
                });
            }
        }

        //test api for sending email
        /*[HttpGet]
        public async Task<IActionResult> TestEmail()
        {
            var message = new Message(
                new string[] { "jitcse.rushikeshchaudhari@gmail.com" },
                "forget password",
                "<h1>hello world , this is rushikesh chaudhary"
                );

            _emailService.sendEmail(message);
            return StatusCode(StatusCodes.Status200OK,
                new Response { Status = "Success", Message = "Email sent successfully" });
        }*/

        //we are making below endpoint to makesure that user has entered correct email by checking token
        //below action will be hit when you send mail and in email there will be a link of below action api endpoint
        [HttpGet("ConfirmEmail")]

        public async Task<IActionResult> ConfirmEmail(string token, string email)
        {
            var user = await _userManager.FindByEmailAsync(email);
            if (user != null)
            {
                var result = await _userManager.ConfirmEmailAsync(user, token);
                if (result.Succeeded)
                {
                    return StatusCode(StatusCodes.Status200OK,
                       new Response { Status = "Success", Message = "Email verified Successfully" });
                }

            }
            return StatusCode(StatusCodes.Status500InternalServerError, new Response
            {
                Status = "Error",
                Message = "This user does not exist"
            });
        }

        [HttpPost]
        [Route("login")]
        public async Task<IActionResult> Login([FromBody] LoginModel loginModel)
        {

            //checking the user 
            var user = await _userManager.FindByNameAsync(loginModel.UserName);
            var result =await  _userManager.CheckPasswordAsync(user, loginModel.Password);
            if (result) { 
            if (user.TwoFactorEnabled)
            {
                /*
                 * Signs out the user using the _signInManager.SignOutAsync method.
                  Signs in the user using the _signInManager.PasswordSignInAsync method with the user's email and password.
                  This logs the user in to the application.*/
                await _signInManager.SignOutAsync();
                await _signInManager.PasswordSignInAsync(user, loginModel.Password, false, true);
                var twoFacAuthToken = await _userManager.GenerateTwoFactorTokenAsync(user, "Email");
                var twoFacAuthMessage = new Message(new string[] { user.Email! }, "otp confirmation ", twoFacAuthToken);
                _emailService.sendEmail(twoFacAuthMessage);
                return StatusCode(StatusCodes.Status200OK, new Response
                {
                    Status = "Successs",
                    Message = $"We have sent an otp to your email {user.Email}"
                });
            }
            }


            return Unauthorized();

        }

        [HttpPost]
        [Route("login-2FA")]
        public async Task<IActionResult> LoginWithOTP(string code, string userName)
        {
            var user = await _userManager.FindByNameAsync(userName);
            var signIn = await _signInManager.TwoFactorSignInAsync("Email", code, false, false);
            if (signIn.Succeeded)
            {
                if (user != null)
                {

                    //claimlist creation

                    var authClaims = new List<Claim>
                   {
                     new Claim(ClaimTypes.Name, user.UserName),
                     new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                   };

                    //add roles to the claims
                    var userRoles = await _userManager.GetRolesAsync(user);
                    foreach (var role in userRoles)
                    {
                        authClaims.Add(new Claim(ClaimTypes.Role, role));
                    }

                    //generate the token with claims
                    var jwtToken = GetToken(authClaims);


                    //returning the token
                    return Ok(new
                    {
                        token = new JwtSecurityTokenHandler().WriteToken(jwtToken),
                        expiration = jwtToken.ValidTo
                    });

                }

            }
            return StatusCode(StatusCodes.Status403Forbidden,
              new Response { Status = "Error", Message = $"Invalid Code" });
        }


        [AllowAnonymous]
        [HttpPost]
        [Route("forget-password")]
        public async Task<IActionResult> ForgetPassword([Required] string email)
        {

            var user = await _userManager.FindByEmailAsync(email);
            if (user != null)
            {
                var token = await _userManager.GeneratePasswordResetTokenAsync(user);
                var forgetPasswordlink = Url.Action(nameof(ResetPassword), "Authentication", new { token, email = user.Email }, Request.Scheme);
                var message = new Message(new string[] { user.Email }, "Forget Password Link", forgetPasswordlink);
                _emailService.sendEmail(message);
                return StatusCode(StatusCodes.Status200OK,
            new Response { Status = "Success", Message = $"We have sent an email to  your email:{user.Email}. Please open your mail and click on forget password link" });
            }

            return StatusCode(StatusCodes.Status400BadRequest,
           new Response { Status = "Error", Message = $"Couldn.t send an email on {user.Email}.Please try again." });



        }

        [AllowAnonymous]
        [HttpPost]
        [Route("reeset-password")]
        public async Task<IActionResult> ResetPassword([Required] ResetPassword resetPassword)
        {

            var user = await _userManager.FindByEmailAsync(resetPassword.Email);
            if (user != null)
            {
                var resetPasswordResult = await _userManager.ResetPasswordAsync(user, resetPassword.Token, resetPassword.ConfirmPassword);
                if (!resetPasswordResult.Succeeded)
                {
                    foreach (var error in resetPasswordResult.Errors)
                    {
                        ModelState.AddModelError(error.Code, error.Description);
                        /*The ModelState object is a part of the ASP.NET Core Model - View - Controller(MVC) framework and is used to store errors and validation results for the current request.*/
                    }

                    return Ok(ModelState);
                }
                return StatusCode(StatusCodes.Status200OK,
            new Response { Status = "Success", Message = $"password has been changed" });
            }

            return StatusCode(StatusCodes.Status400BadRequest,
           new Response { Status = "Error", Message = $"Couldn.t send an email on {user.Email}.Please try again." });



        }


        [HttpGet("reeset-password")]
        public async Task<IActionResult> ResetPassword(string token, string email)
        {
            var model = new ResetPassword() { Token = token, Email = email };


            return Ok(new
            {
                model
            });
        }
        private JwtSecurityToken GetToken(List<Claim> authClaims)
        {
            var authSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JWT:Secret"]));
            var validIssuer = _configuration["JWT:ValidIssuer"];
            var validAudience = _configuration["JWT:ValidAudience"];

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Issuer = validIssuer,
                Audience = validAudience,
                Expires = DateTime.UtcNow.AddHours(1),
                Subject = new ClaimsIdentity(authClaims),
                SigningCredentials = new SigningCredentials(authSigningKey, SecurityAlgorithms.HmacSha256)
            };

            var tokenHandler = new JwtSecurityTokenHandler();
            var token = (JwtSecurityToken)tokenHandler.CreateToken(tokenDescriptor);

            return token;
        }



    }


}
