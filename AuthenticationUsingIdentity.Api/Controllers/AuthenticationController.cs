
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using AuthenticationUsingIdentity.Api.Models;
using AuthenticationUsingIdentity.Service.Models.Authentication.SignUp;
using AuthenticationUsingIdentity.Service.Services;
using AuthenticationUsingIdentity.Service.Models;
using AuthenticationUsingIdentity.Service.Models.Authentication.Login;
using System.Security.Claims;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using Microsoft.AspNetCore.Authorization;
using System.ComponentModel.DataAnnotations;
using AuthenticationUsingIdentity.Api.Models.Authentication.Reset;
using AuthenticationUsingIdentity.Service.Models.User;
using AuthenticationUsingIdentity.Data.Models;


namespace AuthenticationUsingIdentity.Api.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthenticationController : ControllerBase
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly IConfiguration _configuration;
        private readonly IEmailService _emailService;
        private readonly IUserManagement _userManagement;
        public AuthenticationController(
            UserManager<ApplicationUser> userManager,
            RoleManager<IdentityRole> roleManager,
            SignInManager<ApplicationUser> signInManager,
            IConfiguration configuration,
            IEmailService emailService,
            IUserManagement userManagement
            )
        {
            _userManager = userManager;
            _configuration = configuration;
            _emailService = emailService;
            _userManagement = userManagement;
        }

        [HttpPost]
        public async Task<IActionResult> Register([FromBody] RegisterUser request)
        {
            try
            {

                var tokenResponse = await _userManagement.CreateUserWithTokenAsync(request);
                if (tokenResponse.IsSuccess && tokenResponse.Response != null)
                {

                    await _userManagement.AssignRoleToUserAsync(request.Roles, tokenResponse.Response.User);

                    //below "Authentication" is controller name
                    var confirmationLink = Url.Action(nameof(ConfirmEmail), "Authentication", new { token = tokenResponse.Response.Token, email = request.Email }, Request.Scheme);
                    var message = new Message(new String[] { request.Email! }, "Confirmation email Link", confirmationLink);
                    _emailService.sendEmail(message);
                    return StatusCode(StatusCodes.Status200OK,
                    new Response { Status = "Success", Message = $"User created successfully and we have sent an email confirmation mail on your email", IsSuccess = true });

                }

                return StatusCode(StatusCodes.Status500InternalServerError,
                 new Response { Status = "Failed", Message = tokenResponse.Message, IsSuccess = false });
            }
            catch (Exception ex)
            {
                return StatusCode(StatusCodes.Status500InternalServerError, new Response
                {
                    Status = "Error",
                    Message = $"Internal Server Error: {ex}"
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
                       new Response { Status = "Success", Message = "Email verified Successfully", IsSuccess = true });
                }

            }
            return StatusCode(StatusCodes.Status500InternalServerError, new Response
            {
                Status = "Error",
                Message = "This user does not exist",
                IsSuccess = true
            });
        }

        [HttpPost]
        [Route("login")]
        public async Task<IActionResult> Login([FromBody] LoginModel loginModel)
        {
            var loginOtpresponse = await _userManagement.GetOtpByLoginAsync(loginModel);

            if (loginOtpresponse.Response != null)
            {
                var user = loginOtpresponse.Response.User;


                if (user.TwoFactorEnabled)
                {

                    var token = loginOtpresponse.Response.Token;
                    //sending two factor authentication via email
                    var twoFacAuthMessage = new Message(new string[] { user.Email! }, "otp confirmation ", token);
                    _emailService.sendEmail(twoFacAuthMessage);
                    return StatusCode(StatusCodes.Status200OK, new Response
                    {
                        Status = "Successs",
                        Message = $"We have sent an otp to your email {user.Email}",
                        IsSuccess = loginOtpresponse.IsSuccess
                    });
                }


                if (user != null && await _userManager.CheckPasswordAsync(user, loginModel.Password))
                {
                    var serviceResponse = await _userManagement.GetJwtTokenAsync(user);
                    return Ok(serviceResponse);

                }
            }
            return Unauthorized();
        }


        [HttpPost]
        [Route("login-2FA")]
        public async Task<IActionResult> LoginWithOTP(string code, string userName)
        {
            var jwt = await _userManagement.LoginUserWithJWTokenAsync(code, userName);
            if (jwt.IsSuccess)
            {
                return Ok(jwt);
            }
            return StatusCode(StatusCodes.Status404NotFound,
                new Response { Status = "Success", Message = $"Invalid Code" });
        }


        [AllowAnonymous]
        [HttpPost]
        [Route("forget-password")]
        public async Task<IActionResult> ForgetPassword([Required] string email)
        {

            var user = await _userManager.FindByEmailAsync(email);
            if (user != null)
            {  //generating token for password reset request
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

        [HttpPost]
        [Route("Refresh-Token")]
        public async Task<IActionResult> RefreshToken([FromBody] LoginResponse tokens)
        {
            var jwt = await _userManagement.RenewAccessTokenAsync(tokens);
            if (jwt.IsSuccess)
            {
                return Ok(jwt);
            }
            return StatusCode(StatusCodes.Status404NotFound,
                new Response { Status = "Success", Message = $"Invalid Code" });
        }



    }


}
