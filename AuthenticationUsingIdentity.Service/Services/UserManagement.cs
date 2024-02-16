using AuthenticationUsingIdentity.Data.Models;
using AuthenticationUsingIdentity.Service.Models;
using AuthenticationUsingIdentity.Service.Models.Authentication.Login;
using AuthenticationUsingIdentity.Service.Models.Authentication.SignUp;
using AuthenticationUsingIdentity.Service.Models.Authentication.User;
using AuthenticationUsingIdentity.Service.Models.User;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System.Data;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;


namespace AuthenticationUsingIdentity.Service.Services
{
    public class UserManagement : IUserManagement
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly IConfiguration _configuration;

        public UserManagement(
            UserManager<ApplicationUser> userManager,
            RoleManager<IdentityRole> roleManager,
            SignInManager<ApplicationUser> signInManager,
            IConfiguration configuration,
            IEmailService emailService
            )
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _signInManager = signInManager;
            _configuration = configuration;
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
            var newUser = new ApplicationUser
            {
                Email = request.Email,
                UserName = request.UserName,
                SecurityStamp = Guid.NewGuid().ToString(),
                TwoFactorEnabled = true,

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


        public async Task<ApiResponse<List<string>>> AssignRoleToUserAsync(List<string> roles, ApplicationUser newUser)
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

        public async Task<ApiResponse<LoginResponse>> GetJwtTokenAsync(ApplicationUser user)
        {
            var authClaims = new List<Claim>
                {
                    new Claim(ClaimTypes.Name, user.UserName),
                    new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                };

            var userRoles = await _userManager.GetRolesAsync(user);
            foreach (var role in userRoles)
            {
                authClaims.Add(new Claim(ClaimTypes.Role, role));
            }

            var jwtToken = GetToken(authClaims); //access token
            var refreshToken = GenerateRefreshToken();
            _ = int.TryParse(_configuration["JWT:RefreshTokenValidity"], out int refreshTokenValidity);

            user.RefreshToken = refreshToken;
            user.RefreshTokenExpiry = DateTime.UtcNow.AddDays(refreshTokenValidity);

            await _userManager.UpdateAsync(user);

            return new ApiResponse<LoginResponse>
            {
                Response = new LoginResponse()
                {
                    AccessToken = new TokenType()
                    {
                        Token = new JwtSecurityTokenHandler().WriteToken(jwtToken),
                        ExpiryTokenDate = jwtToken.ValidTo
                    },
                    RefreshToken = new TokenType()
                    {
                        Token = user.RefreshToken,
                        ExpiryTokenDate = (DateTime)user.RefreshTokenExpiry
                    }
                },

                IsSuccess = true,
                StatusCode = 200,
                Message = $"Token created"
            };
        }

        public async Task<ApiResponse<LoginResponse>> LoginUserWithJWTokenAsync(string otp, string userName)
        {
            var user = await _userManager.FindByNameAsync(userName);
            var signIn = await _signInManager.TwoFactorSignInAsync("Email", otp, false, false);
            if (signIn.Succeeded)
            {
                if (user != null)
                {
                    return await GetJwtTokenAsync(user);
                }
            }
            return new ApiResponse<LoginResponse>()
            {

                Response = new LoginResponse()
                {

                },
                IsSuccess = false,
                StatusCode = 400,
                Message = $"Invalid Otp"
            };
        }

        public async Task<ApiResponse<LoginResponse>> RenewAccessTokenAsync(LoginResponse tokens)
        {
            var accessToken = tokens.AccessToken;
            var refreshToken = tokens.RefreshToken;
            var principal = GetClaimsPrincipal(accessToken.Token);
            var user = await _userManager.FindByNameAsync(principal.Identity.Name);
            if (refreshToken.Token != user.RefreshToken && refreshToken.ExpiryTokenDate <= DateTime.Now)
            {
                return new ApiResponse<LoginResponse>
                {

                    IsSuccess = false,
                    StatusCode = 400,
                    Message = $"Token invalid or expired"
                };
            }
            var respnse = await GetJwtTokenAsync(user);
            return respnse;
        }


        #region private method region

        private JwtSecurityToken GetToken(List<Claim> authClaims)
        {
            var authSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JWT:Secret"]));
            var validIssuer = _configuration["JWT:ValidIssuer"];
            var validAudience = _configuration["JWT:ValidAudience"];
            _ = int.TryParse(_configuration["JWT:TokenValidityInMinutes"], out int tokenValidityInMinutes);
            var expirationTimeUtc = DateTime.UtcNow.AddMinutes(tokenValidityInMinutes);
            var localTimeZone = TimeZoneInfo.Local;
            var expirationTimeInLocalTimeZone = TimeZoneInfo.ConvertTimeFromUtc(expirationTimeUtc, localTimeZone);
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Issuer = validIssuer,
                Audience = validAudience,
                Expires = expirationTimeInLocalTimeZone,
                Subject = new ClaimsIdentity(authClaims), // Here we have set claims based on the user's JWT token
                SigningCredentials = new SigningCredentials(authSigningKey, SecurityAlgorithms.HmacSha256)
            };

            var tokenHandler = new JwtSecurityTokenHandler();
            var token = (JwtSecurityToken)tokenHandler.CreateToken(tokenDescriptor);

            return token;
        }

        private string GenerateRefreshToken()
        {
            var randomNumber = new Byte[64];
            var range = RandomNumberGenerator.Create();
            range.GetBytes(randomNumber);
            return Convert.ToBase64String(randomNumber);
        }

        private ClaimsPrincipal GetClaimsPrincipal(string accessToken)
        {
            var tokenValidationParameters = new TokenValidationParameters
            {
                ValidateAudience = false,
                ValidateIssuer = false,
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JWT:Secret"])),
                ValidateLifetime = false
            };
            var tokenHandler = new JwtSecurityTokenHandler();
            var principal = tokenHandler.ValidateToken(accessToken, tokenValidationParameters, out SecurityToken securityToken);

            return principal;
        }



        #endregion
    }
}
