using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore.Metadata.Conventions.Internal;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using TestApiJWT.Helpers;
using TestApiJWT.Models;

namespace TestApiJWT.Services
{
    public class AuthService : IAuthService
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        
        private readonly JWT _jwt; 
        public AuthService(UserManager<ApplicationUser> userManager, IOptions<JWT> jwt, RoleManager<IdentityRole> roleManager)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _jwt = jwt.Value;
        }

        public async Task<AuthModel> RegisterAsync(RegisterModel model)
        {
            //check if the given email exists in the DB or not
            //if exists it can not be register again
            if (await _userManager.FindByEmailAsync(model.Email) != null)
                return new AuthModel 
                { 
                    Message = "Email is already registered!",
                    IsAuthenticated = false,
                };

            //check if the given username exists in the DB or not
            //if exists it can not be register again
            if (await _userManager.FindByNameAsync(model.Username) != null)
                return new AuthModel
                {
                    Message = "Username is already registered!",
                    IsAuthenticated = false,
                };

            var user = new ApplicationUser
            {
                UserName = model.Username,
                Email = model.Email,
                FirstName = model.FirstName,
                LastName = model.LastName,
            };

            var result = await _userManager.CreateAsync(user, model.Password); //Pass the Password to encrypt it during user creation or DB saving

            if (!result.Succeeded)
            {
                string errors = string.Empty;
                foreach (var error in result.Errors)
                    errors += $"{error.Description}, ";

                return new AuthModel
                {
                    Message = errors,
                    IsAuthenticated = false,
                };
            }

            //To add the created user to Role User
            await _userManager.AddToRoleAsync(user, "User");

            var jwtToken = await CreateJwtToken(user);

            return new AuthModel
            {
                Email = user.Email,
                Username = user.UserName,
                IsAuthenticated = true,
                Message = "The user created Successfully",
                ExpiresOn = jwtToken.ValidTo,
                Roles = new List<string> { "User" },
                Token = new JwtSecurityTokenHandler().WriteToken(jwtToken),
            };
        }

        public async Task<AuthModel> GetTokenAsync(TokenRequestModel model)
        {
            var authModel = new AuthModel();

            var user = await _userManager.FindByEmailAsync(model.Email);

            //In  case of there is no user with the provided Email or the password incorrect
            if (user == null || !await _userManager.CheckPasswordAsync(user, model.Password))
            {
                authModel.Message = "Email or Password is incorrect";
                return authModel;
            }

            var jwtToken = await CreateJwtToken(user);
            var RolesList = await _userManager.GetRolesAsync(user);

            authModel.IsAuthenticated = true;
            authModel.Token = new JwtSecurityTokenHandler().WriteToken(jwtToken);
            authModel.Email = user.Email;
            authModel.Username = user.UserName;
            authModel.ExpiresOn = jwtToken.ValidTo;
            authModel.Roles = RolesList.ToList();

            return authModel;
        }

        public async Task<string> AddRoleAsync(AddRoleModel model)
        {
            //Check the UserId(User) & Role Existance in Db
            var user = await _userManager.FindByIdAsync(model.UserId);
            if (user is null || !await _roleManager.RoleExistsAsync(model.Role))
                return "User ID or Role is Invalid!";

            //Check if the user assigned to the role already
            /*var userRoles = await _userManager.GetRolesAsync(user);
            if (userRoles.Contains(model.Role))
                return "The user assigned to this role already";*/
            if(await _userManager.IsInRoleAsync(user, model.Role))
                return "User already assigned to this role";

            var result = await _userManager.AddToRoleAsync(user, model.Role);
            if (result.Succeeded)
                return "";

            return "Something went wrong!";
        }


        private async Task<JwtSecurityToken> CreateJwtToken(ApplicationUser user)
        {
            //To create a jwt token
            
            //1. u should obtain the user claims
            var UserClaims = await _userManager.GetClaimsAsync(user);

            //2. prefer to obtain the user roles to return them with the generated token for front-end developer
            var UserRoles = await _userManager.GetRolesAsync(user);

            var roleClaims = new List<Claim>();

            foreach (var role in UserRoles)
                roleClaims.Add(new Claim("roles", role));

            var claims = new Claim[]
            {
                new Claim(JwtRegisteredClaimNames.Sub, user.UserName),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new Claim(JwtRegisteredClaimNames.Email, user.Email),
                new Claim("uid", user.Id)
            }
            .Union(UserClaims)
            .Union(roleClaims);

            //generate symmetricSecuirtyKey
            var symmetricSecuirtyKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwt.Key));

            var signingCredentials =  new SigningCredentials(symmetricSecuirtyKey, SecurityAlgorithms.HmacSha256);

            //what values that will be used during JWT token generation
            var jwtToken = new JwtSecurityToken(
                issuer: _jwt.Issuer,
                audience: _jwt.Audience,
                claims: claims,
                expires: DateTime.Now.AddDays(_jwt.DurationInDays),
                signingCredentials: signingCredentials
                );

            return jwtToken;
        }
    }
}
