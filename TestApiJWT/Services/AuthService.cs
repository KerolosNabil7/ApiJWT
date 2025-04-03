﻿using System.IdentityModel.Tokens.Jwt;
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
        private readonly JWT _jwt; 
        public AuthService(UserManager<ApplicationUser> userManager, IOptions<JWT> jwt)
        {
            _userManager = userManager;
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
