using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using RefreshTokenExample.Entities;
using RefreshTokenExample.Helpers;
using RefreshTokenExample.Models;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace RefreshTokenExample.Services
{
    public class UserService : IUserService
    {
        private UserDbContext _context;
        private readonly AppSettings _appSettings;

        public UserService(UserDbContext context, IOptions<AppSettings> appSettings)
        {
            _context = context;
            _appSettings = appSettings.Value;
        }

        public AuthenticateResponse Authenticate(AuthenticateRequest model, string ipAddress)
        {
            var user = _context.Users.SingleOrDefault(x => x.Username == model.Username && x.Password == model.Password);

            // kullanıcı yoksa null döndür
            if (user == null)
            {
                return null;
            }

            // authentication başarılı bir şekilde yapıldıysa jwt ve refresh token üret
            var jwtToken = GenerateJwtToken(user);
            var refreshToken = GenerateRefreshToken(ipAddress);

            // refresh token kaydet
            user.RefreshTokens.Add(refreshToken);
            _context.Update(user);
            _context.SaveChanges();

            return new AuthenticateResponse(user, jwtToken, refreshToken.Token);
        }
        public AuthenticateResponse RefreshToken(string token, string ipAddress)
        {
            var user = _context.Users.SingleOrDefault(u => u.RefreshTokens.Any(t => t.Token == token));

            // o tokena ait kullanıcı yoksa null döndür
            if (user == null)
            {
                return null;
            }

            var refreshToken = user.RefreshTokens.Single(x => x.Token == token);

            // eğer token aktif değilse null gönder
            if (!refreshToken.IsActive)
            {
                return null;
            }

            // eski refresh tokenı yenisiyle değiştir ve kaydet 
            var newRefreshToken = GenerateRefreshToken(ipAddress);
            refreshToken.RevokedDate = DateTime.Now;
            refreshToken.RevokedByIp = ipAddress;
            refreshToken.ReplacedByToken = newRefreshToken.Token;
            user.RefreshTokens.Add(newRefreshToken);
            _context.Update(user);
            _context.SaveChanges();

            var jwtToken = GenerateJwtToken(user);
            return new AuthenticateResponse(user, jwtToken, newRefreshToken.Token);
        }

        public bool RevokeToken(string token, string ipAddress)
        {
            var user = _context.Users.SingleOrDefault(u => u.RefreshTokens.Any(t => t.Token == token));

            // o tokena ait kullanıcı bulunamazsa false döndür
            if (user == null)
            {
                return false;
            }

            var refreshToken = user.RefreshTokens.Single(x => x.Token == token);

            // token aktif değilse false döndür
            if (!refreshToken.IsActive)
            {
                return false;
            }

            // iptal et ve kaydet
            refreshToken.RevokedDate = DateTime.Now;
            refreshToken.RevokedByIp = ipAddress;
            _context.Update(user);
            _context.SaveChanges();

            return true;
        }

        public IEnumerable<User> GetAll()
        {
            return _context.Users;
        }

        public User GetById(int id)
        {
            return _context.Users.Find(id);
        }

        //helper metotlar
        private string GenerateJwtToken(User user)
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes(_appSettings.Secret);
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new Claim[]
                {
                    new Claim(ClaimTypes.Name, user.Id.ToString())
                }),
                Expires = DateTime.Now.AddMinutes(15),
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
            };
            var token = tokenHandler.CreateToken(tokenDescriptor);
            return tokenHandler.WriteToken(token);
        }

        private RefreshToken GenerateRefreshToken(string ipAddress)
        {
            using (var rngCryptoServiceProvider = new RNGCryptoServiceProvider())
            {
                var randomBytes = new byte[64];
                rngCryptoServiceProvider.GetBytes(randomBytes);
                return new RefreshToken
                {
                    Token = Convert.ToBase64String(randomBytes),
                    ExpiredDate = DateTime.Now.AddDays(7),
                    CreatedDate = DateTime.Now,
                    CreatedByIp = ipAddress
                };
            }
        }
    }
}
