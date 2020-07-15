using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using RefreshTokenExample.Models;
using RefreshTokenExample.Services;
using System;

namespace RefreshTokenExample.Controllers
{
    [Authorize]
    [ApiController]
    [Route("controller")]
    public class UsersController : Controller
    {
        private IUserService _userService;

        public UsersController(IUserService userService)
        {
            _userService = userService;
        }

        [AllowAnonymous]
        [HttpPost("authenticate")]
        public IActionResult Authenticate([FromBody] AuthenticateRequest request)
        {
            var response = _userService.Authenticate(request, IpAddress());

            if (response == null)
            {
                return BadRequest(new { message = "Kullanıcı adı ya da şifreniz yanlış" });
            }

            SetTokenCookie(response.RefreshToken);
            return Ok(response);
        }

        [AllowAnonymous]
        [HttpPost("refresh-token")]
        public IActionResult RefreshToken()
        {
            var refreshToken = Request.Cookies["refreshToken"];
            var response = _userService.RefreshToken(refreshToken, IpAddress());

            if (response == null)
            {
                return Unauthorized(new { message = "Geçersiz Token" });
            }

            SetTokenCookie(response.RefreshToken);

            return Ok(response);
        }
        
        [HttpPost("revoke-token")]
        public IActionResult RevokeToken([FromBody] RevokeTokenRequest tokenRequest)
        {
            // tokenı request bodyden veya cookieden al
            var token = tokenRequest.Token ?? Request.Cookies["refreshToken"];

            if (string.IsNullOrEmpty(token))
            {
                return BadRequest(new { message = "Token bulunamadı" });
            }

            var response = _userService.RevokeToken(token, IpAddress());

            if (!response)
            {
                return NotFound(new { message = "Token gerekli" });
            }

            return Ok(new { message = "Token iptal edildi" });
        }

        [HttpGet]
        public IActionResult GetAll()
        {
            var users = _userService.GetAll();
            return Ok(users);
        }

        [HttpGet("{id}/refresh-tokens")]
        public IActionResult GetRefreshTokens(int id)
        {
            var user = _userService.GetById(id);
            if (user == null)
            {
                return NotFound();
            }
            return Ok(user.RefreshTokens);
        }

        //Helper Metotlar

        private void SetTokenCookie(string refreshToken)
        {
            var cookieOptions = new CookieOptions { HttpOnly = true, Expires = DateTime.Now.AddDays(7) };
            Response.Cookies.Append("refreshToken", refreshToken, cookieOptions);
        }

        private string IpAddress()
        {
            if (Request.Headers.ContainsKey("X-Forwarded-For"))
            {
                return Request.Headers["X-Forwarded-For"];
            }
            else
            {
                return HttpContext.Connection.RemoteIpAddress.MapToIPv4().ToString();
            }
        }
    }
}