using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace AuthenticationUsingIdentity.Api.Controllers
{
    [Authorize(Roles = "Admin")]
    [Route("api/[controller]")]
    [ApiController]
    public class AdminController : ControllerBase
    {
        [HttpGet("Employees")]
        public async Task<IEnumerable<string>> Get()
        {
            return new List<string> { "Apeksha", "Rushieksh", "rohit", "Karmanye" };
        }
    }
}
