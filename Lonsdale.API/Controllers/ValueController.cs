using System.Linq;
using System.Threading.Tasks;
using Lonsdale.API.Data;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace Lonsdale.API.Controllers
{
    [Authorize]
    [Route("api/[controller]")]
    [ApiController]
    public class ValueController : ControllerBase
    {
        private readonly DataContext _context;
        public ValueController(DataContext context){
            _context = context;
        }
        [HttpGet]
        public async Task<IActionResult> Get(){
            var values = await _context.Values.ToListAsync();
            return Ok(values);
        }
        [HttpGet("{id}")]
        public async Task<IActionResult> GetValue(int id){
            var values = await _context.Values.FirstOrDefaultAsync(x => x.Id == id);
            return Ok(values);
        }
    }
}