using cyberbezpieczenstwolab.Data;
using cyberbezpieczenstwolab.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;

namespace cyberbezpieczenstwolab.Pages.Account;

public class ProfileModel : PageModel
{
    private readonly AppDbContext _context;

    public ProfileModel(AppDbContext context)
    {
        _context = context;
    }

    public User? CurrentUser { get; set; }
    public int PasswordHistoryCount { get; set; }

    public async Task<IActionResult> OnGetAsync()
    {
        var username = User.Identity?.Name;
        if (string.IsNullOrEmpty(username))
        {
            return RedirectToPage("/Account/Login");
        }

        CurrentUser = await _context.Users
            .Include(u => u.PasswordHistories)
            .FirstOrDefaultAsync(u => u.Username == username);

        if (CurrentUser == null)
        {
            return RedirectToPage("/Account/Login");
        }

        PasswordHistoryCount = CurrentUser.PasswordHistories.Count;
        return Page();
    }
}
