using System.ComponentModel.DataAnnotations;
using cyberbezpieczenstwolab.Data;
using cyberbezpieczenstwolab.Models;
using cyberbezpieczenstwolab.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;

namespace cyberbezpieczenstwolab.Pages.Articles;

[Authorize]
public class IndexModel : PageModel
{
    private readonly AppDbContext _context;
    private readonly IAuditService _auditService;

    public IndexModel(AppDbContext context, IAuditService auditService)
    {
        _context = context;
        _auditService = auditService;
    }

    public List<Article> Articles { get; set; } = [];
    public bool CanCreateArticle { get; set; }
    public bool CanModerate { get; set; }
    public string? SuccessMessage { get; set; }
    public string? ErrorMessage { get; set; }

    [BindProperty]
    public NewArticleInput NewArticle { get; set; } = new();

    [BindProperty]
    public NewCommentInput NewComment { get; set; } = new();

    public class NewArticleInput
    {
        [Required(ErrorMessage = "Tytuł artykułu jest wymagany.")]
        [StringLength(100, MinimumLength = 3, ErrorMessage = "Tytuł musi mieć od 3 do 100 znaków.")]
        public string Title { get; set; } = string.Empty;

        [Required(ErrorMessage = "Treść artykułu jest wymagana.")]
        [StringLength(5000, MinimumLength = 5, ErrorMessage = "Treść musi mieć co najmniej 5 znaków.")]
        public string Content { get; set; } = string.Empty;
    }

    public class NewCommentInput
    {
        public int ArticleId { get; set; }

        [Required(ErrorMessage = "Treść komentarza jest wymagana.")]
        [StringLength(1000, MinimumLength = 2, ErrorMessage = "Komentarz musi mieć co najmniej 2 znaki.")]
        public string Content { get; set; } = string.Empty;
    }

    public async Task OnGetAsync()
    {
        CheckPermissions();

        Articles = await _context.Articles
            .Include(a => a.Comments.OrderBy(c => c.CreatedAt))
            .OrderByDescending(a => a.CreatedAt)
            .ToListAsync();

        if (TempData["SuccessMessage"] != null)
        {
            SuccessMessage = TempData["SuccessMessage"]?.ToString();
        }
        if (TempData["ErrorMessage"] != null)
        {
            ErrorMessage = TempData["ErrorMessage"]?.ToString();
        }
    }

    public async Task<IActionResult> OnPostCreateArticleAsync()
    {
        CheckPermissions();

        if (!CanCreateArticle)
        {
            var ip = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "127.0.0.1";
            await _auditService.LogAsync(User.Identity?.Name, "POST_ARTYKUL_403", "Próba publikacji artykułu przez użytkownika bez uprawnień redaktora.", ip, false);
            return Forbid();
        }

        if (!ModelState.IsValid)
        {
            await OnGetAsync();
            return Page();
        }

        var article = new Article
        {
            Title = NewArticle.Title,
            Content = NewArticle.Content,
            AuthorUsername = User.Identity?.Name ?? "Anonim",
            CreatedAt = DateTime.UtcNow
        };

        _context.Articles.Add(article);
        await _context.SaveChangesAsync();

        var ipSuccess = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "127.0.0.1";
        await _auditService.LogAsync(User.Identity?.Name, "PUBLIKACJA_ARTYKULU", $"Opublikowano artykuł '{article.Title}'.", ipSuccess, true);

        TempData["SuccessMessage"] = "Artykuł został pomyślnie opublikowany.";
        return RedirectToPage();
    }

    public async Task<IActionResult> OnPostAddCommentAsync()
    {
        CheckPermissions();

        if (string.IsNullOrWhiteSpace(NewComment.Content))
        {
            TempData["ErrorMessage"] = "Treść komentarza nie może być pusta.";
            return RedirectToPage();
        }

        var article = await _context.Articles.FindAsync(NewComment.ArticleId);
        if (article == null)
        {
            return RedirectToPage();
        }

        var comment = new ArticleComment
        {
            ArticleId = NewComment.ArticleId,
            AuthorUsername = User.Identity?.Name ?? "Anonim",
            Content = NewComment.Content,
            CreatedAt = DateTime.UtcNow,
            IsModerated = false
        };

        _context.ArticleComments.Add(comment);
        await _context.SaveChangesAsync();

        var ip = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "127.0.0.1";
        await _auditService.LogAsync(User.Identity?.Name, "DODANIE_KOMENTARZA", $"Dodano komentarz do artykułu ID={article.Id}.", ip, true);

        TempData["SuccessMessage"] = "Komentarz został dodany.";
        return RedirectToPage();
    }

    public async Task<IActionResult> OnPostModerateCommentAsync(int commentId)
    {
        CheckPermissions();

        if (!CanModerate)
        {
            var ip = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "127.0.0.1";
            await _auditService.LogAsync(User.Identity?.Name, "MODERACJA_KOMENTARZA_403", "Próba moderacji komentarza bez uprawnień audytora/administratora.", ip, false);
            return Forbid();
        }

        var comment = await _context.ArticleComments.FindAsync(commentId);
        if (comment == null)
        {
            return RedirectToPage();
        }

        comment.IsModerated = true;
        comment.Content = "[Komentarz ukryty przez moderatora ze względów regulaminowych]";
        await _context.SaveChangesAsync();

        var ipSuccess = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "127.0.0.1";
        await _auditService.LogAsync(User.Identity?.Name, "MODERACJA_TRESCI", $"Zmoderowano komentarz ID={comment.Id} użytkownika {comment.AuthorUsername}.", ipSuccess, true);

        TempData["SuccessMessage"] = "Komentarz został pomyślnie zmoderowany.";
        return RedirectToPage();
    }

    public async Task<IActionResult> OnPostDeleteArticleAsync(int articleId)
    {
        CheckPermissions();

        if (!CanModerate)
        {
            var ip = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "127.0.0.1";
            await _auditService.LogAsync(User.Identity?.Name, "USUNIECIE_ARTYKULU_403", "Próba usunięcia artykułu bez uprawnień audytora/administratora.", ip, false);
            return Forbid();
        }

        var article = await _context.Articles.FindAsync(articleId);
        if (article == null)
        {
            return RedirectToPage();
        }

        _context.Articles.Remove(article);
        await _context.SaveChangesAsync();

        var ipSuccess = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "127.0.0.1";
        await _auditService.LogAsync(User.Identity?.Name, "USUNIECIE_ARTYKULU", $"Usunięto artykuł '{article.Title}'.", ipSuccess, true);

        TempData["SuccessMessage"] = "Artykuł został pomyślnie usunięty.";
        return RedirectToPage();
    }

    private void CheckPermissions()
    {
        CanCreateArticle = User.IsInRole(AppRoles.Redaktor) || User.IsInRole(AppRoles.Administrator);
        CanModerate = User.IsInRole(AppRoles.Audytor) || User.IsInRole(AppRoles.Administrator);
    }
}
