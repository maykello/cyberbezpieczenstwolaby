namespace cyberbezpieczenstwolab.Models;

public class ArticleComment
{
    public int Id { get; set; }
    public int ArticleId { get; set; }
    public Article? Article { get; set; }
    public string AuthorUsername { get; set; } = string.Empty;
    public string Content { get; set; } = string.Empty;
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public bool IsModerated { get; set; } = false;
}
