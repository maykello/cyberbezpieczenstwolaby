namespace cyberbezpieczenstwolab.Models;

public class Article
{
    public int Id { get; set; }
    public string Title { get; set; } = string.Empty;
    public string Content { get; set; } = string.Empty;
    public string AuthorUsername { get; set; } = string.Empty;
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public List<ArticleComment> Comments { get; set; } = [];
}
