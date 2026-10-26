namespace cyberbezpieczenstwolab.Models;

public static class AppRoles
{
    public const string Administrator = "Administrator";
    public const string Audytor = "Audytor";
    public const string Redaktor = "Redaktor";
    public const string Czytelnik = "Czytelnik";

    public static readonly string[] All = [Administrator, Audytor, Redaktor, Czytelnik];
}
