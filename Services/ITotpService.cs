namespace cyberbezpieczenstwolab.Services;

public interface ITotpService
{
    string GenerateSecretKey();
    string GenerateQrCodeUri(string username, string secretKey, string issuer = "CyberLab1");
    string GenerateQrCodeBase64Image(string otpAuthUri);
    bool VerifyCode(string secretKey, string code);
}
