using OtpNet;
using QRCoder;

namespace cyberbezpieczenstwolab.Services;

public class TotpService : ITotpService
{
    public string GenerateSecretKey()
    {
        byte[] secretBytes = KeyGeneration.GenerateRandomKey(20);
        return Base32Encoding.ToString(secretBytes);
    }

    public string GenerateQrCodeUri(string username, string secretKey, string issuer = "CyberLab1")
    {
        string encodedIssuer = Uri.EscapeDataString(issuer);
        string encodedUsername = Uri.EscapeDataString(username);
        return $"otpauth://totp/{encodedIssuer}:{encodedUsername}?secret={secretKey}&issuer={encodedIssuer}&digits=6";
    }

    public string GenerateQrCodeBase64Image(string otpAuthUri)
    {
        using var qrGenerator = new QRCodeGenerator();
        using var qrCodeData = qrGenerator.CreateQrCode(otpAuthUri, QRCodeGenerator.ECCLevel.Q);
        using var qrCode = new PngByteQRCode(qrCodeData);
        byte[] qrBytes = qrCode.GetGraphic(10);
        return $"data:image/png;base64,{Convert.ToBase64String(qrBytes)}";
    }

    public bool VerifyCode(string secretKey, string code)
    {
        if (string.IsNullOrWhiteSpace(secretKey) || string.IsNullOrWhiteSpace(code))
        {
            return false;
        }

        try
        {
            byte[] secretBytes = Base32Encoding.ToBytes(secretKey);
            var totp = new Totp(secretBytes);
            return totp.VerifyTotp(code.Trim(), out _, VerificationWindow.RfcSpecifiedNetworkDelay);
        }
        catch
        {
            return false;
        }
    }
}
