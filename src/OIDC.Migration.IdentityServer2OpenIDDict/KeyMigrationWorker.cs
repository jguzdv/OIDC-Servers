using Microsoft.AspNetCore.DataProtection;
using System.Security.Cryptography;
using System.Text;

using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.Globalization;
using System.IO;
using System.Security.Cryptography.X509Certificates;

internal class KeyMigrationWorker : IHostedService
{
    private readonly IDataProtector _dataProtector;
    private readonly IOptions<Options> _options;
    private readonly ILogger<KeyMigrationWorker> _logger;
    private readonly IHostApplicationLifetime _hostApplicationLifetime;

    public KeyMigrationWorker(
        IDataProtectionProvider dataProtectionProvider,
        IOptions<Options> options,
        ILogger<KeyMigrationWorker> logger,
        IHostApplicationLifetime hostApplicationLifetime
    )
    {
        _dataProtector = dataProtectionProvider.CreateProtector("KeyProtection");
        _options = options;
        _logger = logger;
        _hostApplicationLifetime = hostApplicationLifetime;
    }

    public Task StartAsync(CancellationToken cancellationToken)
    {
        _ = RunAsync(cancellationToken);
        _logger.LogInformation("Started Key Migration job");
        return Task.CompletedTask;
    }

    public Task StopAsync(CancellationToken cancellationToken)
    {
        return Task.CompletedTask;
    }


    private async Task RunAsync(CancellationToken ct)
    {
        await MigrateKeys(ct);

        _hostApplicationLifetime.StopApplication();
    }


    private async Task MigrateKeys(CancellationToken ct)
    {
        try
        {
            var rsaKeys = new List<(RsaSecurityKey SecurityKey, DateTimeOffset ValidFrom)>();
            foreach (var filename in Directory.EnumerateFiles(_options.Value.KeyPath))
            {
                _logger.LogDebug("Attempting to load {filename}", filename);
                var rsaKey = await LoadKeyAsync(filename);
                _logger.LogInformation("Loaded key from {filename}", filename);

                rsaKeys.Add(rsaKey);
            }

            var certificates = new List<X509Certificate2>();
            foreach (var rsaKey in rsaKeys)
            {
                var rsa = RSA.Create(rsaKey.SecurityKey.Parameters);
                var subject = new X500DistinguishedName("CN=OIDC Signature Certificate");
                var request = new CertificateRequest(subject, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

                request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, critical: true));

                var certificate = request.CreateSelfSigned(rsaKey.ValidFrom, rsaKey.ValidFrom + TimeSpan.FromDays(90));
                _logger.LogInformation("Created new certificate with thumbprint {thumbprint}", certificate.Thumbprint);

                certificates.Add(certificate);
            }

            Directory.CreateDirectory(_options.Value.CertificatePath);
            foreach (var cert in certificates)
            {
                var bytes = cert.Export(X509ContentType.Pfx, _options.Value.CertificatePassword);
                await File.WriteAllBytesAsync(Path.Combine(_options.Value.CertificatePath, $"{cert.Thumbprint}.pfx"), bytes, ct);
                _logger.LogInformation("Wrote certificate to {path} with name {thumbprint}.pfx", _options.Value.CertificatePath, cert.Thumbprint);
            }
        }
        catch(Exception ex)
        {
            _logger.LogError(ex, "Key Migration failed with an error");
        }
    }



    public async Task<(RsaSecurityKey SecurityKey, DateTimeOffset ValidFrom)> LoadKeyAsync(string fileName)
    {
        byte[] protectedBytes;
        using (var fileStream = File.OpenRead(fileName))
        {
            protectedBytes = new byte[fileStream.Length];
            await fileStream.ReadAsync(protectedBytes, 0, protectedBytes.Length);
            _logger.LogDebug("Read {0} bytes from file {1}", protectedBytes.Length, fileName);
        }

        var plainBytes = _dataProtector.Unprotect(protectedBytes);

        var jsonText = Encoding.UTF8.GetString(plainBytes);
        var rsaParameters = System.Text.Json.JsonSerializer.Deserialize<RSAParameters>(jsonText, new System.Text.Json.JsonSerializerOptions() { IncludeFields = true});
        _logger.LogDebug("RSAParameters have been loaded {param}", rsaParameters.Exponent);

        var securityKey = new RsaSecurityKey(rsaParameters)
        {
            KeyId = Path.GetFileNameWithoutExtension(fileName)
        };

        var effectiveDateString = Path.GetFileNameWithoutExtension(Path.GetFileNameWithoutExtension(fileName));
        var keyEffectiveDate = DateTimeOffset.ParseExact(effectiveDateString, "yyyyMMddHHmmss", CultureInfo.InvariantCulture);

        return (securityKey, keyEffectiveDate);
    }


    internal class Options
    {
        public string? KeyPath { get; set; }

        public string? CertificatePath { get; set; }
        public string? CertificatePassword { get; set; }
    }
}