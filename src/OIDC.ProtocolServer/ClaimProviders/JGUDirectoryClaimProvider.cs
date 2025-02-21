using Dapper;

using JGUZDV.OIDC.ProtocolServer.Configuration;
using JGUZDV.OIDC.ProtocolServer.Model;

using Microsoft.Data.SqlClient;
using Microsoft.Extensions.Options;

using System.Diagnostics.CodeAnalysis;
using System.Security.Claims;

using static JGUZDV.OIDC.ProtocolServer.Constants;

namespace JGUZDV.OIDC.ProtocolServer.ClaimProviders
{
    internal class JGUDirectoryClaimProvider : IClaimProvider
    {
        public ClaimType[] RequiredClaimTypes => [new(_options.Value.PersonIdentifierClaimType)];
        public ClaimType[] ProvidedClaimTypes => [.. AvailableClaimTypes];

        private static readonly ClaimType[] AvailableClaimTypes = 
        [
            new("idm_group"),
            new("idm_sex")
        ];

        private readonly IOptions<ProtocolServerOptions> _options;
        private readonly ILogger<JGUDirectoryClaimProvider> _logger;
        private readonly SqlConnection _sqlConnection;

        public JGUDirectoryClaimProvider(
            IOptions<ProtocolServerOptions> options,
            ILogger<JGUDirectoryClaimProvider> logger)
        {
            _options = options;
            _logger = logger;
            _sqlConnection = new SqlConnection(options.Value.JGUDirectory.DatabaseConnectionString);
        }


        public bool CanProvideAnyOf(IEnumerable<ClaimType> claimTypes)
        {
            return claimTypes.Intersect(AvailableClaimTypes).Any();
        }


        public async Task AddProviderClaimsToContext(ClaimProviderContext context, CancellationToken ct)
        {
            var processableClaimTypes = context.RequestedClaimTypes
                .Intersect(AvailableClaimTypes)
                .ToList();

            if (!processableClaimTypes.Any())
            {
                return;
            }

            var personUuidClaim = context.Claims.FirstOrDefault(x => x.Type == _options.Value.PersonIdentifierClaimType);
            if (personUuidClaim == null)
            {
                _logger.LogWarning("Could not find {type}. Existing claims were: {claims}", _options.Value.PersonIdentifierClaimType, string.Join(", ", context.Claims.Select(x => $"{x.Type}: {x.Value}")));
                return;
            }

            try
            {
                if (processableClaimTypes.Contains("idm_group"))
                {
                    var claims = await GetGroupClaimsAsync(personUuidClaim.Value);
                    context.AddClaims(claims);
                }

                if (processableClaimTypes.Contains("idm_sex"))
                {
                    var claim = await GetPersonSexAsync(personUuidClaim.Value);
                    context.AddClaim(claim);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Could not enrich with claims from JGUDirectory.");
            }
        }


        private async Task<Model.Claim> GetPersonSexAsync(ClaimValue personUuid)
        {
            const string queryText = "SELECT Sex " +
                "FROM [OpenId].[Persons] " +
                "WHERE PersonUuid = @personUuid";

            var personDataQueryResult = await _sqlConnection.QueryAsync<PersonQueryResult>(
                queryText,
                new { personUuid = personUuid.Value });

            return personDataQueryResult.Select(x => new Model.Claim("idm_sex", $"{x.Sex ?? 0}"))
                .FirstOrDefault() ?? new Model.Claim("idm_sex", "0");
        }

        private async Task<List<Model.Claim>> GetGroupClaimsAsync(ClaimValue personUuid)
        {
            const string queryText = "SELECT StructuralUnitUuid, RoleInternalName " +
                "FROM [OpenId].[GroupMembers] " +
                "WHERE StartDate < @refDate AND (EndDate IS NULL OR EndDate > @refDate) " +
                    "AND PersonUuid = @personUuid";

            var groupResult = await _sqlConnection.QueryAsync<GroupQueryResult>(
                queryText,
                new { 
                    personUuid = personUuid.Value, 
                    refDate = DateTimeOffset.Now 
                });

            return groupResult
                .Select(x => new Model.Claim("idm_group", $"{x.StructuralUnitUuid}:{x.RoleInternalName}"))
                .ToList();
        }


        private class GroupQueryResult
        {
            public Guid StructuralUnitUuid { get; set; }

            [NotNull]
            public string? RoleInternalName { get; set; }
        }

        private class PersonQueryResult
        {
            public int? Sex { get; set; }
        }
    }
}
