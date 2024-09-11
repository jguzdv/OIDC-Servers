using Dapper;

using JGUZDV.OIDC.ProtocolServer.Configuration;

using Microsoft.Data.SqlClient;
using Microsoft.Extensions.Options;
using System.Diagnostics.CodeAnalysis;
using System.Security.Claims;

namespace JGUZDV.OIDC.ProtocolServer.ClaimProviders.JGUDirectory
{
    internal class JGUDirectoryClaimProvider : IClaimProvider
    {
        public int ExecutionOrder => 100;

        private static readonly string[] AvailableClaimTypes = new[]
        {
            "idm_group",
            "idm_sex"
        };

        private readonly IOptions<ProtocolServerOptions> _options;
        private readonly ILogger<JGUDirectoryClaimProvider> _logger;
        private readonly SqlConnection _sqlConnection;

        public JGUDirectoryClaimProvider(
            IOptions<ProtocolServerOptions> options,
            ILogger<JGUDirectoryClaimProvider> logger)
        {
            _options = options;
            _logger = logger;
            _sqlConnection = new SqlConnection(options.Value.JGUDirectoryDatabaseConnectionString);
        }

        public async Task<List<Model.Claim>> GetClaimsAsync(
            ClaimsPrincipal currentUser,
            IEnumerable<Model.Claim> knownClaims,
            IEnumerable<string> claimTypes, 
            CancellationToken ct)
        {
            var processableClaimTypes = claimTypes
                .Intersect(AvailableClaimTypes)
                .ToList();

            var result = new List<Model.Claim>();

            if (!processableClaimTypes.Any())
                return result;

            var personUuidClaim = knownClaims.FirstOrDefault(x => x.Type == _options.Value.PersonIdentifierClaimType);
            if (personUuidClaim == null)
            {
                _logger.LogWarning("Could not find PersonUuid-Claim. Existing claims were: {0}", string.Join(", ", knownClaims.Select(x => $"{x.Type}: {x.Value}")));
                return result;
            }

            try
            {
                if (processableClaimTypes.Contains("idm_group"))
                {
                    result.AddRange(await GetGroupClaimsAsync(personUuidClaim.Value));
                }

                if (processableClaimTypes.Contains("idm_sex"))
                {
                    result.Add(await GetPersonSexAsync(personUuidClaim.Value));
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Could not enrich with claims from JGUDirectory.");
            }

            return result;
        }

        public bool CanProvideAnyOf(IEnumerable<string> claimTypes)
        {
            return claimTypes.Intersect(AvailableClaimTypes).Any();
        }


        private async Task<Model.Claim> GetPersonSexAsync(string personUuid)
        {
            const string queryText = "SELECT Sex " +
                "FROM [OpenId].[Persons] " +
                "WHERE PersonUuid = @personUuid";

            var personDataQueryResult = await _sqlConnection.QueryAsync<PersonQueryResult>(
                queryText,
                new { personUuid });

            return personDataQueryResult.Select(x => new Model.Claim("idm_sex", $"{x.Sex ?? 0}"))
                .FirstOrDefault() ?? new Model.Claim("idm_sex", "0");
        }

        private async Task<List<Model.Claim>> GetGroupClaimsAsync(string personUuid)
        {
            const string queryText = "SELECT StructuralUnitUuid, RoleInternalName " +
                "FROM [OpenId].[GroupMembers] " +
                "WHERE StartDate < @refDate AND (EndDate IS NULL OR EndDate > @refDate) " +
                    "AND PersonUuid = @personUuid";

            var groupResult = await _sqlConnection.QueryAsync<GroupQueryResult>(
                queryText,
                new { personUuid, refDate = DateTimeOffset.Now });

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
