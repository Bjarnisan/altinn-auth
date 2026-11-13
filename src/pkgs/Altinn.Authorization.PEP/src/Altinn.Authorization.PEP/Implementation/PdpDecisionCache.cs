using System.Diagnostics.Metrics;
using System.Security.Claims;
using System.Text.Json;
using Altinn.Authorization.ABAC.Xacml;
using Altinn.Authorization.ABAC.Xacml.JsonProfile;
using Altinn.Common.PEP.Configuration;
using Altinn.Common.PEP.Constants;
using Altinn.Common.PEP.Helpers;
using Altinn.Common.PEP.Interfaces;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Options;

namespace Altinn.Common.PEP.Implementation
{
    /// <summary>
    /// A decorator for <see cref="IPDP"/> that keeps Permit decisions in memory for
    /// <see cref="PepSettings.PdpDecisionCachingTimeout"/> minutes.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Only a request for one subject, one action and one resource with a task or end event is cached, so a Permit
    /// is reused only for the task the caller supplies. Deny, errors and null responses always go to the PDP. The
    /// key is every attribute of the subject, action and resource, so a decision is reused only for a request the
    /// PDP would see as the same, for example the same user and session when the token has a session id. The caller
    /// still validates the cached response, with its obligations, against its current user.
    /// </para>
    /// <para>
    /// Before a host turns it on: a cache hit is not sent to the PDP, so it is not in the PDP's audit log. And a
    /// right that is revoked can still be used until the entry expires. The PDP caches roles, access packages and
    /// delegations for 5 minutes and policies and access lists for 10, so the worst case is the timeout plus those.
    /// </para>
    /// </remarks>
    public sealed class PdpDecisionCache : IPDP
    {
        /// <summary>
        /// The name of the meter that counts lookups in the cache.
        /// </summary>
        public const string MeterName = "Altinn.Common.PEP";

        // The cache is the host's own, so the keys get a prefix that no other entry has.
        private const string CacheKeyPrefix = "Altinn.Common.PEP.PdpDecisionCache:";

        private static readonly Meter Meter = new(MeterName);
        private static readonly Counter<long> Lookups = Meter.CreateCounter<long>(
            "altinn.pep.pdp_decision_cache.lookups",
            description: "Decision requests to the PDP decision cache, tagged with whether the decision was found (hit), fetched (miss) or not cacheable (skipped).");

        private readonly IPDP _pdp;
        private readonly IMemoryCache _memoryCache;
        private readonly IOptions<PepSettings> _pepSettings;

        /// <summary>
        /// Initializes a new instance of the <see cref="PdpDecisionCache"/> class.
        /// </summary>
        /// <param name="pdp">The PDP that decisions not in the cache are requested from.</param>
        /// <param name="memoryCache">The cache.</param>
        /// <param name="pepSettings">The settings with the caching timeout.</param>
        public PdpDecisionCache(IPDP pdp, IMemoryCache memoryCache, IOptions<PepSettings> pepSettings)
        {
            _pdp = pdp;
            _memoryCache = memoryCache;
            _pepSettings = pepSettings;
        }

        /// <inheritdoc/>
        public Task<XacmlJsonResponse> GetDecisionForRequest(XacmlJsonRequestRoot xacmlJsonRequest)
            => GetDecisionForRequest(xacmlJsonRequest, CancellationToken.None);

        /// <inheritdoc/>
        public async Task<XacmlJsonResponse> GetDecisionForRequest(XacmlJsonRequestRoot xacmlJsonRequest, CancellationToken cancellationToken)
        {
            int timeoutMinutes = _pepSettings.Value.PdpDecisionCachingTimeout;
            if (timeoutMinutes <= 0 || !IsCacheable(xacmlJsonRequest))
            {
                Lookups.Add(1, new KeyValuePair<string, object>("result", "skipped"));
                return await _pdp.GetDecisionForRequest(xacmlJsonRequest, cancellationToken);
            }

            string cacheKey = CreateCacheKey(xacmlJsonRequest.Request);
            if (_memoryCache.TryGetValue(cacheKey, out XacmlJsonResponse cachedResponse))
            {
                Lookups.Add(1, new KeyValuePair<string, object>("result", "hit"));
                return cachedResponse;
            }

            Lookups.Add(1, new KeyValuePair<string, object>("result", "miss"));
            XacmlJsonResponse response = await _pdp.GetDecisionForRequest(xacmlJsonRequest, cancellationToken);
            if (IsSinglePermit(response))
            {
                // Size is set so that the entry can also be stored in a host's cache that has a size limit.
                _memoryCache.Set(cacheKey, response, new MemoryCacheEntryOptions
                {
                    AbsoluteExpirationRelativeToNow = TimeSpan.FromMinutes(timeoutMinutes),
                    Size = 1,
                });
            }

            return response;
        }

        /// <inheritdoc/>
        public Task<bool> GetDecisionForUnvalidateRequest(XacmlJsonRequestRoot xacmlJsonRequest, ClaimsPrincipal user)
            => GetDecisionForUnvalidateRequest(xacmlJsonRequest, user, CancellationToken.None);

        /// <inheritdoc/>
        public async Task<bool> GetDecisionForUnvalidateRequest(XacmlJsonRequestRoot xacmlJsonRequest, ClaimsPrincipal user, CancellationToken cancellationToken)
        {
            XacmlJsonResponse response = await GetDecisionForRequest(xacmlJsonRequest, cancellationToken);

            // Throws as PDPAppSI does, so that callers see the same behaviour with and without the cache.
            if (response?.Response == null)
            {
                throw new ArgumentNullException("response");
            }

            return DecisionHelper.ValidatePdpDecision(response.Response, user);
        }

        /// <summary>
        /// A request can be cached when it asks about one subject, one action and one resource, and the resource has
        /// the task or end event of the instance. Without them the PDP finds the task itself, and the decision can
        /// change when the process moves on. A request that uses parts of XACML the key leaves out, such as category
        /// ids, content or asking for more in the response, is not cached.
        /// </summary>
        private static bool IsCacheable(XacmlJsonRequestRoot xacmlJsonRequest)
        {
            XacmlJsonRequest request = xacmlJsonRequest?.Request;
            if (request == null
                || request.MultiRequests != null
                || request.ReturnPolicyIdList
                || request.CombinedDecision
                || request.AccessSubject?.Count != 1
                || request.Action?.Count != 1
                || request.Resource?.Count != 1
                || request.Category?.Count > 0
                || request.RecipientSubject?.Count > 0
                || request.IntermediarySubject?.Count > 0
                || request.RequestingMachine?.Count > 0)
            {
                return false;
            }

            XacmlJsonCategory[] categories = [request.AccessSubject[0], request.Action[0], request.Resource[0]];
            if (categories.Any(c => c.CategoryId != null || c.Content != null || c.Attribute?.Exists(a => a.IncludeInResult) == true))
            {
                return false;
            }

            return request.Resource[0].Attribute?.Exists(a =>
                (a.AttributeId == AltinnXacmlUrns.TaskId || a.AttributeId == AltinnXacmlUrns.EndEvent)
                && !string.IsNullOrWhiteSpace(a.Value)) == true;
        }

        private static bool IsSinglePermit(XacmlJsonResponse response)
        {
            return response?.Response?.Count == 1
                && response.Response[0].Decision == XacmlContextDecision.Permit.ToString();
        }

        /// <summary>
        /// Creates a key from every attribute in the subject, action and resource, sorted so that the order of the
        /// attributes does not matter. Category ids are left out. The key is JSON, so no value can be read as part
        /// of another.
        /// </summary>
        private static string CreateCacheKey(XacmlJsonRequest request)
        {
            return CacheKeyPrefix + JsonSerializer.Serialize(new[]
            {
                SortedAttributes(request.AccessSubject[0]),
                SortedAttributes(request.Action[0]),
                SortedAttributes(request.Resource[0]),
            });
        }

        private static string[][] SortedAttributes(XacmlJsonCategory category)
        {
            return (category.Attribute ?? [])
                .Select(a => new[] { a.AttributeId, a.Value, a.DataType, a.Issuer })
                .OrderBy(a => a[0], StringComparer.Ordinal)
                .ThenBy(a => a[1], StringComparer.Ordinal)
                .ThenBy(a => a[2], StringComparer.Ordinal)
                .ThenBy(a => a[3], StringComparer.Ordinal)
                .ToArray();
        }
    }
}
