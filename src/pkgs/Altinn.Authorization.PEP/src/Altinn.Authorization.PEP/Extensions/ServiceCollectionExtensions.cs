using Altinn.Common.PEP.Authorization;
using Altinn.Common.PEP.Configuration;
using Altinn.Common.PEP.Implementation;
using Altinn.Common.PEP.Interfaces;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;

namespace Altinn.Authorization.PEP.Extensions;

/// <summary>
/// Provides extension methods for registering Altinn-specific authorization services.
/// Must be called atleast once if registering using extensions methods from <see cref="AuthorizationBuilderExtensions"/>.
/// </summary>
public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Adds authorization handlers required for Altinn PEP (Policy Enforcement Point).
    /// Registers handlers for claim-based, resource-based, and scope-based access control.
    /// <see cref="ClaimAccessHandler"/>, <see cref="ResourceAccessHandler"/> and <see cref="ResourceAccessHandler"/>
    /// </summary>
    public static IServiceCollection AddAltinnPEP(this IServiceCollection services)
    {
        services.TryAddScoped<IAuthorizationHandler, ClaimAccessHandler>();
        services.TryAddScoped<IAuthorizationHandler, ResourceAccessHandler>();
        services.TryAddScoped<IAuthorizationHandler, ScopeAccessHandler>();
        return services;
    }

    /// <summary>
    /// Wraps the registered <see cref="IPDP"/> in a <see cref="PdpDecisionCache"/>, which keeps Permit decisions for
    /// <see cref="PepSettings.PdpDecisionCachingTimeout"/> minutes. The cache is off while the timeout is 0, the default.
    /// When no <see cref="IPDP"/> is registered yet, it wraps a <see cref="PDPAppSI"/>, and a later TryAdd of
    /// <see cref="IPDP"/> does nothing; a later Add or Replace removes the cache. Calling it again does nothing.
    /// Read the remarks on <see cref="PdpDecisionCache"/> about the audit log and revoked rights before setting a timeout.
    /// </summary>
    public static IServiceCollection AddAltinnPdpDecisionCache(this IServiceCollection services)
    {
        if (services.Any(d => d.ServiceType == typeof(PdpDecisionCacheRegistered)))
        {
            return services;
        }

        services.AddSingleton<PdpDecisionCacheRegistered>();
        services.AddMemoryCache();
        services.AddOptions<PepSettings>();

        ServiceDescriptor registered = services.LastOrDefault(d => d.ServiceType == typeof(IPDP) && !d.IsKeyedService);
        Func<IServiceProvider, IPDP> createPdp = registered switch
        {
            null => sp => ActivatorUtilities.CreateInstance<PDPAppSI>(sp),
            { ImplementationInstance: IPDP instance } => _ => instance,
            { ImplementationFactory: { } factory } => sp => (IPDP)factory(sp),
            _ => sp => (IPDP)ActivatorUtilities.CreateInstance(sp, registered.ImplementationType),
        };

        services.RemoveAll<IPDP>();
        services.Add(new ServiceDescriptor(
            typeof(IPDP),
            sp => new PdpDecisionCache(createPdp(sp), sp.GetRequiredService<IMemoryCache>(), sp.GetRequiredService<IOptions<PepSettings>>()),
            registered?.Lifetime ?? ServiceLifetime.Transient));

        return services;
    }

    /// <summary>
    /// Marks that <see cref="AddAltinnPdpDecisionCache"/> has wrapped the <see cref="IPDP"/>, so it is not wrapped twice.
    /// </summary>
    private sealed class PdpDecisionCacheRegistered;
}
