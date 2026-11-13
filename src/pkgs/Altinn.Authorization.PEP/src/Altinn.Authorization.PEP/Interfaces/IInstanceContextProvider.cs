#nullable enable

using Altinn.Common.PEP.Authorization;
using Altinn.Common.PEP.Models;

namespace Altinn.Common.PEP.Interfaces
{
    /// <summary>
    /// Provides the process state of an app instance, so that <see cref="AppAccessHandler"/> can send the
    /// current task or end event to the PDP. A host enables it by registering an implementation in its service
    /// collection. Without one, the PDP looks the instance up in Storage itself.
    /// </summary>
    /// <remarks>
    /// When the request has a task or end event, the PDP no longer looks the instance up, so it no longer checks
    /// that the instance exists and belongs to the party and app in the route. <see cref="AppAccessHandler"/> does
    /// that check with the owner and app the provider returns, so they must come from the stored instance, read
    /// for this request. Return null when the instance does not exist.
    /// </remarks>
    public interface IInstanceContextProvider
    {
        /// <summary>
        /// Gets the owner, app and current task or end event of an instance.
        /// </summary>
        /// <param name="org">The org from the route.</param>
        /// <param name="app">The app from the route.</param>
        /// <param name="instanceOwnerPartyId">The party id of the instance owner, from the route.</param>
        /// <param name="instanceGuid">The id of the instance.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/>.</param>
        /// <returns>The instance context, or null when it is not known, for example because the instance does not exist.</returns>
        Task<InstanceContext?> GetInstanceContext(string org, string app, int instanceOwnerPartyId, Guid instanceGuid, CancellationToken cancellationToken);
    }
}
