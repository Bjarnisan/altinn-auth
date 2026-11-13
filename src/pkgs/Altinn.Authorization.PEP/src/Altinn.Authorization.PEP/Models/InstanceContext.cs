#nullable enable

namespace Altinn.Common.PEP.Models
{
    /// <summary>
    /// The owner, app and process state of an app instance, read from Storage for the current request.
    /// </summary>
    /// <param name="InstanceOwnerPartyId">The party id of the instance owner, as stored on the instance.</param>
    /// <param name="AppId">The app of the instance, as stored on the instance, in the form "org/app".</param>
    /// <param name="TaskId">The id of the current task, or null when the process has no current task.</param>
    /// <param name="EndEvent">The id of the end event the process has reached, or null when it has not ended.</param>
    public sealed record InstanceContext(int InstanceOwnerPartyId, string AppId, string? TaskId, string? EndEvent);
}
