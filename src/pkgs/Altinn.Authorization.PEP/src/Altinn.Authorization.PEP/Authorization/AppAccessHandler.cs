using Altinn.Authorization.ABAC.Xacml.JsonProfile;
using Altinn.Common.PEP.Helpers;
using Altinn.Common.PEP.Interfaces;
using Altinn.Common.PEP.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace Altinn.Common.PEP.Authorization
{
    /// <summary>
    /// AuthorizationHandler that is created for handling access to app.
    /// Authorizes based om AppAccessRequirement and app id from route
    /// <see href="https://docs.asp.net/en/latest/security/authorization/policies.html"/> for details about authorization
    /// in asp.net core
    /// </summary>
    public class AppAccessHandler : AuthorizationHandler<AppAccessRequirement>
    {
        private readonly IHttpContextAccessor _httpContextAccessor;
        private readonly IPDP _pdp;
        private readonly ILogger _logger;

        /// <summary>
        /// Initializes a new instance of the <see cref="AppAccessHandler"/> class.
        /// </summary>
        /// <param name="httpContextAccessor">The http context accessor</param>
        /// <param name="pdp">The pdp</param>
        /// <param name="logger">The logger. </param>
        public AppAccessHandler(
            IHttpContextAccessor httpContextAccessor,
            IPDP pdp,
            ILogger<AppAccessHandler> logger)
        {
            _httpContextAccessor = httpContextAccessor;
            _pdp = pdp;
            _logger = logger;
        }

        /// <summary>
        /// This method authorize access bases on context and requirement
        /// Is triggered by annotation on MVC action and setup in startup.
        /// </summary>
        /// <param name="context">The context</param>
        /// <param name="requirement">The requirement</param>
        /// <returns>A Task</returns>
        protected override async Task HandleRequirementAsync(AuthorizationHandlerContext context, AppAccessRequirement requirement)
        {
            HttpContext httpContext = _httpContextAccessor.HttpContext;
            RouteData routeData = httpContext.GetRouteData();

            InstanceContext instanceContext = await GetInstanceContext(httpContext, routeData);
            XacmlJsonRequestRoot request = DecisionHelper.CreateDecisionRequest(context, requirement, routeData, instanceContext);

            XacmlJsonResponse response = await _pdp.GetDecisionForRequest(request, httpContext.RequestAborted);

            if (response?.Response == null)
            {
                throw new InvalidOperationException("PDP returned null-response");
            }

            if (!DecisionHelper.ValidatePdpDecision(response.Response, context.User))
            {
                context.Fail();
            }

            context.Succeed(requirement);
        }

        /// <summary>
        /// Gets the process state of the instance in the route from the host's <see cref="IInstanceContextProvider"/>.
        /// The provider is resolved per request, because this handler is often registered as a singleton.
        /// </summary>
        /// <param name="httpContext">The current <see cref="HttpContext"/>.</param>
        /// <param name="routeData">The route data from the request.</param>
        /// <returns>
        /// The instance context, or null when there is no provider, no instance in the route, nothing known about it,
        /// or an instance that does not belong to the party and app in the route.
        /// </returns>
        private static async Task<InstanceContext> GetInstanceContext(HttpContext httpContext, RouteData routeData)
        {
            IInstanceContextProvider provider = httpContext.RequestServices?.GetService<IInstanceContextProvider>();
            if (provider == null)
            {
                return null;
            }

            DecisionHelper.AppRouteValues route = DecisionHelper.GetAppRouteValues(routeData);
            if (string.IsNullOrEmpty(route.Org)
                || string.IsNullOrEmpty(route.App)
                || !int.TryParse(route.InstanceOwnerPartyId, out int instanceOwnerPartyId)
                || !Guid.TryParse(route.InstanceGuid, out Guid instanceGuid))
            {
                return null;
            }

            InstanceContext instanceContext = await provider.GetInstanceContext(route.Org, route.App, instanceOwnerPartyId, instanceGuid, httpContext.RequestAborted);

            // With a task or end event the PDP does not look the instance up, so it no longer checks that the instance
            // belongs to the party and app in the route. When it does not, leave the lookup, and the denial, to the PDP.
            if (instanceContext == null
                || instanceContext.InstanceOwnerPartyId != instanceOwnerPartyId
                || instanceContext.AppId != $"{route.Org}/{route.App}")
            {
                return null;
            }

            return instanceContext;
        }
    }
}
