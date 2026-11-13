using System.Reflection.Metadata;
using System.Security.Claims;
using System.Text.Json;
using Altinn.AccessManagement.Core.Models;
using Altinn.Authorization.ABAC.Xacml;
using Altinn.Authorization.ABAC.Xacml.JsonProfile;
using Altinn.Common.PEP.Authorization;
using Altinn.Common.PEP.Configuration;
using Altinn.Common.PEP.Interfaces;
using Altinn.Common.PEP.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Moq;

namespace Altinn.Authorization.PEP.Tests
{
    [UnitTest]
    public class AppAccessHandlerTest
    {
        private const string InstanceOwnerPartyId = "1000";
        private static readonly Guid InstanceGuid = Guid.Parse("0f8b3f8c-9d0e-4bb4-a6a4-1a2b3c4d5e6f");

        private readonly Mock<IHttpContextAccessor> _httpContextAccessorMock;
        private readonly Mock<IPDP> _pdpMock;
        private readonly IOptions<PepSettings> _generalSettings;
        private readonly AppAccessHandler _aah;
        private readonly JsonSerializerOptions jsonOptions = new(JsonSerializerDefaults.Web);

        public AppAccessHandlerTest()
        {
            _httpContextAccessorMock = new Mock<IHttpContextAccessor>();
            _pdpMock = new Mock<IPDP>();
            _generalSettings = Options.Create(new PepSettings());
            _aah = new AppAccessHandler(_httpContextAccessorMock.Object, _pdpMock.Object, new Mock<ILogger<AppAccessHandler>>().Object);
        }

        /// <summary>
        /// Test case: Send request and get response that fulfills all requirements
        /// Expected: Context will succeed
        /// </summary>
        [Fact]
        public async Task HandleRequirementAsync_PermitDecision_Succeeds()
        {
            // Arrange 
            AuthorizationHandlerContext context = CreateAuthorizationHandlerContext();
            _httpContextAccessorMock.Setup(h => h.HttpContext).Returns(CreateHttpContext());
            XacmlJsonResponse response = CreateResponse(XacmlContextDecision.Permit.ToString());
            _pdpMock.Setup(a => a.GetDecisionForRequest(It.IsAny<XacmlJsonRequestRoot>(), It.IsAny<CancellationToken>())).Returns(Task.FromResult(response));

            // Act
            await _aah.HandleAsync(context);

            // Assert
            Assert.True(context.HasSucceeded);
            Assert.False(context.HasFailed);
        }

        /// <summary>
        /// Test case: Send request and get respons with result deny
        /// Expected: Context will fail
        /// </summary>
        [Fact]
        public async Task HandleRequirementAsync_DenyDecision_Fails()
        {
            // Arrange 
            AuthorizationHandlerContext context = CreateAuthorizationHandlerContext();
            _httpContextAccessorMock.Setup(h => h.HttpContext).Returns(CreateHttpContext());
            XacmlJsonResponse response = CreateResponse(XacmlContextDecision.Deny.ToString());
            _pdpMock.Setup(a => a.GetDecisionForRequest(It.IsAny<XacmlJsonRequestRoot>(), It.IsAny<CancellationToken>())).Returns(Task.FromResult(response));

            // Act
            await _aah.HandleAsync(context);

            // Assert
            Assert.False(context.HasSucceeded);
            Assert.True(context.HasFailed);
        }

        /// <summary>
        /// Test case: Send request and get respons with two results
        /// Expected: Context will fail
        /// </summary>
        [Fact]
        public async Task HandleRequirementAsync_MultipleResults_Fails()
        {
            // Arrange 
            AuthorizationHandlerContext context = CreateAuthorizationHandlerContext();
            _httpContextAccessorMock.Setup(h => h.HttpContext).Returns(CreateHttpContext());
            XacmlJsonResponse response = CreateResponse(XacmlContextDecision.Permit.ToString());

            // Add extra result
            response.Response.Add(new XacmlJsonResult());
            _pdpMock.Setup(a => a.GetDecisionForRequest(It.IsAny<XacmlJsonRequestRoot>(), It.IsAny<CancellationToken>())).Returns(Task.FromResult(response));

            // Act
            await _aah.HandleAsync(context);

            // Assert
            Assert.False(context.HasSucceeded);
            Assert.True(context.HasFailed);
        }

        /// <summary>
        /// Test case: Send request and get respons with obligation that contains min authentication level that the user meets
        /// Expected: context will succeed
        /// </summary>
        [Fact]
        public async Task HandleRequirementAsync_MinAuthLevelMet_Succeeds()
        {
            // Arrange 
            AuthorizationHandlerContext context = CreateAuthorizationHandlerContext();
            _httpContextAccessorMock.Setup(h => h.HttpContext).Returns(CreateHttpContext());
            XacmlJsonResponse response = CreateResponse(XacmlContextDecision.Permit.ToString());
            AddObligationWithMinAuthLv(response, "2");
            _pdpMock.Setup(a => a.GetDecisionForRequest(It.IsAny<XacmlJsonRequestRoot>(), It.IsAny<CancellationToken>())).Returns(Task.FromResult(response));

            // Act
            await _aah.HandleAsync(context);

            // Assert
            Assert.True(context.HasSucceeded);
            Assert.False(context.HasFailed);
        }

        /// <summary>
        /// Test case: Send request and get respons with obligation that contains min authentication level that the user do not meet
        /// Expected: context will fail
        /// </summary>
        [Fact]
        public async Task HandleRequirementAsync_MinAuthLevelNotMet_Fails()
        {
            // Arrange 
            AuthorizationHandlerContext context = CreateAuthorizationHandlerContext();
            _httpContextAccessorMock.Setup(h => h.HttpContext).Returns(CreateHttpContext());
            XacmlJsonResponse response = CreateResponse(XacmlContextDecision.Permit.ToString());
            AddObligationWithMinAuthLv(response, "3");
            _pdpMock.Setup(a => a.GetDecisionForRequest(It.IsAny<XacmlJsonRequestRoot>(), It.IsAny<CancellationToken>())).Returns(Task.FromResult(response));

            // Act
            await _aah.HandleAsync(context);

            // Assert
            Assert.False(context.HasSucceeded);
            Assert.True(context.HasFailed);
        }

        /// <summary>
        /// Test case: Send request and get response that is null
        /// Expected: Context will fail 
        /// </summary>
        [Fact]
        public async Task HandleRequirementAsync_NullResponse_ThrowsInvalidOperationException()
        {
            // Arrange 
            AuthorizationHandlerContext context = CreateAuthorizationHandlerContext();
            _httpContextAccessorMock.Setup(h => h.HttpContext).Returns(CreateHttpContext());
            XacmlJsonResponse response = null;
            _pdpMock.Setup(a => a.GetDecisionForRequest(It.IsAny<XacmlJsonRequestRoot>(), It.IsAny<CancellationToken>())).Returns(Task.FromResult(response));

            // Act & Assert
            await Assert.ThrowsAsync<InvalidOperationException>(() => _aah.HandleAsync(context));
        }

        /// <summary>
        /// Test case: Send request and get response with a result list that is null
        /// Expected: Context will fail 
        /// </summary>
        [Fact]
        public async Task HandleRequirementAsync_NullResultList_ThrowsInvalidOperationException()
        {
            // Arrange 
            AuthorizationHandlerContext context = CreateAuthorizationHandlerContext();
            _httpContextAccessorMock.Setup(h => h.HttpContext).Returns(CreateHttpContext());

            // Create response with a result list that is null
            XacmlJsonResponse response = new XacmlJsonResponse();
            response.Response = null;
            _pdpMock.Setup(a => a.GetDecisionForRequest(It.IsAny<XacmlJsonRequestRoot>(), It.IsAny<CancellationToken>())).Returns(Task.FromResult(response));

            // Act & Assert
            await Assert.ThrowsAsync<InvalidOperationException>(() => _aah.HandleAsync(context));
        }

        /// <summary>
        /// Test case: Send request verify if the ipaddress from the x-forwarded-for header is received
        /// Expected: XForwardedForHeader proeprty in request receives the ipaddress from the header
        /// </summary>
        [Fact]
        public async Task HandleRequirementAsync_XForwardedForHeaderPresent_Succeeds()
        {
            // Arrange 
            AuthorizationHandlerContext context = CreateAuthorizationHandlerContext();
            string ipaddress = "18.203.138.153";
            _httpContextAccessorMock.Setup(h => h.HttpContext).Returns(CreateHttpContext(ipaddress));
            XacmlJsonResponse response = CreateResponse(XacmlContextDecision.Permit.ToString());
            AddObligationWithMinAuthLv(response, "2");
            _pdpMock.Setup(a => a.GetDecisionForRequest(It.IsAny<XacmlJsonRequestRoot>(), It.IsAny<CancellationToken>())).Returns(Task.FromResult(response));

            // Act
            await _aah.HandleAsync(context);

            // Assert
            Assert.True(context.HasSucceeded);
            Assert.False(context.HasFailed);

            XacmlJsonRequestRoot request = Assert.IsType<XacmlJsonRequestRoot>(Assert.Single(_pdpMock.Invocations).Arguments[0]);

            // Known gap: even with an X-Forwarded-For header present, the PEP does not
            // copy it onto the decision request. The AppAccessRequirement overload of
            // DecisionHelper.CreateDecisionRequest is not even passed the headers, so
            // XForwardedForHeader is never set and the PDP never sees the client IP.
            // This pins current behaviour; switch to Assert.Equal(ipaddress, ...) once
            // IP forwarding is implemented.
            Assert.Null(request.Request.XForwardedForHeader);
        }

        /// <summary>
        /// Test case: Send request and get response that fulfills all requirements with system user
        /// Expected: Context will succeed
        /// </summary>
        [Fact]
        public async Task HandleRequirementAsync_SystemUserPermit_Succeeds()
        {
            // Arrange 
            AuthorizationHandlerContext context = CreateAuthorizationHandlerContextSystemUser();
            _httpContextAccessorMock.Setup(h => h.HttpContext).Returns(CreateHttpContext());
            XacmlJsonResponse response = CreateResponse(XacmlContextDecision.Permit.ToString());
            _pdpMock.Setup(a => a.GetDecisionForRequest(It.IsAny<XacmlJsonRequestRoot>(), It.IsAny<CancellationToken>())).Returns(Task.FromResult(response));

            // Act
            await _aah.HandleAsync(context);

            // Assert
            Assert.True(context.HasSucceeded);
            Assert.False(context.HasFailed);
        }

        /// <summary>
        /// Test case: Send request and get response that fulfills all requirements with app user
        /// Expected: Context will succeed
        /// </summary>
        [Fact]
        public async Task HandleRequirementAsync_AppUserPermit_Succeeds()
        {
            // Arrange 
            AuthorizationHandlerContext context = CreateAuthorizationHandlerContextAppUser("app_skd_flyttemelding");
            _httpContextAccessorMock.Setup(h => h.HttpContext).Returns(CreateHttpContext());
            XacmlJsonResponse response = CreateResponse(XacmlContextDecision.Permit.ToString());
            _pdpMock.Setup(a => a.GetDecisionForRequest(It.IsAny<XacmlJsonRequestRoot>(), It.IsAny<CancellationToken>())).Returns(Task.FromResult(response));

            // Act
            await _aah.HandleAsync(context);

            // Assert
            Assert.True(context.HasSucceeded);
            Assert.False(context.HasFailed);
        }

        /// <summary>
        /// Test case: The host has registered an instance context provider that knows the current task
        /// Expected: The provider gets the instance from the route, and the task is sent to the PDP
        /// </summary>
        [Fact]
        public async Task HandleRequirementAsync_InstanceContextProviderReturnsTask_SendsTaskToPdp()
        {
            // Arrange
            AuthorizationHandlerContext context = CreateAuthorizationHandlerContext();
            Mock<IInstanceContextProvider> providerMock = new Mock<IInstanceContextProvider>();
            providerMock
                .Setup(p => p.GetInstanceContext(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<int>(), It.IsAny<Guid>(), It.IsAny<CancellationToken>()))
                .ReturnsAsync(new InstanceContext(1000, "myOrg/myApp", "Task_1", null));
            using CancellationTokenSource cts = new CancellationTokenSource();
            HttpContext httpContext = CreateHttpContextWithInstance(InstanceOwnerPartyId, InstanceGuid.ToString(), providerMock.Object);
            httpContext.RequestAborted = cts.Token;
            _httpContextAccessorMock.Setup(h => h.HttpContext).Returns(httpContext);
            _pdpMock.Setup(a => a.GetDecisionForRequest(It.IsAny<XacmlJsonRequestRoot>(), It.IsAny<CancellationToken>())).ReturnsAsync(CreateResponse(XacmlContextDecision.Permit.ToString()));

            // Act
            await _aah.HandleAsync(context);

            // Assert
            Assert.True(context.HasSucceeded);
            providerMock.Verify(p => p.GetInstanceContext("myOrg", "myApp", 1000, InstanceGuid, cts.Token), Times.Once);
            XacmlJsonCategory resource = GetSentResource();
            Assert.Equal("Task_1", Assert.Single(resource.Attribute, a => a.AttributeId == "urn:altinn:task").Value);
            Assert.DoesNotContain(resource.Attribute, a => a.AttributeId == "urn:altinn:end-event");
        }

        /// <summary>
        /// Test case: The host has registered an instance context provider, and the process has ended
        /// Expected: The end event is sent to the PDP
        /// </summary>
        [Fact]
        public async Task HandleRequirementAsync_InstanceContextProviderReturnsEndEvent_SendsEndEventToPdp()
        {
            // Arrange
            AuthorizationHandlerContext context = CreateAuthorizationHandlerContext();
            Mock<IInstanceContextProvider> providerMock = new Mock<IInstanceContextProvider>();
            providerMock
                .Setup(p => p.GetInstanceContext(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<int>(), It.IsAny<Guid>(), It.IsAny<CancellationToken>()))
                .ReturnsAsync(new InstanceContext(1000, "myOrg/myApp", null, "EndEvent_1"));
            _httpContextAccessorMock.Setup(h => h.HttpContext).Returns(CreateHttpContextWithInstance(InstanceOwnerPartyId, InstanceGuid.ToString(), providerMock.Object));
            _pdpMock.Setup(a => a.GetDecisionForRequest(It.IsAny<XacmlJsonRequestRoot>(), It.IsAny<CancellationToken>())).ReturnsAsync(CreateResponse(XacmlContextDecision.Permit.ToString()));

            // Act
            await _aah.HandleAsync(context);

            // Assert
            Assert.True(context.HasSucceeded);
            XacmlJsonCategory resource = GetSentResource();
            Assert.Equal("EndEvent_1", Assert.Single(resource.Attribute, a => a.AttributeId == "urn:altinn:end-event").Value);
            Assert.DoesNotContain(resource.Attribute, a => a.AttributeId == "urn:altinn:task");
        }

        /// <summary>
        /// Test case: The instance context provider knows nothing about the instance
        /// Expected: The request is sent as without a provider, so the PDP looks the instance up itself
        /// </summary>
        [Fact]
        public async Task HandleRequirementAsync_InstanceContextProviderReturnsNull_SendsNoTaskOrEndEvent()
        {
            // Arrange
            AuthorizationHandlerContext context = CreateAuthorizationHandlerContext();
            Mock<IInstanceContextProvider> providerMock = new Mock<IInstanceContextProvider>();
            providerMock
                .Setup(p => p.GetInstanceContext(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<int>(), It.IsAny<Guid>(), It.IsAny<CancellationToken>()))
                .ReturnsAsync((InstanceContext)null);
            _httpContextAccessorMock.Setup(h => h.HttpContext).Returns(CreateHttpContextWithInstance(InstanceOwnerPartyId, InstanceGuid.ToString(), providerMock.Object));
            _pdpMock.Setup(a => a.GetDecisionForRequest(It.IsAny<XacmlJsonRequestRoot>(), It.IsAny<CancellationToken>())).ReturnsAsync(CreateResponse(XacmlContextDecision.Permit.ToString()));

            // Act
            await _aah.HandleAsync(context);

            // Assert
            Assert.True(context.HasSucceeded);
            providerMock.Verify(p => p.GetInstanceContext(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<int>(), It.IsAny<Guid>(), It.IsAny<CancellationToken>()), Times.Once);
            AssertNoTaskOrEndEvent(GetSentResource());
        }

        /// <summary>
        /// Test case: The instance the provider read belongs to another party or another app than the route says
        /// Expected: No task or end event is sent, so the PDP looks the instance up itself and denies as before
        /// </summary>
        [Theory]
        [InlineData(1001, "myOrg/myApp")]
        [InlineData(1000, "myOrg/otherApp")]
        [InlineData(1000, "otherOrg/myApp")]
        [InlineData(1000, "MYORG/myApp")]
        public async Task HandleRequirementAsync_InstanceBelongsToAnotherPartyOrApp_SendsNoTaskOrEndEvent(int instanceOwnerPartyId, string appId)
        {
            // Arrange
            AuthorizationHandlerContext context = CreateAuthorizationHandlerContext();
            Mock<IInstanceContextProvider> providerMock = new Mock<IInstanceContextProvider>();
            providerMock
                .Setup(p => p.GetInstanceContext(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<int>(), It.IsAny<Guid>(), It.IsAny<CancellationToken>()))
                .ReturnsAsync(new InstanceContext(instanceOwnerPartyId, appId, "Task_1", null));
            _httpContextAccessorMock.Setup(h => h.HttpContext).Returns(CreateHttpContextWithInstance(InstanceOwnerPartyId, InstanceGuid.ToString(), providerMock.Object));
            _pdpMock.Setup(a => a.GetDecisionForRequest(It.IsAny<XacmlJsonRequestRoot>(), It.IsAny<CancellationToken>())).ReturnsAsync(CreateResponse(XacmlContextDecision.Deny.ToString()));

            // Act
            await _aah.HandleAsync(context);

            // Assert
            Assert.True(context.HasFailed);
            AssertNoTaskOrEndEvent(GetSentResource());
        }

        /// <summary>
        /// Test case: The route has an instance, but no org or app
        /// Expected: The provider is not asked, since the instance cannot be checked against the app
        /// </summary>
        [Theory]
        [InlineData("org")]
        [InlineData("app")]
        public async Task HandleRequirementAsync_RouteWithoutOrgOrApp_DoesNotCallInstanceContextProvider(string missing)
        {
            // Arrange
            AuthorizationHandlerContext context = CreateAuthorizationHandlerContext();
            Mock<IInstanceContextProvider> providerMock = new Mock<IInstanceContextProvider>();
            HttpContext httpContext = CreateHttpContextWithInstance(InstanceOwnerPartyId, InstanceGuid.ToString(), providerMock.Object);
            httpContext.Request.RouteValues.Remove(missing);
            _httpContextAccessorMock.Setup(h => h.HttpContext).Returns(httpContext);
            _pdpMock.Setup(a => a.GetDecisionForRequest(It.IsAny<XacmlJsonRequestRoot>(), It.IsAny<CancellationToken>())).ReturnsAsync(CreateResponse(XacmlContextDecision.Permit.ToString()));

            // Act
            await _aah.HandleAsync(context);

            // Assert
            providerMock.VerifyNoOtherCalls();
            AssertNoTaskOrEndEvent(GetSentResource());
        }

        /// <summary>
        /// Test case: The host has a service provider, but no instance context provider in it
        /// Expected: The request is sent as before
        /// </summary>
        [Fact]
        public async Task HandleRequirementAsync_NoInstanceContextProvider_SendsNoTaskOrEndEvent()
        {
            // Arrange
            AuthorizationHandlerContext context = CreateAuthorizationHandlerContext();
            _httpContextAccessorMock.Setup(h => h.HttpContext).Returns(CreateHttpContextWithInstance(InstanceOwnerPartyId, InstanceGuid.ToString(), null));
            _pdpMock.Setup(a => a.GetDecisionForRequest(It.IsAny<XacmlJsonRequestRoot>(), It.IsAny<CancellationToken>())).ReturnsAsync(CreateResponse(XacmlContextDecision.Permit.ToString()));

            // Act
            await _aah.HandleAsync(context);

            // Assert
            Assert.True(context.HasSucceeded);
            AssertNoTaskOrEndEvent(GetSentResource());
        }

        /// <summary>
        /// Test case: The route does not identify an instance, as when a new instance is created
        /// Expected: The provider is not asked, and the request is sent as before
        /// </summary>
        [Theory]
        [InlineData(null, null)]
        [InlineData(InstanceOwnerPartyId, null)]
        [InlineData("notANumber", "0f8b3f8c-9d0e-4bb4-a6a4-1a2b3c4d5e6f")]
        [InlineData(InstanceOwnerPartyId, "notAGuid")]
        public async Task HandleRequirementAsync_RouteWithoutInstance_DoesNotCallInstanceContextProvider(string instanceOwnerPartyId, string instanceGuid)
        {
            // Arrange
            AuthorizationHandlerContext context = CreateAuthorizationHandlerContext();
            Mock<IInstanceContextProvider> providerMock = new Mock<IInstanceContextProvider>();
            _httpContextAccessorMock.Setup(h => h.HttpContext).Returns(CreateHttpContextWithInstance(instanceOwnerPartyId, instanceGuid, providerMock.Object));
            _pdpMock.Setup(a => a.GetDecisionForRequest(It.IsAny<XacmlJsonRequestRoot>(), It.IsAny<CancellationToken>())).ReturnsAsync(CreateResponse(XacmlContextDecision.Permit.ToString()));

            // Act
            await _aah.HandleAsync(context);

            // Assert
            Assert.True(context.HasSucceeded);
            providerMock.VerifyNoOtherCalls();
            AssertNoTaskOrEndEvent(GetSentResource());
        }

        /// <summary>
        /// Test case: The instance context provider fails
        /// Expected: The exception is not swallowed, and no decision is requested without the task
        /// </summary>
        [Fact]
        public async Task HandleRequirementAsync_InstanceContextProviderThrows_ThrowsWithoutCallingPdp()
        {
            // Arrange
            AuthorizationHandlerContext context = CreateAuthorizationHandlerContext();
            Mock<IInstanceContextProvider> providerMock = new Mock<IInstanceContextProvider>();
            providerMock
                .Setup(p => p.GetInstanceContext(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<int>(), It.IsAny<Guid>(), It.IsAny<CancellationToken>()))
                .ThrowsAsync(new HttpRequestException("Storage is unavailable"));
            _httpContextAccessorMock.Setup(h => h.HttpContext).Returns(CreateHttpContextWithInstance(InstanceOwnerPartyId, InstanceGuid.ToString(), providerMock.Object));

            // Act & Assert
            await Assert.ThrowsAsync<HttpRequestException>(() => _aah.HandleAsync(context));
            _pdpMock.VerifyNoOtherCalls();
        }

        private static HttpContext CreateHttpContextWithInstance(string instanceOwnerPartyId, string instanceGuid, IInstanceContextProvider provider)
        {
            ServiceCollection services = new ServiceCollection();
            if (provider != null)
            {
                services.AddSingleton(provider);
            }

            HttpContext httpContext = new DefaultHttpContext { RequestServices = services.BuildServiceProvider() };
            httpContext.Request.RouteValues.Add("org", "myOrg");
            httpContext.Request.RouteValues.Add("app", "myApp");
            httpContext.Request.RouteValues.Add("instanceOwnerPartyId", instanceOwnerPartyId);
            httpContext.Request.RouteValues.Add("instanceGuid", instanceGuid);

            return httpContext;
        }

        private XacmlJsonCategory GetSentResource()
        {
            XacmlJsonRequestRoot request = Assert.IsType<XacmlJsonRequestRoot>(Assert.Single(_pdpMock.Invocations).Arguments[0]);
            return Assert.Single(request.Request.Resource);
        }

        private static void AssertNoTaskOrEndEvent(XacmlJsonCategory resource)
        {
            Assert.DoesNotContain(resource.Attribute, a => a.AttributeId == "urn:altinn:task" || a.AttributeId == "urn:altinn:end-event");
        }

        private ClaimsPrincipal CreateUser()
        {
            // Create the user
            List<Claim> claims = new List<Claim>();

            // type, value, valuetype, issuer
            claims.Add(new Claim("urn:name", "Ola", "string", "org"));
            claims.Add(new Claim("urn:altinn:authlevel", "2", "string", "org"));

            ClaimsPrincipal user = new ClaimsPrincipal(new ClaimsIdentity(claims));

            return user;
        }

        private ClaimsPrincipal CreateSystemUser()
        {
            SystemUserClaim systemUserClaim = new SystemUserClaim
            {
                Systemuser_id = new List<string>() { "996a686f-d24d-4d92-a92e-5b3cec4a8cf7" },
                Systemuser_org = new OrgClaim() { ID = "myOrg" },
                System_id = "the_matrix"
            };

            List<Claim> claims = new List<Claim>();
            claims.Add(new Claim("authorization_details", JsonSerializer.Serialize(systemUserClaim, jsonOptions), "string", "org"));
            ClaimsPrincipal user = new ClaimsPrincipal(new ClaimsIdentity(claims));

            return user;
        }

        private ClaimsPrincipal CreateAppUser(string appId)
        {
            List<Claim> claims = new List<Claim>();
            claims.Add(new Claim("urn:altinn:resource", appId, "string", "org"));
            ClaimsPrincipal user = new ClaimsPrincipal(new ClaimsIdentity(claims));
            return user;
        }

        private HttpContext CreateHttpContext()
        {
            HttpContext httpContext = new DefaultHttpContext();
            httpContext.Request.RouteValues.Add("org", "myOrg");
            httpContext.Request.RouteValues.Add("app", "myApp");
            httpContext.Request.RouteValues.Add("instanceGuid", "asdfg");
            httpContext.Request.RouteValues.Add("InstanceOwnerId", "1000");

            return httpContext;
        }

        private HttpContext CreateHttpContext(string xForwardedForHeader)
        {
            HttpContext httpContext = new DefaultHttpContext();
            httpContext.Request.RouteValues.Add("org", "myOrg");
            httpContext.Request.RouteValues.Add("app", "myApp");
            httpContext.Request.RouteValues.Add("instanceGuid", "asdfg");
            httpContext.Request.RouteValues.Add("InstanceOwnerId", "1000");

            if (!string.IsNullOrEmpty(xForwardedForHeader))
            {
                httpContext.Request.Headers["x-forwarded-for"] = xForwardedForHeader;
            }

            return httpContext;
        }

        private XacmlJsonResponse CreateResponse(string decision)
        {
            // Create response 
            XacmlJsonResponse response = new XacmlJsonResponse();
            response.Response = new List<XacmlJsonResult>();

            // Set result to premit
            XacmlJsonResult result = new XacmlJsonResult();
            result.Decision = decision;
            response.Response.Add(result);

            return response;
        }

        private XacmlJsonResponse AddObligationWithMinAuthLv(XacmlJsonResponse response, string minAuthLv)
        {
            // Add obligation to result with a minimum authentication level attribute
            XacmlJsonResult result = response.Response[0];
            XacmlJsonObligationOrAdvice obligation = new XacmlJsonObligationOrAdvice();
            obligation.AttributeAssignment = new List<XacmlJsonAttributeAssignment>();
            XacmlJsonAttributeAssignment authenticationAttribute = new XacmlJsonAttributeAssignment()
            {
                Category = "urn:altinn:minimum-authenticationlevel",
                Value = minAuthLv
            };
            obligation.AttributeAssignment.Add(authenticationAttribute);
            result.Obligations = new List<XacmlJsonObligationOrAdvice>();
            result.Obligations.Add(obligation);

            return response;
        }

        private AuthorizationHandlerContext CreateAuthorizationHandlerContext()
        {
            AppAccessRequirement requirement = new AppAccessRequirement("read");
            ClaimsPrincipal user = CreateUser();
            Document resource = default(Document);
            AuthorizationHandlerContext context = new AuthorizationHandlerContext(
                new[] { requirement },
                user,
                resource);
            return context;
        }

        private AuthorizationHandlerContext CreateAuthorizationHandlerContextSystemUser()
        {
            AppAccessRequirement requirement = new AppAccessRequirement("read");
            ClaimsPrincipal user = CreateSystemUser();
            Document resource = default(Document);
            AuthorizationHandlerContext context = new AuthorizationHandlerContext(
                new[] { requirement },
                user,
                resource);
            return context;
        }

        private AuthorizationHandlerContext CreateAuthorizationHandlerContextAppUser(string appId)
        {
            AppAccessRequirement requirement = new AppAccessRequirement("read");
            ClaimsPrincipal user = CreateAppUser(appId);
            Document resource = default(Document);
            AuthorizationHandlerContext context = new AuthorizationHandlerContext(
                new[] { requirement },
                user,
                resource);
            return context;
        }
    }
}
