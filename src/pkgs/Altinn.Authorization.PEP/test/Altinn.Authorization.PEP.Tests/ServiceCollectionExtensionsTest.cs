using System.Diagnostics.Metrics;
using System.Net;
using System.Security.Claims;
using System.Text;

using Altinn.Authorization.ABAC.Xacml;
using Altinn.Authorization.ABAC.Xacml.JsonProfile;
using Altinn.Authorization.PEP.Extensions;
using Altinn.Common.PEP.Clients;
using Altinn.Common.PEP.Configuration;
using Altinn.Common.PEP.Implementation;
using Altinn.Common.PEP.Interfaces;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace Altinn.Authorization.PEP.Tests
{
    [UnitTest]
    [Collection(nameof(PdpDecisionCache))]
    public class ServiceCollectionExtensionsTest
    {
        /// <summary>
        /// Test case: An IPDP is registered as an instance, a type or a factory before the cache is added
        /// Expected: The cache wraps it and keeps its lifetime
        /// </summary>
        [Theory]
        [InlineData("instance", ServiceLifetime.Singleton)]
        [InlineData("type", ServiceLifetime.Scoped)]
        [InlineData("factory", ServiceLifetime.Transient)]
        public async Task AddAltinnPdpDecisionCache_IPdpRegisteredBefore_WrapsIt(string registration, ServiceLifetime lifetime)
        {
            // Arrange
            ServiceCollection services = new ServiceCollection();
            FakePdp.Calls = 0;
            switch (registration)
            {
                case "instance":
                    services.AddSingleton<IPDP>(new FakePdp());
                    break;
                case "type":
                    services.AddScoped<IPDP, FakePdp>();
                    break;
                default:
                    services.AddTransient<IPDP>(_ => new FakePdp());
                    break;
            }

            // Act
            services.AddAltinnPdpDecisionCache();
            using ServiceProvider provider = services.BuildServiceProvider();
            using IServiceScope scope = provider.CreateScope();
            IPDP pdp = scope.ServiceProvider.GetRequiredService<IPDP>();
            XacmlJsonResponse response = await pdp.GetDecisionForRequest(new XacmlJsonRequestRoot { Request = new XacmlJsonRequest() }, TestContext.Current.CancellationToken);

            // Assert
            Assert.IsType<PdpDecisionCache>(pdp);
            Assert.Equal(lifetime, Assert.Single(services, d => d.ServiceType == typeof(IPDP)).Lifetime);
            Assert.Equal(XacmlContextDecision.Permit.ToString(), response.Response[0].Decision);
            Assert.Equal(1, FakePdp.Calls);
        }

        /// <summary>
        /// Test case: The cache is added before the host registers its IPDP with TryAdd, as in Altinn apps, where
        /// custom services are registered before the app library's
        /// Expected: The cache wraps a PDPAppSI, which calls the authorization API, and the later TryAdd does nothing
        /// </summary>
        [Fact]
        public async Task AddAltinnPdpDecisionCache_NoIPdpRegistered_WrapsPdpAppSI()
        {
            // Arrange
            CountingHandler handler = new CountingHandler();
            ServiceCollection services = new ServiceCollection();
            services.AddLogging();
            services.AddSingleton(new AuthorizationApiClient(
                new HttpContextAccessor(),
                new HttpClient(handler),
                Options.Create(new PlatformSettings { ApiAuthorizationEndpoint = "http://localhost/authorization/api/v1/" }),
                NullLogger<AuthorizationApiClient>.Instance));

            // Act
            services.AddAltinnPdpDecisionCache();
            services.TryAddTransient<IPDP, FakePdp>();
            using ServiceProvider provider = services.BuildServiceProvider();
            IPDP pdp = provider.GetRequiredService<IPDP>();
            await pdp.GetDecisionForRequest(new XacmlJsonRequestRoot { Request = new XacmlJsonRequest() }, TestContext.Current.CancellationToken);

            // Assert
            Assert.IsType<PdpDecisionCache>(pdp);
            Assert.Equal(1, handler.Calls);
        }

        /// <summary>
        /// Test case: The cache is added twice
        /// Expected: The IPDP is wrapped once, so a request is looked up in the cache once
        /// </summary>
        [Fact]
        public async Task AddAltinnPdpDecisionCache_CalledTwice_WrapsOnce()
        {
            // Arrange
            ServiceCollection services = new ServiceCollection();
            services.AddSingleton<IPDP>(new FakePdp());
            List<string> results = [];
            using MeterListener listener = new MeterListener();
            listener.InstrumentPublished = (instrument, l) =>
            {
                if (instrument.Meter.Name == PdpDecisionCache.MeterName)
                {
                    l.EnableMeasurementEvents(instrument);
                }
            };
            listener.SetMeasurementEventCallback<long>((_, _, tags, _) => results.Add((string)tags.ToArray().Single(t => t.Key == "result").Value));
            listener.Start();

            // Act
            services.AddAltinnPdpDecisionCache();
            services.AddAltinnPdpDecisionCache();
            using ServiceProvider provider = services.BuildServiceProvider();
            await provider.GetRequiredService<IPDP>().GetDecisionForRequest(new XacmlJsonRequestRoot { Request = new XacmlJsonRequest() }, TestContext.Current.CancellationToken);
            listener.Dispose();

            // Assert
            Assert.Equal(["skipped"], results);
        }

        private sealed class FakePdp : IPDP
        {
            public static int Calls { get; set; }

            public Task<XacmlJsonResponse> GetDecisionForRequest(XacmlJsonRequestRoot xacmlJsonRequest)
                => GetDecisionForRequest(xacmlJsonRequest, CancellationToken.None);

            public Task<XacmlJsonResponse> GetDecisionForRequest(XacmlJsonRequestRoot xacmlJsonRequest, CancellationToken cancellationToken)
            {
                Calls++;
                return Task.FromResult(new XacmlJsonResponse { Response = [new XacmlJsonResult { Decision = XacmlContextDecision.Permit.ToString() }] });
            }

            public Task<bool> GetDecisionForUnvalidateRequest(XacmlJsonRequestRoot xacmlJsonRequest, ClaimsPrincipal user)
                => throw new NotSupportedException();

            public Task<bool> GetDecisionForUnvalidateRequest(XacmlJsonRequestRoot xacmlJsonRequest, ClaimsPrincipal user, CancellationToken cancellationToken)
                => throw new NotSupportedException();
        }

        private sealed class CountingHandler : HttpMessageHandler
        {
            public int Calls { get; private set; }

            protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
            {
                Calls++;
                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new StringContent("""{"response":[{"decision":"Permit"}]}""", Encoding.UTF8, "application/json"),
                });
            }
        }
    }
}
