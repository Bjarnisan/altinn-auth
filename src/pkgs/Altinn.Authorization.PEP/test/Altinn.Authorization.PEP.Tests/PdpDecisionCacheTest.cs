using System.Diagnostics.Metrics;
using System.Security.Claims;

using Altinn.Authorization.ABAC.Xacml;
using Altinn.Authorization.ABAC.Xacml.JsonProfile;
using Altinn.Common.PEP.Configuration;
using Altinn.Common.PEP.Implementation;
using Altinn.Common.PEP.Interfaces;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Internal;
using Microsoft.Extensions.Options;

using Moq;

namespace Altinn.Authorization.PEP.Tests
{
    /// <summary>
    /// Tests of <see cref="PdpDecisionCache"/>. The tests that create one are in the same collection, so that they do
    /// not run in parallel and the meter test sees only its own measurements.
    /// </summary>
    [UnitTest]
    [Collection(nameof(PdpDecisionCache))]
    public class PdpDecisionCacheTest
    {
        private const string TaskId = "urn:altinn:task";
        private const string EndEvent = "urn:altinn:end-event";

        private readonly Mock<IPDP> _pdpMock = new Mock<IPDP>();
        private readonly TestClock _clock = new TestClock();
        private readonly PepSettings _pepSettings = new PepSettings { PdpDecisionCachingTimeout = 5 };
        private readonly PdpDecisionCache _cache;

        public PdpDecisionCacheTest()
        {
            _cache = new PdpDecisionCache(
                _pdpMock.Object,
                new MemoryCache(new MemoryCacheOptions { Clock = _clock }),
                Options.Create(_pepSettings));
        }

        /// <summary>
        /// Test case: The same request with a task or an end event is sent twice, and the PDP permits it
        /// Expected: The PDP is asked once, and the second call gets the same decision from the cache
        /// </summary>
        [Theory]
        [InlineData(TaskId, "Task_1")]
        [InlineData(EndEvent, "EndEvent_1")]
        public async Task GetDecisionForRequest_PermitForInstanceInTaskOrEnded_AsksPdpOnce(string attributeId, string value)
        {
            // Arrange
            XacmlJsonResponse permit = CreateResponse(XacmlContextDecision.Permit.ToString());
            SetupPdp(permit);

            // Act
            XacmlJsonResponse first = await _cache.GetDecisionForRequest(CreateRequest(processAttribute: (attributeId, value)), TestContext.Current.CancellationToken);
            XacmlJsonResponse second = await _cache.GetDecisionForRequest(CreateRequest(processAttribute: (attributeId, value)), TestContext.Current.CancellationToken);

            // Assert
            Assert.Same(permit, first);
            Assert.Same(permit, second);
            Assert.Single(_pdpMock.Invocations);
        }

        /// <summary>
        /// Test case: The request has no task or end event, or one without a value
        /// Expected: The decision is not cached, since the PDP finds the task itself and it can change
        /// </summary>
        [Theory]
        [InlineData(null, null)]
        [InlineData(TaskId, "")]
        [InlineData(EndEvent, " ")]
        public async Task GetDecisionForRequest_WithoutTaskOrEndEvent_AsksPdpEveryTime(string attributeId, string value)
        {
            // Arrange
            SetupPdp(CreateResponse(XacmlContextDecision.Permit.ToString()));
            (string, string)? processAttribute = attributeId == null ? null : (attributeId, value);

            // Act
            await _cache.GetDecisionForRequest(CreateRequest(processAttribute: processAttribute), TestContext.Current.CancellationToken);
            await _cache.GetDecisionForRequest(CreateRequest(processAttribute: processAttribute), TestContext.Current.CancellationToken);

            // Assert
            Assert.Equal(2, _pdpMock.Invocations.Count);
        }

        /// <summary>
        /// Test case: The PDP answers with something other than a single Permit
        /// Expected: The answer is not cached, so the next request goes to the PDP
        /// </summary>
        [Theory]
        [InlineData("Deny", 1)]
        [InlineData("NotApplicable", 1)]
        [InlineData("Indeterminate", 1)]
        [InlineData("Permit", 2)]
        [InlineData(null, 0)]
        public async Task GetDecisionForRequest_NotASinglePermit_AsksPdpEveryTime(string decision, int resultCount)
        {
            // Arrange
            XacmlJsonResponse response = resultCount == 0 ? null : CreateResponse(decision);
            for (int i = 1; i < resultCount; i++)
            {
                response.Response.Add(new XacmlJsonResult { Decision = decision });
            }

            SetupPdp(response);

            // Act
            await _cache.GetDecisionForRequest(CreateRequest(), TestContext.Current.CancellationToken);
            await _cache.GetDecisionForRequest(CreateRequest(), TestContext.Current.CancellationToken);

            // Assert
            Assert.Equal(2, _pdpMock.Invocations.Count);
        }

        /// <summary>
        /// Test case: The second request differs from the first in one attribute
        /// Expected: The cached decision is not used, so another user, session, action, instance or task asks the PDP
        /// </summary>
        [Theory]
        [InlineData("subject", "urn:altinn:userid", "1338")]
        [InlineData("subject", "urn:altinn:sessionid", "another-session")]
        [InlineData("subject", "urn:altinn:authlevel", "3")]
        [InlineData("action", "urn:oasis:names:tc:xacml:1.0:action:action-id", "write")]
        [InlineData("resource", "urn:altinn:instance-id", "1000/26a6f9dd-7f6d-4a83-8b4c-2b5c1d2e3f40")]
        [InlineData("resource", TaskId, "Task_2")]
        public async Task GetDecisionForRequest_RequestDiffersInOneAttribute_AsksPdpAgain(string category, string attributeId, string value)
        {
            // Arrange
            SetupPdp(CreateResponse(XacmlContextDecision.Permit.ToString()));
            XacmlJsonRequestRoot other = CreateRequest();
            XacmlJsonCategory otherCategory = category switch
            {
                "subject" => other.Request.AccessSubject[0],
                "action" => other.Request.Action[0],
                _ => other.Request.Resource[0],
            };
            otherCategory.Attribute.Single(a => a.AttributeId == attributeId).Value = value;

            // Act
            await _cache.GetDecisionForRequest(CreateRequest(), TestContext.Current.CancellationToken);
            await _cache.GetDecisionForRequest(other, TestContext.Current.CancellationToken);

            // Assert
            Assert.Equal(2, _pdpMock.Invocations.Count);
        }

        /// <summary>
        /// Test case: The second request has the same attributes in another order, and other category ids
        /// Expected: The cached decision is used
        /// </summary>
        [Fact]
        public async Task GetDecisionForRequest_SameAttributesInAnotherOrder_UsesCachedDecision()
        {
            // Arrange
            SetupPdp(CreateResponse(XacmlContextDecision.Permit.ToString()));
            XacmlJsonRequestRoot reordered = CreateRequest();
            reordered.Request.AccessSubject[0].Attribute.Reverse();
            reordered.Request.Resource[0].Attribute.Reverse();
            reordered.Request.Resource[0].Id = "r1";

            // Act
            await _cache.GetDecisionForRequest(CreateRequest(), TestContext.Current.CancellationToken);
            await _cache.GetDecisionForRequest(reordered, TestContext.Current.CancellationToken);

            // Assert
            Assert.Single(_pdpMock.Invocations);
        }

        /// <summary>
        /// Test case: One attribute value contains the separators a plain string key would use
        /// Expected: It does not match a request with the same characters split over two attributes
        /// </summary>
        [Fact]
        public async Task GetDecisionForRequest_ValueContainsSeparators_DoesNotMatchAnotherRequest()
        {
            // Arrange
            SetupPdp(CreateResponse(XacmlContextDecision.Permit.ToString()));
            XacmlJsonRequestRoot first = CreateRequest();
            first.Request.AccessSubject[0].Attribute = [CreateAttribute("urn:a", "1;urn:b:2")];
            XacmlJsonRequestRoot second = CreateRequest();
            second.Request.AccessSubject[0].Attribute = [CreateAttribute("urn:a", "1"), CreateAttribute("urn:b", "2")];

            // Act
            await _cache.GetDecisionForRequest(first, TestContext.Current.CancellationToken);
            await _cache.GetDecisionForRequest(second, TestContext.Current.CancellationToken);

            // Assert
            Assert.Equal(2, _pdpMock.Invocations.Count);
        }

        /// <summary>
        /// Test case: The request is a multi request, or has more than one category of a kind, or other categories
        /// Expected: It is not cached
        /// </summary>
        [Theory]
        [InlineData("multi")]
        [InlineData("twoResources")]
        [InlineData("twoActions")]
        [InlineData("environment")]
        [InlineData("categoryId")]
        [InlineData("content")]
        [InlineData("includeInResult")]
        [InlineData("returnPolicyIdList")]
        [InlineData("combinedDecision")]
        public async Task GetDecisionForRequest_NotASingleSubjectActionAndResource_AsksPdpEveryTime(string shape)
        {
            // Arrange
            SetupPdp(CreateResponse(XacmlContextDecision.Permit.ToString()));

            // Act
            await _cache.GetDecisionForRequest(CreateRequestWithShape(shape), TestContext.Current.CancellationToken);
            await _cache.GetDecisionForRequest(CreateRequestWithShape(shape), TestContext.Current.CancellationToken);

            // Assert
            Assert.Equal(2, _pdpMock.Invocations.Count);
        }

        /// <summary>
        /// Test case: The host's cache has a size limit, and is shared with the host's own entries
        /// Expected: The decision is cached, under a key with the cache's own prefix
        /// </summary>
        [Fact]
        public async Task GetDecisionForRequest_CacheWithSizeLimit_CachesUnderOwnPrefix()
        {
            // Arrange
            using MemoryCache memoryCache = new MemoryCache(new MemoryCacheOptions { SizeLimit = 10 });
            PdpDecisionCache cache = new PdpDecisionCache(_pdpMock.Object, memoryCache, Options.Create(_pepSettings));
            SetupPdp(CreateResponse(XacmlContextDecision.Permit.ToString()));

            // Act
            await cache.GetDecisionForRequest(CreateRequest(), TestContext.Current.CancellationToken);
            await cache.GetDecisionForRequest(CreateRequest(), TestContext.Current.CancellationToken);

            // Assert
            Assert.Single(_pdpMock.Invocations);
            Assert.StartsWith("Altinn.Common.PEP.PdpDecisionCache:", Assert.IsType<string>(Assert.Single(memoryCache.Keys)));
        }

        /// <summary>
        /// Test case: The caching timeout is 0, the default
        /// Expected: Nothing is cached
        /// </summary>
        [Fact]
        public async Task GetDecisionForRequest_TimeoutIsZero_AsksPdpEveryTime()
        {
            // Arrange
            _pepSettings.PdpDecisionCachingTimeout = 0;
            SetupPdp(CreateResponse(XacmlContextDecision.Permit.ToString()));

            // Act
            await _cache.GetDecisionForRequest(CreateRequest(), TestContext.Current.CancellationToken);
            await _cache.GetDecisionForRequest(CreateRequest(), TestContext.Current.CancellationToken);

            // Assert
            Assert.Equal(2, _pdpMock.Invocations.Count);
        }

        /// <summary>
        /// Test case: The cached decision is older than the timeout
        /// Expected: The PDP is asked again
        /// </summary>
        [Fact]
        public async Task GetDecisionForRequest_TimeoutHasPassed_AsksPdpAgain()
        {
            // Arrange
            SetupPdp(CreateResponse(XacmlContextDecision.Permit.ToString()));
            await _cache.GetDecisionForRequest(CreateRequest(), TestContext.Current.CancellationToken);

            // Act & Assert
            _clock.UtcNow = _clock.UtcNow.AddMinutes(5).AddSeconds(-1);
            await _cache.GetDecisionForRequest(CreateRequest(), TestContext.Current.CancellationToken);
            Assert.Single(_pdpMock.Invocations);

            _clock.UtcNow = _clock.UtcNow.AddSeconds(1);
            await _cache.GetDecisionForRequest(CreateRequest(), TestContext.Current.CancellationToken);
            Assert.Equal(2, _pdpMock.Invocations.Count);
        }

        /// <summary>
        /// Test case: A request is sent with a cancellation token
        /// Expected: The token is passed on to the PDP, and the overload without a token passes none
        /// </summary>
        [Fact]
        public async Task GetDecisionForRequest_WithCancellationToken_PassesTokenToPdp()
        {
            // Arrange
            SetupPdp(CreateResponse(XacmlContextDecision.Deny.ToString()));
            using CancellationTokenSource cts = new CancellationTokenSource();

            // Act
            await _cache.GetDecisionForRequest(CreateRequest(), cts.Token);
#pragma warning disable xUnit1051 // The overload without a token is what this test checks.
            await _cache.GetDecisionForRequest(CreateRequest());
#pragma warning restore xUnit1051

            // Assert
            _pdpMock.Verify(p => p.GetDecisionForRequest(It.IsAny<XacmlJsonRequestRoot>(), cts.Token), Times.Once);
            _pdpMock.Verify(p => p.GetDecisionForRequest(It.IsAny<XacmlJsonRequestRoot>(), CancellationToken.None), Times.Once);
        }

        /// <summary>
        /// Test case: A cached Permit has an obligation for authentication level 3, and the second user only has level 2
        /// Expected: The cached response is validated again for each user
        /// </summary>
        [Fact]
        public async Task GetDecisionForUnvalidateRequest_CachedPermit_ValidatesForEachUser()
        {
            // Arrange
            XacmlJsonResponse permit = CreateResponse(XacmlContextDecision.Permit.ToString());
            permit.Response[0].Obligations =
            [
                new XacmlJsonObligationOrAdvice
                {
                    AttributeAssignment = [new XacmlJsonAttributeAssignment { Category = "urn:altinn:minimum-authenticationlevel", Value = "3" }],
                },
            ];
            SetupPdp(permit);

            // Act
            bool levelThree = await _cache.GetDecisionForUnvalidateRequest(CreateRequest(), CreateUser("3"), TestContext.Current.CancellationToken);
#pragma warning disable xUnit1051 // Uses the overload without a token, so both overloads are covered.
            bool levelTwo = await _cache.GetDecisionForUnvalidateRequest(CreateRequest(), CreateUser("2"));
#pragma warning restore xUnit1051

            // Assert
            Assert.True(levelThree);
            Assert.False(levelTwo);
            Assert.Single(_pdpMock.Invocations);
        }

        /// <summary>
        /// Test case: The PDP gives no response to a request that is validated
        /// Expected: The same exception as from PDPAppSI
        /// </summary>
        [Fact]
        public async Task GetDecisionForUnvalidateRequest_NullResponse_ThrowsArgumentNullException()
        {
            // Arrange
            SetupPdp(null);

            // Act & Assert
            await Assert.ThrowsAsync<ArgumentNullException>(() => _cache.GetDecisionForUnvalidateRequest(CreateRequest(), CreateUser("2"), TestContext.Current.CancellationToken));
        }

        /// <summary>
        /// Test case: Requests that are skipped, missed and hit
        /// Expected: Each is counted with its result
        /// </summary>
        [Fact]
        public async Task GetDecisionForRequest_CountsSkippedMissAndHit()
        {
            // Arrange
            SetupPdp(CreateResponse(XacmlContextDecision.Permit.ToString()));
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
            await _cache.GetDecisionForRequest(CreateRequest(processAttribute: null), TestContext.Current.CancellationToken);
            await _cache.GetDecisionForRequest(CreateRequest(), TestContext.Current.CancellationToken);
            await _cache.GetDecisionForRequest(CreateRequest(), TestContext.Current.CancellationToken);
            listener.Dispose();

            // Assert
            Assert.Equal(["skipped", "miss", "hit"], results);
        }

        private void SetupPdp(XacmlJsonResponse response)
        {
            _pdpMock
                .Setup(p => p.GetDecisionForRequest(It.IsAny<XacmlJsonRequestRoot>(), It.IsAny<CancellationToken>()))
                .ReturnsAsync(response);
        }

        private static XacmlJsonRequestRoot CreateRequest()
        {
            return CreateRequest(processAttribute: (TaskId, "Task_1"));
        }

        private static XacmlJsonRequestRoot CreateRequest((string AttributeId, string Value)? processAttribute)
        {
            List<XacmlJsonAttribute> resource =
            [
                CreateAttribute("urn:altinn:partyid", "1000"),
                CreateAttribute("urn:altinn:instance-id", "1000/0f8b3f8c-9d0e-4bb4-a6a4-1a2b3c4d5e6f"),
                CreateAttribute("urn:altinn:org", "myOrg"),
                CreateAttribute("urn:altinn:app", "myApp"),
            ];
            if (processAttribute is { } process)
            {
                resource.Add(CreateAttribute(process.AttributeId, process.Value));
            }

            return new XacmlJsonRequestRoot
            {
                Request = new XacmlJsonRequest
                {
                    AccessSubject =
                    [
                        new XacmlJsonCategory
                        {
                            Attribute =
                            [
                                CreateAttribute("urn:altinn:userid", "1337"),
                                CreateAttribute("urn:altinn:sessionid", "a-session"),
                                CreateAttribute("urn:altinn:authlevel", "2"),
                            ],
                        },
                    ],
                    Action = [new XacmlJsonCategory { Attribute = [CreateAttribute("urn:oasis:names:tc:xacml:1.0:action:action-id", "read")] }],
                    Resource = [new XacmlJsonCategory { Attribute = resource }],
                },
            };
        }

        private static XacmlJsonRequestRoot CreateRequestWithShape(string shape)
        {
            XacmlJsonRequestRoot root = CreateRequest();
            XacmlJsonRequest request = root.Request;
            switch (shape)
            {
                case "multi":
                    request.MultiRequests = new XacmlJsonMultiRequests();
                    break;
                case "twoResources":
                    request.Resource.Add(CreateRequest().Request.Resource[0]);
                    break;
                case "twoActions":
                    request.Action.Add(CreateRequest().Request.Action[0]);
                    break;
                case "environment":
                    request.Category = [new XacmlJsonCategory { CategoryId = "urn:oasis:names:tc:xacml:3.0:attribute-category:environment", Attribute = [] }];
                    break;
                case "categoryId":
                    request.AccessSubject[0].CategoryId = "urn:oasis:names:tc:xacml:1.0:subject-category:recipient-subject";
                    break;
                case "content":
                    request.Resource[0].Content = "<content/>";
                    break;
                case "includeInResult":
                    request.Resource[0].Attribute[0].IncludeInResult = true;
                    break;
                case "returnPolicyIdList":
                    request.ReturnPolicyIdList = true;
                    break;
                default:
                    request.CombinedDecision = true;
                    break;
            }

            return root;
        }

        private static XacmlJsonAttribute CreateAttribute(string attributeId, string value)
        {
            return new XacmlJsonAttribute { AttributeId = attributeId, Value = value, DataType = "string", Issuer = "Altinn" };
        }

        private static XacmlJsonResponse CreateResponse(string decision)
        {
            return new XacmlJsonResponse { Response = [new XacmlJsonResult { Decision = decision }] };
        }

        private static ClaimsPrincipal CreateUser(string authLevel)
        {
            return new ClaimsPrincipal(new ClaimsIdentity([new Claim("urn:altinn:authlevel", authLevel, "string", "org")]));
        }

        private sealed class TestClock : ISystemClock
        {
            public DateTimeOffset UtcNow { get; set; } = new DateTimeOffset(2026, 11, 13, 12, 0, 0, TimeSpan.Zero);
        }
    }
}
