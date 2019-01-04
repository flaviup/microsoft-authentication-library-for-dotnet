// ------------------------------------------------------------------------------
//
// Copyright (c) Microsoft Corporation.
// All rights reserved.
//
// This code is licensed under the MIT License.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files(the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and / or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions :
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.
//
// ------------------------------------------------------------------------------

using System;
using System.Collections.Generic;
using System.Net;
using System.Threading.Tasks;
using Microsoft.Identity.Client.Core;
using Microsoft.Identity.Client.Http;
using Microsoft.Identity.Client.TelemetryCore;
using Microsoft.Identity.Client.UI;
using Microsoft.Identity.Client.Utils;

namespace Microsoft.Identity.Client.Internal.Requests
{
    internal class NonInteractiveLoginRequest : InteractiveRequest
    {
        private IHttpManager _httpManager;

        public NonInteractiveLoginRequest(
            IServiceBundle serviceBundle,
            AuthenticationRequestParameters authenticationRequestParameters,
            ApiEvent.ApiIds apiId,
            IEnumerable<string> extraScopesToConsent,
            UIBehavior uiBehavior,
            IWebUI webUi,
            string userName,
            string password)
            : base(
                serviceBundle,
                authenticationRequestParameters,
                apiId,
                extraScopesToConsent,
                uiBehavior,
                webUi)
        {
            Init(userName, password);
        }

        public NonInteractiveLoginRequest(
            IServiceBundle serviceBundle,
            AuthenticationRequestParameters authenticationRequestParameters,
            ApiEvent.ApiIds apiId,
            IEnumerable<string> extraScopesToConsent,
            string loginHint,
            UIBehavior uiBehavior,
            IWebUI webUi,
            string userName,
            string password)
            : base(serviceBundle, authenticationRequestParameters, apiId, extraScopesToConsent, loginHint, uiBehavior, webUi)
        {
            Init(userName, password);
        }

        internal string Username { get; private set; }
        internal string Password { get; private set; }

        private void Init(string userName, string password)
        {
            Username = userName;
            Password = password;
            _httpManager = new HttpManager(new HttpClientFactory(false));
        }

        internal protected override async Task AcquireAuthorizationAsync()
        {
            var authorizationUri = CreateAuthorizationUri(true, true);

            var uiEvent = new UiEvent();
            using (ServiceBundle.TelemetryManager.CreateTelemetryHelper(
                AuthenticationRequestParameters.RequestContext.TelemetryRequestId,
                AuthenticationRequestParameters.ClientId,
                uiEvent))
            {
                var requestContext = AuthenticationRequestParameters.RequestContext;
                var response = await _httpManager.SendGetAsync(authorizationUri, new Dictionary<string, string>(), requestContext).ConfigureAwait(false);

                if (response != null && 
                    response.StatusCode == HttpStatusCode.OK && 
                    !string.IsNullOrEmpty(response.Body))
                {
                    var csrf = GetField(response.Body, "csrf");
                    var transId = GetField(response.Body, "transId");
                    var policy = GetField(response.Body, "policy");
                    var pageViewId = GetField(response.Body, "pageViewId");
                    var api = GetField(response.Body, "api");
                    var logonUri = CreateLogonUri(transId, policy);
                    var postData = new Dictionary<string, string>
                    {
                        ["request_type"] = "RESPONSE",
                        ["logonIdentifier"] = Username,
                        ["password"] = Password
                    };
                    var response2 = await _httpManager.SendPostAsync(logonUri, new Dictionary<string, string> { ["X-CSRF-TOKEN"] = csrf }, postData, requestContext).ConfigureAwait(false);

                    if (response2 != null &&
                        response2.StatusCode == HttpStatusCode.OK)
                    {
                        var confirmedUri = CreateConfirmedUri(csrf, transId, policy, pageViewId, api);
                        var response3 = await _httpManager.SendGetAsync(confirmedUri, new Dictionary<string, string> { ["x-ms-cpim-pageviewid"] = pageViewId }, requestContext).ConfigureAwait(false);

                        if (response3 != null &&
                            (response3.StatusCode == HttpStatusCode.Found || 
                            response3.StatusCode == HttpStatusCode.OK))
                        {
                            AuthorizationResult = new AuthorizationResult(AuthorizationStatus.Success, response3.Headers?.Location);
                        }
                        else
                        {
                            AuthorizationResult = new AuthorizationResult(AuthorizationStatus.ErrorHttp);
                        }
                    }
                    else
                    {
                        AuthorizationResult = new AuthorizationResult(AuthorizationStatus.ErrorHttp);
                    }
                }
                else
                {
                    AuthorizationResult = new AuthorizationResult(AuthorizationStatus.ErrorHttp);
                }
                uiEvent.UserCancelled = AuthorizationResult.Status == AuthorizationStatus.UserCancel;
                uiEvent.AccessDenied = AuthorizationResult.Status == AuthorizationStatus.ProtocolError;
            }
        }

        private static string GetField(string htmlCode, string fieldName)
        {
            fieldName = $"\"{fieldName}\"";
            var position = htmlCode.IndexOf(fieldName);

            if (position > -1)
            {
                position = htmlCode.IndexOf('"', position + fieldName.Length);

                if (position > -1)
                {
                    var position2 = htmlCode.IndexOf('"', position + 1);

                    if (position2 > -1)
                    {
                        return htmlCode.Substring(position + 1, position2 - position - 1);
                    }
                }
            }
            return string.Empty;
        }

        private Uri CreateLogonUri(string transId, string policy)
        {
            var logonRequestParameters = new Dictionary<string, string>
            {
                ["tx"] = transId,
                ["p"] = policy
            };

            string qp = logonRequestParameters.ToQueryParameter().Replace("%3D", "=").Replace("%3d", "=");
            var endpointUrl = AuthenticationRequestParameters.Authority.CanonicalAuthority; // "https://login.microsoftonline.com/lcdevtestb2ctenant.onmicrosoft.com/B2C_1_susi";

            if (endpointUrl.EndsWith("/"))
            {
                endpointUrl = endpointUrl.Remove(endpointUrl.Length - 1, 1);
            }
            var builder = new UriBuilder(new Uri($"{endpointUrl}/SelfAsserted"));
            builder.AppendQueryParameters(qp);

            return builder.Uri;
        }

        private Uri CreateConfirmedUri(string csrf, string transId, string policy, string pageViewId, string api)
        {
            pageViewId = string.IsNullOrEmpty(pageViewId) ? null : $"\"pageViewId\":\"{pageViewId}\"";
            api = string.IsNullOrEmpty(api) ? "CombinedSigninAndSignup" : api;
            var pageId = $"\"pageId\":\"{api}\"";
            var diags = string.Join(",", pageViewId, pageId);
            var confirmedRequestParameters = new Dictionary<string, string>
            {
                ["csrf_token"] = csrf,
                ["tx"] = transId,
                ["p"] = policy,
                ["diags"] = $"{{{diags},\"trace\":[]}}"
            };
            string qp = confirmedRequestParameters.ToQueryParameter().Replace("%3D", "=").Replace("%3d", "=");
            var endpointUrl = AuthenticationRequestParameters.Authority.CanonicalAuthority; // "https://login.microsoftonline.com/lcdevtestb2ctenant.onmicrosoft.com/B2C_1_susi";

            if (endpointUrl.EndsWith("/"))
            {
                endpointUrl = endpointUrl.Remove(endpointUrl.Length - 1, 1);
            }
            var builder = new UriBuilder(new Uri($"{endpointUrl}/api/{api}/confirmed"));
            builder.AppendQueryParameters(qp);

            return builder.Uri;
        }
    }
}
