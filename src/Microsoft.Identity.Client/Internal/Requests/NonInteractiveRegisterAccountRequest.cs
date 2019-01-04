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
using System.Threading;
using System.Threading.Tasks;
using System.Runtime.Serialization;
using Microsoft.Identity.Client.Core;
using Microsoft.Identity.Client.Http;
using Microsoft.Identity.Client.TelemetryCore;
using Microsoft.Identity.Client.UI;
using Microsoft.Identity.Client.Utils;

namespace Microsoft.Identity.Client.Internal.Requests
{
    internal class NonInteractiveRegisterAccountRequest : InteractiveRequest
    {
        private IHttpManager _httpManager;

        private string _csrf;
        private string _transId;
        private string _policy;

        public NonInteractiveRegisterAccountRequest(
            IServiceBundle serviceBundle,
            AuthenticationRequestParameters authenticationRequestParameters,
            ApiEvent.ApiIds apiId,
            IEnumerable<string> extraScopesToConsent,
            UIBehavior uiBehavior,
            IWebUI webUi,
            string email)
            : base(
                serviceBundle,
                authenticationRequestParameters,
                apiId,
                extraScopesToConsent,
                uiBehavior,
                webUi)
        {
            Init(email);
        }

        public NonInteractiveRegisterAccountRequest(
            IServiceBundle serviceBundle,
            AuthenticationRequestParameters authenticationRequestParameters,
            ApiEvent.ApiIds apiId,
            IEnumerable<string> extraScopesToConsent,
            string loginHint,
            UIBehavior uiBehavior,
            IWebUI webUi,
            string email)
            : base(serviceBundle, authenticationRequestParameters, apiId, extraScopesToConsent, loginHint, uiBehavior, webUi)
        {
            Init(email);
        }

        internal string Email { get; set; }
        internal string VerificationCode { get; set; }
        internal string Password { get; set; }
        internal string FirstName { get; set; }
        internal string LastName { get; set; }

        [DataContract]
        internal class ResponseStatus
        {
            [DataMember(Name = "status")]
            public string Status { get; set; }

            [DataMember(Name = "result")]
            public int? Result { get; set; }
        }

        private void Init(string email)
        {
            Email = email;
            _httpManager = new HttpManager(new HttpClientFactory(false));
        }

        internal override async Task<AuthenticationResult> ExecuteAsync(CancellationToken cancellationToken)
        {
            if (!string.IsNullOrEmpty(Email) && 
                !string.IsNullOrEmpty(VerificationCode) && 
                !string.IsNullOrEmpty(Password))
            {
                return await base.ExecuteAsync(cancellationToken).ConfigureAwait(false);
            }
            await ResolveAuthorityEndpointsAsync().ConfigureAwait(false);
            await AcquireAuthorizationAsync().ConfigureAwait(false);
            return (AuthorizationResult != null && AuthorizationResult.Status == AuthorizationStatus.Success) ? new AuthenticationResult() : (AuthenticationResult)null;
        }

        private async Task SendEmailVerificationCodeAsync()
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
                    _csrf = GetField(response.Body, "csrf");
                    _transId = GetField(response.Body, "transId");
                    _policy = GetField(response.Body, "policy"); // B2C_1_sign_up
                    var verifyEmailUri = CreateRegisterAccountUri(_transId, _policy);
                    var postData = new Dictionary<string, string>
                    {
                        ["request_type"] = "VERIFICATION_REQUEST",
                        ["claim_id"] = "email",
                        ["claim_value"] = Email
                    };
                    var response2 = await _httpManager.SendPostAsync(verifyEmailUri, new Dictionary<string, string> { ["X-CSRF-TOKEN"] = _csrf }, postData, requestContext).ConfigureAwait(false);

                    if (response2 != null &&
                        response2.StatusCode == HttpStatusCode.OK)
                    {
                        AuthorizationResult = new AuthorizationResult(AuthorizationStatus.Success);
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

        private async Task VerifyEmailCodeAsync()
        {
            var uiEvent = new UiEvent();

            using (ServiceBundle.TelemetryManager.CreateTelemetryHelper(
                AuthenticationRequestParameters.RequestContext.TelemetryRequestId,
                AuthenticationRequestParameters.ClientId,
                uiEvent))
            {
                var requestContext = AuthenticationRequestParameters.RequestContext;
                var verifyEmailUri = CreateRegisterAccountUri(_transId, _policy);
                var postData = new Dictionary<string, string>
                {
                    ["request_type"] = "VALIDATION_REQUEST",
                    ["claim_id"] = "email",
                    ["claim_value"] = Email,
                    ["user_input"] = VerificationCode
                };
                var response = await _httpManager.SendPostAsync(verifyEmailUri, new Dictionary<string, string> { ["X-CSRF-TOKEN"] = _csrf }, postData, requestContext).ConfigureAwait(false);

                if (response != null &&
                    response.StatusCode == HttpStatusCode.OK)
                {
                    var res = JsonHelper.DeserializeFromJson<ResponseStatus>(response.Body);

                    if (res.Status == "200" &&
                        (!res.Result.HasValue ||
                        res.Result == 0))
                    {
                        AuthorizationResult = new AuthorizationResult(AuthorizationStatus.Success);
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

        private async Task RegisterAccountAsync()
        {
            var uiEvent = new UiEvent();

            using (ServiceBundle.TelemetryManager.CreateTelemetryHelper(
                AuthenticationRequestParameters.RequestContext.TelemetryRequestId,
                AuthenticationRequestParameters.ClientId,
                uiEvent))
            {
                var requestContext = AuthenticationRequestParameters.RequestContext;
                var verifyEmailUri = CreateRegisterAccountUri(_transId, _policy);
                var postData = new Dictionary<string, string>
                {
                    ["request_type"] = "RESPONSE",
                    ["email"] = Email,
                    ["email_ver_input"] = VerificationCode,
                    ["newPassword"] = Password,
                    ["reenterPassword"] = Password,
                    ["givenName"] = FirstName,
                    ["surname"] = LastName
                };
                var response = await _httpManager.SendPostAsync(verifyEmailUri, new Dictionary<string, string> { ["X-CSRF-TOKEN"] = _csrf }, postData, requestContext).ConfigureAwait(false);

                if (response != null &&
                    response.StatusCode == HttpStatusCode.OK)
                {
                    var res = JsonHelper.DeserializeFromJson<ResponseStatus>(response.Body);

                    if (res.Status == "200" &&
                        (!res.Result.HasValue ||
                        res.Result == 0))
                    {
                        var confirmedUri = CreateConfirmedUri(_csrf, _transId, _policy);
                        var response2 = await _httpManager.SendGetAsync(confirmedUri, new Dictionary<string, string>(), requestContext).ConfigureAwait(false);

                        if (response2 != null && 
                            (response2.StatusCode == HttpStatusCode.Found || 
                            response2.StatusCode == HttpStatusCode.OK))
                        {
                            AuthorizationResult = new AuthorizationResult(AuthorizationStatus.Success, response2.Headers?.Location);
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
                uiEvent.UserCancelled = AuthorizationResult.Status == AuthorizationStatus.UserCancel;
                uiEvent.AccessDenied = AuthorizationResult.Status == AuthorizationStatus.ProtocolError;
            }
        }

        internal protected override async Task AcquireAuthorizationAsync()
        {
            if (string.IsNullOrEmpty(Password))
            {
                if (string.IsNullOrEmpty(VerificationCode))
                {
                    await SendEmailVerificationCodeAsync().ConfigureAwait(false);
                }
                else
                {
                    await VerifyEmailCodeAsync().ConfigureAwait(false);
                }
            }
            else if (!string.IsNullOrEmpty(Email))
            {
                await RegisterAccountAsync().ConfigureAwait(false);
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

        private Uri CreateRegisterAccountUri(string transId, string policy)
        {
            var registerAccountRequestParameters = new Dictionary<string, string>
            {
                ["tx"] = transId,
                ["p"] = policy
            };

            string qp = registerAccountRequestParameters.ToQueryParameter().Replace("%3D", "=").Replace("%3d", "=");
            var endpointUrl = AuthenticationRequestParameters.Authority.CanonicalAuthority; // "https://login.microsoftonline.com/lcdevtestb2ctenant.onmicrosoft.com/b2c_1_sign_up";

            if (endpointUrl.EndsWith("/"))
            {
                endpointUrl = endpointUrl.Remove(endpointUrl.Length - 1, 1);
            }

            if (endpointUrl.Contains("/tfp/"))
            {
                endpointUrl = endpointUrl.Replace("/tfp/", "/");
            }
            var builder = new UriBuilder(new Uri($"{endpointUrl}/SelfAsserted"));
            builder.AppendQueryParameters(qp);

            return builder.Uri;
        }

        private Uri CreateConfirmedUri(string csrf, string transId, string policy)
        {
            var api = "SelfAsserted";
            var confirmedRequestParameters = new Dictionary<string, string>
            {
                ["csrf_token"] = csrf,
                ["tx"] = transId,
                ["p"] = policy
            };
            string qp = confirmedRequestParameters.ToQueryParameter().Replace("%3D", "=").Replace("%3d", "=");
            var endpointUrl = AuthenticationRequestParameters.Authority.CanonicalAuthority; // "https://login.microsoftonline.com/lcdevtestb2ctenant.onmicrosoft.com/b2c_1_sign_up";

            if (endpointUrl.EndsWith("/"))
            {
                endpointUrl = endpointUrl.Remove(endpointUrl.Length - 1, 1);
            }

            if (endpointUrl.Contains("/tfp/"))
            {
                endpointUrl = endpointUrl.Replace("/tfp/", "/");
            }
            var builder = new UriBuilder(new Uri($"{endpointUrl}/api/{api}/confirmed"));
            builder.AppendQueryParameters(qp);//https://login.microsoftonline.com/tfp/lcdevtestb2ctenant.onmicrosoft.com/b2c_1_sign_up/api/SelfAsserted/confirmed?

            return builder.Uri;
        }
    }
}
