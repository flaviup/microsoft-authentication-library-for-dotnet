using Microsoft.Identity.Client.Core;
using Microsoft.Identity.Client.UI;
using Microsoft.Identity.Test.Unit;
using OpenQA.Selenium;
using System;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

namespace Microsoft.Identity.Test.Integration.SeleniumTests
{
    internal class SeleniumWebUI : IWebUI
    {
        private readonly Action<IWebDriver> _seleniumAutomationLogic;
        private readonly TimeSpan _timeout;

        public SeleniumWebUI(Action<IWebDriver> seleniumAutomationLogic, TimeSpan timeout)
        {
            _seleniumAutomationLogic = seleniumAutomationLogic;
            _timeout = timeout;
        }

        public async Task<AuthorizationResult> AcquireAuthorizationAsync(
            Uri authorizationUri,
            Uri redirectUri,
            RequestContext requestContext)
        {
            if (redirectUri.IsDefaultPort)
            {
                throw new InvalidOperationException("Cannot listen to localhost (no port), please call UpdateRedirectUri to get a free localhost:port address");
            }

            AuthorizationResult result = await SeleniumAcquireAuthAsync(
                authorizationUri,
                redirectUri)
                .ConfigureAwait(true);

            return result;
        }

        public void ValidateRedirectUri(Uri redirectUri)
        {
            if (!redirectUri.IsLoopback)
            {
                throw new ArgumentException("Only loopback redirect uri");
            }

            if (redirectUri.IsDefaultPort)
            {
                throw new ArgumentException("Port required");
            }
        }

        private IWebDriver InitDriverAndGoToUrl(string url)
        {
            IWebDriver driver = null;
            try
            {
                driver = SeleniumExtensions.CreateDefaultWebDriver();
                driver.Navigate().GoToUrl(url);

                return driver;
            }
            catch (Exception ex)
            {
                driver?.Dispose();
                throw;
            }
        }

        private async Task<AuthorizationResult> SeleniumAcquireAuthAsync(
            Uri authorizationUri,
            Uri redirectUri)
        {
            if (!redirectUri.IsLoopback)
            {
                throw new ArgumentException("Only loopback redirect uri");
            }

            if (redirectUri.IsDefaultPort)
            {
                throw new ArgumentException("Port required");
            }

            using (var driver = InitDriverAndGoToUrl(authorizationUri.OriginalString))
            using (var listener = new AuthorizationTcpListener(redirectUri.Port)) // starts listening
            {
                // Run the tcp listener and the selenium automation in parallel
                var seleniumAutomationTask = Task.Run(() =>
                {
                    _seleniumAutomationLogic(driver);
                });

                CancellationTokenSource cancellationTokenSource = new CancellationTokenSource(_timeout);
                var listenForAuthCodeTask = listener.WaitForCallbackAsync(cancellationTokenSource.Token);

                try
                {

                    await Task.WhenAll(seleniumAutomationTask, listenForAuthCodeTask).ConfigureAwait(false);
                    return listenForAuthCodeTask.Result;

                }
                catch (Exception ex) when (ex is TaskCanceledException || ex is OperationCanceledException)
                {
                    return await Task.FromResult(
                        new AuthorizationResult(AuthorizationStatus.UserCancel)).ConfigureAwait(false);
                }
                catch (SocketException ex)
                {
                    var result = new AuthorizationResult(AuthorizationStatus.UnknownError)
                    {
                        ErrorDescription = ex.Message + " soket error code: " + ex.SocketErrorCode,
                        Error = "system_browser_soket_exception"
                    };

                    return await Task.FromResult(result).ConfigureAwait(false);
                }
                catch (Exception ex)
                {
                    var result = new AuthorizationResult(AuthorizationStatus.UnknownError)
                    {
                        ErrorDescription = ex.Message,
                        Error = "system_browser_waiting_exception"
                    };

                    return await Task.FromResult(result).ConfigureAwait(false);
                }
            }
        }
    }
}
