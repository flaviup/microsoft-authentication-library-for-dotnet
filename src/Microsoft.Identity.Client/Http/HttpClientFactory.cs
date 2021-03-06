﻿//------------------------------------------------------------------------------
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
//------------------------------------------------------------------------------

using System.Net.Http;
using System.Net.Http.Headers;

namespace Microsoft.Identity.Client.Http
{
    internal interface IHttpClientFactory
    {
        HttpClient HttpClient { get; }
    }

    internal class HttpClientFactory : IHttpClientFactory
    {
        // The HttpClient is a singleton per ClientApplication so that we don't have a process wide singleton.
        public const long MaxResponseContentBufferSizeInBytes = 1024*1024;

        public HttpClientFactory(bool allowAutoRedirect = true)
        {
            var clientHandler = new HttpClientHandler
            {
                UseDefaultCredentials = true,
                AllowAutoRedirect = allowAutoRedirect
            };
            var httpClient = new HttpClient(clientHandler)
            {
                MaxResponseContentBufferSize = MaxResponseContentBufferSizeInBytes
            };

            httpClient.DefaultRequestHeaders.Accept.Clear();
            httpClient.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

            HttpClient = httpClient;
        }

        public HttpClient HttpClient { get; }
    }
}