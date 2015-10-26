/*
 * Copyright 2015 Dominick Baier, Brock Allen
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

using Microsoft.Owin.Logging;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Infrastructure;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Claims;
using System.Threading.Tasks;

namespace IdentityServer3.AccessTokenValidation
{
    internal class ValidationEndpointTokenProvider : AuthenticationTokenProvider
    {
        private readonly HttpClient _client;
        private readonly string _tokenValidationEndpoint;
        private readonly IdentityServerBearerTokenAuthenticationOptions _options;
        private readonly ILogger _logger;
        private string _userinfoEndpoint;

        public ValidationEndpointTokenProvider(IdentityServerBearerTokenAuthenticationOptions options, ILoggerFactory loggerFactory)
        {
            _logger = loggerFactory.Create(this.GetType().FullName);

            if (string.IsNullOrWhiteSpace(options.Authority))
            {
                throw new Exception("Authority must be set to use validation endpoint.");
            }

            var baseAddress = options.Authority.EnsureTrailingSlash();
            _userinfoEndpoint = baseAddress + "connect/userinfo";
            
            baseAddress += "connect/accesstokenvalidation";
            _tokenValidationEndpoint = baseAddress;
            var handler = options.BackchannelHttpHandler ?? new WebRequestHandler();

            if (options.BackchannelCertificateValidator != null)
            {
                // Set the cert validate callback
                var webRequestHandler = handler as WebRequestHandler;
                if (webRequestHandler == null)
                {
                    throw new InvalidOperationException("Invalid certificate validator");
                }

                webRequestHandler.ServerCertificateValidationCallback = options.BackchannelCertificateValidator.Validate;
            }

            _client = new HttpClient(handler);
            _options = options;
        }

        public override async Task ReceiveAsync(AuthenticationTokenReceiveContext context)
        {
            if (_options.EnableValidationResultCache)
            {
                var cachedClaims = await _options.ValidationResultCache.GetAsync(context.Token);
                if (cachedClaims != null)
                {
                    SetAuthenticationTicket(context, cachedClaims);
                    return;
                }
            }

            var form = new Dictionary<string, string>
            {
                { "token", context.Token }
            };

            HttpResponseMessage response = null;
            try
            {
                response = await _client.PostAsync(_tokenValidationEndpoint, new FormUrlEncodedContent(form));
                if (response.StatusCode != HttpStatusCode.OK)
                {
                    _logger.WriteInformation("Error returned from token validation endpoint: " + response.ReasonPhrase);
                    return;
                }
            }
            catch (Exception ex)
            {
                _logger.WriteError("Exception while contacting token validation endpoint: " + ex.ToString());
                return;
            }

            var jsonString = await response.Content.ReadAsStringAsync();
            var dictionary = JsonConvert.DeserializeObject<Dictionary<string, object>>(jsonString);


            if (_options.FetchUserInfo)
            {
                HttpResponseMessage userinfoResponse;
                try
                {
                    var userinfoForm = new Dictionary<string, string>
                    {
                        {"access_token", context.Token}
                    };

                    userinfoResponse =
                        await _client.PostAsync(_userinfoEndpoint, new FormUrlEncodedContent(userinfoForm));
                    if (userinfoResponse.StatusCode != HttpStatusCode.OK)
                    {
                        _logger.WriteError("Error fetch user info: " + userinfoResponse.ReasonPhrase);
                        return;
                    }
                }
                catch (Exception ex)
                {
                    _logger.WriteError("Exception while contacting user info endpoint: " + ex);
                    return;
                }

                var dic = await userinfoResponse.Content.ReadAsAsync<Dictionary<string, object>>();
                foreach (var i in dic)
                {
                    if (!dictionary.ContainsKey(i.Key))
                        dictionary.Add(i.Key, i.Value);
                }
            }

            var claims = new List<Claim>();

            foreach (var item in dictionary)
            {
                var values = item.Value as IEnumerable<object>;

                if (values == null)
                {
                    claims.Add(new Claim(item.Key, item.Value.ToString()));
                }
                else
                {
                    foreach (var value in values)
                    {
                        claims.Add(new Claim(item.Key, value.ToString()));
                    }
                }
            }

            if (_options.EnableValidationResultCache)
            {
                await _options.ValidationResultCache.AddAsync(context.Token, claims);
            }

            _logger.WriteVerbose(
                $"{nameof(ValidationEndpointTokenProvider)}: token loaded: {string.Join(",", claims.Select(x => $"{x.Type}:{x.Value}"))}");

            SetAuthenticationTicket(context, claims);
        }

        private void SetAuthenticationTicket(AuthenticationTokenReceiveContext context, IEnumerable<Claim> claims)
        {
            var id = new ClaimsIdentity(
                            claims,
                            _options.AuthenticationType,
                            _options.NameClaimType,
                            _options.RoleClaimType);

            context.SetTicket(new AuthenticationTicket(id, new AuthenticationProperties()));
        }
    }
}