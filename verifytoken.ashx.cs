/*
 * Copyright 2013 Google Inc. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

// For revocation and REST queries using HTTPRequest.
using System.Net;
using System.Web;
using System.Web.Compilation;

// For string manipulations used in the template and string building.
using System.Text;
using System.Text.RegularExpressions;

// For mapping routes
using System.Web.Routing;
using System.Web.SessionState;

// Generated libraries for Google APIs
using System.Net;
using System.Web;
using Google.Apis.Authentication.OAuth2;
using Google.Apis.Authentication.OAuth2.DotNetOpenAuth;
using Google.Apis.Oauth2.v2;
using Google.Apis.Oauth2.v2.Data;
using Google.Apis.Util;

// For token verification
using Microsoft.IdentityModel.Tokens.JWT;
using Microsoft.IdentityModel.Tokens;

using System.Collections;
using System.IdentityModel.Tokens;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
// For OAuth2
using DotNetOpenAuth.Messaging;
using DotNetOpenAuth.OAuth2;

// For JSON parsing.
using Newtonsoft.Json;

namespace VerifyToken
{
    /// <summary>
    ///  This is a minimal implementation of OAuth V2 verification that
    ///  demonstrates:
    ///    - ID Token validation
    ///    - Access token validation
    /// </summary>
    /// @author class@google.com (Gus Class)
    public class VerifyToken : IHttpHandler, IRequiresSessionState, IRouteHandler
    {
        // Get this from your app at https://code.google.com/apis/console
        static public string CLIENT_ID = "YOUR_CLIENT_ID";

        // Values returned in the response
        access_token_status ats = new access_token_status();
        id_token_status its = new id_token_status();

        /// <summary>
        /// Processes the request based on the path.
        /// </summary>
        /// <param name="context">Contains the request and response.</param>
        public void ProcessRequest(HttpContext context){
        
            // Get the code from the request POST body.
            string accessToken = context.Request.Params["access_token"];
            string idToken = context.Request.Params["id_token"];

            // Validate the ID token
            if (idToken != null)
            {
                JWTSecurityToken token = new JWTSecurityToken(idToken);
                JWTSecurityTokenHandler jwt = new JWTSecurityTokenHandler();

                // Configure validation
                Byte[][] certBytes = getCertBytes();
                for (int i = 0; i < certBytes.Length; i++)
                {
                    X509Certificate2 certificate = new X509Certificate2(certBytes[i]);
                    X509SecurityToken certToken = new X509SecurityToken(certificate);

                    // Set up token validation 
                    TokenValidationParameters tvp = new TokenValidationParameters();
                    tvp.AllowedAudience = CLIENT_ID;
                    tvp.SigningToken = certToken;
                    tvp.ValidIssuer = "accounts.google.com";

                    // Enable / disable tests                
                    tvp.ValidateNotBefore = false;
                    tvp.ValidateExpiration = true;
                    tvp.ValidateSignature = true;
                    tvp.ValidateIssuer = true;

                    // Account for clock skew. Look at current time when getting the message
                    // "The token is expired" in try/catch block.
                    // This is relative to GMT, for example, GMT-8 is:
                    tvp.ClockSkewInSeconds = 3600 * 13;

                    try
                    {
                        // Validate using the provider
                        ClaimsPrincipal cp = jwt.ValidateToken(token, tvp);
                        if (cp != null)
                        {
                            its.valid = true;
                            its.message = "Valid ID Token.";
                        }
                    }
                    catch (Exception e)
                    {
                        // Multiple certificates are tested.
                        if (its.valid != true)
                        {
                            its.message = "Invalid ID Token.";                           
                        }
                        if (e.Message.IndexOf("The token is expired") > 0)
                        {
                            // TODO: Check current time in the exception for clock skew.
                        }
                    }
                }

                // Get the Google+ id for this user from the "sub" claim.
                Claim[] claims = token.Claims.ToArray<Claim>();
                for (int i = 0; i < claims.Length; i++)
                {
                    if (claims[i].Type.Equals("sub"))
                    {
                        its.gplus_id = claims[i].Value;
                    }
                }
            }

            // Use Tokeninfo to validate the user and the client.
            var tokeninfo_request = new Oauth2Service().Tokeninfo();
            tokeninfo_request.Access_token = accessToken;

            // Use Google as a trusted provider to validate the token.
            // Invalid values, including expired tokens, return 400
            Tokeninfo tokeninfo = null;
            try
            {
                tokeninfo = tokeninfo_request.Fetch();
                if (tokeninfo.Issued_to != CLIENT_ID){
                    ats.message = "Access Token not meant for this app.";
                }else{
                    ats.valid = true;
                    ats.message = "Valid Access Token.";
                    ats.gplus_id = tokeninfo.User_id;
                }
            }
            catch (Exception stve)
            {                
                ats.message = "Invalid Access Token.";
            }

            // Use the wrapper to return JSON
            token_status_wrapper tsr = new token_status_wrapper();
            tsr.id_token_status = its;
            tsr.access_token_status = ats;

            context.Response.StatusCode = 200;
            context.Response.ContentType = "text/json";
            context.Response.Write(JsonConvert.SerializeObject(tsr));
        }


        // Used for string parsing the Certificates from Google
        private const string beginCert = "-----BEGIN CERTIFICATE-----\\n";
        private const string endCert = "\\n-----END CERTIFICATE-----\\n";

        /// <summary>
        /// Retrieves the certificates for Google and returns them as byte arrays.
        /// </summary>
        /// <returns>An array of byte arrays representing the Google certificates.</returns>
        public byte[][] getCertBytes()
        {
            // The request will be made to the authentication server.
            WebRequest request = WebRequest.Create(
                "https://www.googleapis.com/oauth2/v1/certs"
            );

            StreamReader reader = new StreamReader(request.GetResponse().GetResponseStream());

            string responseFromServer = reader.ReadToEnd();
            
            String[] split = responseFromServer.Split(':');

            // There are two certificates returned from Google
            byte[][] certBytes = new byte[2][];
            int index = 0;
            UTF8Encoding utf8 = new UTF8Encoding();
            for (int i = 0; i < split.Length; i++)
            {
                if (split[i].IndexOf(beginCert) > 0)
                {                  
                    int startSub = split[i].IndexOf(beginCert);
                    int endSub = split[i].IndexOf(endCert) + endCert.Length;
                    certBytes[index] = utf8.GetBytes(split[i].Substring(startSub, endSub).Replace("\\n", "\n"));
                    index++;
                }
            }
            return certBytes;
        }


        /// <summary>
        /// Stores the result data for the ID token verification.
        /// </summary>
        class id_token_status
        {
            public Boolean valid = false;
            public String gplus_id = null;
            public String message = "";
        }

        /// <summary>
        /// Stores the result data for the access token verification.
        /// </summary>
        class access_token_status
        {
            public Boolean valid = false;
            public String gplus_id = null;
            public String message = "";
        }

        class token_status_wrapper
        {
            public id_token_status id_token_status = null;
            public access_token_status access_token_status = null;
        }

        /// <summary>
        /// Implements IRouteHandler interface for mapping routes to this
        /// IHttpHandler.
        /// </summary>
        /// <param name="requestContext">Information about the request.
        /// </param>
        /// <returns></returns>
        public IHttpHandler GetHttpHandler(RequestContext
            requestContext)
        {
            var page = BuildManager.CreateInstanceFromVirtualPath
                 ("~/verifytoken.ashx", typeof(IHttpHandler)) as IHttpHandler;
            return page;
        }

        public bool IsReusable { get { return false; } }
    }
}
