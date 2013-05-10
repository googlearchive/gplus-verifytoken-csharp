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
using Google.Apis.Authentication.OAuth2;
using Google.Apis.Authentication.OAuth2.DotNetOpenAuth;
using Google.Apis.Oauth2.v2;
using Google.Apis.Oauth2.v2.Data;
using Google.Apis.Util;

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
    ///    - Token validation
    /// </summary>
    /// @author class@google.com (Gus Class)
    public class VerifyToken : IHttpHandler, IRequiresSessionState, IRouteHandler
    {
        private string CLIENT_ID = "YOUR_CLIENT_ID";

        /// <summary>
        /// Processes the request based on the path.
        /// </summary>
        /// <param name="context">Contains the request and response.</param>
        public void ProcessRequest(HttpContext context)
        
            // Get the code from the request POST body.
            string accessToken = context.Request.Params["access_token"]
            string idToken = context.Request.Params["id_token"];

            // Return if we don't have the required parameters.
            if (idToken == null || accessToken == null)
            {
                context.Response.StatusCode = 401;
                context.Response.StatusDescription = "Empty parameters";
                return;
            }

            string[] segments = idToken.Split('.');

            string base64EncoodedJsonBody = segments[1];
            int mod4 = base64EncoodedJsonBody.Length % 4;
            if ( mod4 > 0 )
            {
                base64EncoodedJsonBody += new string( '=', 4 - mod4 );
            }
            byte[] encodedBodyAsBytes =
                System.Convert.FromBase64String(base64EncoodedJsonBody);
            string json_body =
                System.Text.Encoding.UTF8.GetString(encodedBodyAsBytes);
            IDTokenJsonBodyObject bodyObject =
                JsonConvert.DeserializeObject<IDTokenJsonBodyObject>(json_body);
            string gplus_id = bodyObject.sub;

            // Use Tokeninfo to validate the user and the client.
            var tokeninfo_request = new Oauth2Service().Tokeninfo();
            tokeninfo_request.Access_token = accessToken;

            // Use Google as a trusted provider to validate the token.
            // Invalid values, including expired tokens, return 40
            // BAD REQUEST and throw an exception.
            var tokeninfo = tokeninfo_request.Fetch();
            if (
              // Verify that the id token's user id matches the token user ID
              gplus_id == tokeninfo.User_id

              // Verify the token is for this app
              && tokeninfo.Issued_to == CLIENT_ID
 
              // Verify the token hasn't expired
              && tokeninfo.Expires_in > 0
            )
            {
                // Success
                context.Response.StatusCode = 200;
            }
            else
            {
                // The credentials did not match.
                context.Response.StatusCode = 401;
                return;
            }
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

    /// <summary>
    /// Encapsulates JSON data for ID token body.
    /// </summary>
    public class IDTokenJsonBodyObject
    {
        public string iss;
        public string aud;
        public string at_hash;
        public string azp;
        public string c_hash;
        public string sub;
        public int iat;
        public int exp;
    }
}
