# Demo: Verify Token (C#) #

This demo verifies an OAuth v2 access token and parses an OAuth v2 ID token.

## Requirements ##
* Visual Studio 2012 or later

## Usage ##
1. Open the VerifyTokenDemo solution.
2. Install the JSON Web Token Handler for the Microsoft .Net Framework 4.5 using [the package manager console](http://docs.nuget.org/docs/start-here/using-the-package-manager-console) or by restoring the required packages by selecting Project->Enable NuGet Package Restore, Project-> Manage NuGet Packages, **Restore**.

    PM> Install-Package Microsoft.IdentityModel.Tokens.JWT
2. Edit YOUR_CLIENT_ID in verifytoken.ashx.cs to be the client ID for your app.
3. Click the run/play icon to start the program.
4. Open your browser to: 

    http://localhost:4567/verifytoken.ashx?access_token=[YOUR_ACCESS_TOKEN]&id_token=[YOUR_ID_TOKEN]

5. The app will return JSON representing whether each token is valid. For example:

    {
        "access_token_status":{
          "valid":false,
          "gplus_id":null,
          "message":"The remote server returned an error: (400) Bad Request."
        },
        "id_token_status":{
          "valid":false,
          "gplus_id":null,
          "message":""}
    }

