# Project status #
![status: inactive](https://img.shields.io/badge/status-inactive-red.svg)

This project is no longer actively maintained, and remains here as an archive of this work.

# Verifying Google+ Tokens in C# 

This sample demonstrates how to verify that the ID tokens and access tokens that you receive on your server are valid. This process is important to perform when your app must send tokens to your server but  is unable to use the one-time-code flow for securely getting tokens for your server.

## Security concerns

ID tokens and access tokens are sensitive and can be misused if intercepted. You must ensure that these tokens are handled securely by only transmitting them over HTTPS and only via POST data or within request headers. If you store them on your server, you must also store them securely.

## Use cases

The following are common situations where you might send tokens to your server:

* Sending ID tokens with requests that need to be authenticated. For example, if you need to pass data to your server and you want to ensure that particular data came from a specific user.
* Sending client-side access tokens to the server so that the server an make requests to the Google APIs and when the one-time-code flow is not available. For example, if your iOS app has a back-end server that needs to request data from the APIs and then background process it on behalf of the client.

## When to verify tokens

All tokens need to be verified on your server unless you know that they came directly from Google. Any token that you receive from your client apps must be verified.

## Requirements ##
* Visual Studio 2012 or later
* .NET 4.5

## Usage ##
1. Open the VerifyTokenDemo solution.
2. Install the JSON Web Token Handler for the Microsoft .Net Framework 4.5 using [the package manager console](http://docs.nuget.org/docs/start-here/using-the-package-manager-console) or by restoring the required packages by selecting Project->Enable NuGet Package Restore, Project-> Manage NuGet Packages, **Restore**.

    PM> Install-Package Microsoft.IdentityModel.Tokens.JWT
2. Edit YOUR_CLIENT_ID in verifytoken.ashx.cs to be the client ID for your app.
3. Click the run/play icon to start the program.
4. Open your browser to: 

    http://localhost:4567/verifytoken.ashx?access_token=[YOUR_ACCESS_TOKEN]&id_token=[YOUR_ID_TOKEN]

or

    http://localhost:4567/default.aspx

## Alternatives

You should use the one-time-code flow to get your server its own access tokens and refresh tokens for the user. This one-time-use code is exchanged for tokens and then becomes immediately invalid. It can only be exchanged by server's that have the correct client ID and client secret. These two aspects of the one-time-code flow provide significantly more security over the exchange of tokens with a server.

One-time-code flow is available for web apps and Android apps:
+ [Android](https://developers.google.com/+/mobile/android/sign-in#server-side_access_for_your_app)
+ [Web](https://developers.google.com/+/web/signin/server-side-flow)
