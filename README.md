# Demo: Verify Token (C#) #

This demo verifies an OAuth v2 access token and parses an OAuth v2 ID token.

## Usage ##
1. Open the VerifyTokenDemo solution.
2. Edit YOUR_CLIENT_ID in verifytoken.ashx.cs to be the client ID for your app.
3. Click the run/play icon to start the program.
4. Open your browser to: 

    http://localhost:4567/verifytoken.ashx?access_token=[YOUR_ACCESS_TOKEN]&id_token=[YOUR_ID_TOKEN]
5. The app will return a status code of 200 if the token is valid, 401 if it 
is not.
