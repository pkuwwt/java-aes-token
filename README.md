# java-aes-token
A sample code to generate token using AES encrypt. The encrypted information includes username, password, period

You can generate a token by 

    String token = AESenc.generateToken(username, password, new Date(), 1000, "secretKey");
  
with period of 1000 seconds.

Then you can check if it is valid by

    AESenc.validateToken(token, "secretKey");
  
And you can check whether it is outdated by

    AESenc.isTokenOutDated(token, "secretKey");
  

The secret key for AES and hasing is separated.
