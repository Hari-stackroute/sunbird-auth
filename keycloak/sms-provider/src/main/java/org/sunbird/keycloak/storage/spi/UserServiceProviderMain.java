package org.sunbird.keycloak.storage.spi;

import com.google.api.client.googleapis.auth.oauth2.GoogleAuthorizationCodeFlow;
import com.google.api.client.googleapis.auth.oauth2.GoogleCredential;
import com.google.api.client.googleapis.auth.oauth2.GoogleTokenResponse;
import com.google.api.client.googleapis.javanet.GoogleNetHttpTransport;
import com.google.api.client.http.HttpRequestInitializer;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.json.gson.GsonFactory;
import com.google.api.services.people.v1.PeopleService;
import com.google.api.services.people.v1.PeopleServiceScopes;
import com.google.api.services.people.v1.model.Person;
import com.google.common.base.Splitter;
import org.jboss.logging.Logger;
import org.keycloak.component.ComponentModel;
import org.keycloak.models.*;
import org.keycloak.storage.StorageId;
import org.keycloak.storage.UserStorageProvider;
import org.keycloak.storage.user.UserLookupProvider;
import org.keycloak.storage.user.UserQueryProvider;
import org.sunbird.keycloak.utils.Constants;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.GeneralSecurityException;
import java.util.*;
import java.util.stream.Collectors;
//import com.google.api.client.json.JacksonFactory;

public class UserServiceProviderMain  {
  private static final Logger logger = Logger.getLogger(UserServiceProviderMain.class);


  public static void main(String args[]) {
    GoogleAuthorizationCodeFlow flow = new GoogleAuthorizationCodeFlow.Builder(
            new NetHttpTransport(), new GsonFactory(), "113975703552-4knb62rjo9ia27eh208tqc1dokrgcgvq.apps.googleusercontent.com", "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",
            Arrays.asList(PeopleServiceScopes.USERINFO_EMAIL, PeopleServiceScopes.USERINFO_PROFILE))
            .setAccessType("offline")
            .setApprovalPrompt("force")
            .build();
    logger.info("flow:"+ flow.newAuthorizationUrl().getHost());
    String authorizationUrl = flow.newAuthorizationUrl().setRedirectUri("http://localhost:8080/callback").build();
    logger.info("authorizationUrl:"+ authorizationUrl);

    String authorizationCode = null;
    try {
      authorizationCode = extractAuthorizationCode(authorizationUrl);
    } catch (URISyntaxException e) {
      throw new RuntimeException(e);
    }
    String accessToken = null;
    //GoogleTokenResponse tokenResponse = flow.newTokenRequest(authorizationCode).setRedirectUri("http://localhost:8080/callback").execute();
    try {
      GoogleTokenResponse tokenResponse = flow.newTokenRequest(authorizationCode)
              .setRedirectUri("http://localhost:8080/callback")
              .execute();
      logger.info("tokenResponse:"+ tokenResponse);
      accessToken = tokenResponse.getAccessToken();
      Long expiresIn = tokenResponse.getExpiresInSeconds();
    } catch (IOException e) {
      logger.error("error in tokenResponse:"+ e.getMessage());
      throw new RuntimeException(e);
    }
    try {
      HttpRequestInitializer requestInitializer = new GoogleCredential.Builder()
              .setTransport(GoogleNetHttpTransport.newTrustedTransport())
              .setJsonFactory(new GsonFactory())

              .build().setAccessToken(accessToken);


   /* GoogleCredential credential = null;
    GoogleCredential credential1 = null;
    try {
      // Load the credentials from the downloaded JSON file.
      *//*credential = GoogleCredential.fromStream(new FileInputStream("/Users/harikumarpalemkota/Documents/workspace/sunbird-auth/keycloak/sms-provider/src/main/resources/credentials.json"))
              .createScoped(Collections.singleton("PLUS_ME"));*//*
      credential = new GoogleCredential.Builder()
              .setTransport(new NetHttpTransport())
              .setJsonFactory(new GsonFactory())
              .setClientSecrets("113975703552-4knb62rjo9ia27eh208tqc1dokrgcgvq.apps.googleusercontent.com", "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")
              .build();
      logger.info("UserServiceProvider: credential :"+credential.toString());
    } catch (Exception e) {
      // Handle the exception.
      logger.error("error in credential:"+ e.getMessage());
    }

    // Authenticate the user and obtain an access token.
    String accessToken = null;
    try {
      accessToken = credential.getAccessToken();
      logger.info("UserServiceProvider: accessToken :"+accessToken);
    } catch (Exception e) {
      logger.error("error in accesstoken:"+ e.getMessage());
      // Handle the exception.
    }*/

    // Use the People API to retrieve the user's profile information.
    PeopleService peopleService = new PeopleService.Builder(new NetHttpTransport(), new GsonFactory(), requestInitializer)
            .setApplicationName("your-application-name")
            .build();
    Person profile = null;
    try {
      profile = peopleService.people().get("people/me")
              .setPersonFields("names,emailAddresses,photos")
              .execute();
      logger.info("UserServiceProvider: profile :"+profile);
      // Create a new User object using the retrieved profile information.
      User user = new User();
      user.setEmail(profile.getEmailAddresses().get(0).getValue());
      user.setFirstName(profile.getNames().get(0).getGivenName());
      user.setLastName(profile.getNames().get(0).getFamilyName());
      logger.info("UserServiceProvider: addUser info called");
      logger.info("UserServiceProvider: user-firstname :"+user.getFirstName());
      logger.info("UserServiceProvider: user-lastname :"+user.getLastName());
      logger.info("UserServiceProvider: user-email :"+user.getEmail());
    } catch (IOException e) {
      // Handle the exception.
      logger.error("error in profile:"+ e.getMessage());
    }
    } catch (GeneralSecurityException e) {
      throw new RuntimeException(e);
    } catch (IOException e) {
      throw new RuntimeException(e);
    }


    // Add the new User object to the Realm instance.
    //realm.add(user);

    /*UserModel userModel =new UserStorageManager(session).addUser(realm,username);

    logger.info("UserServiceProvider: email :"+userModel.getEmail());
    logger.info("UserServiceProvider: firstname :"+userModel.getFirstName());
    logger.info("UserServiceProvider: id :"+userModel.getId());*/
    /*JsonHttpContent JsonHttpContent = new JsonHttpContent().getJsonFactory()
    JsonFactory jsonFactory = new JsonFactory();
    JacksonFactory jsonFactory = JacksonFactory.getDefaultInstance();
    // Build the Google authorization flow
    GoogleAuthorizationCodeFlow flow = new GoogleAuthorizationCodeFlow.Builder(
            new NetHttpTransport(), new JacksonFactory(), clientId, clientSecret,
            Arrays.asList(PeopleServiceScopes.USERINFO_EMAIL, PeopleServiceScopes.USERINFO_PROFILE))
            .setAccessType("offline")
            .setApprovalPrompt("force")
            .build();

// Generate the authorization URL
    String authorizationUrl = flow.newAuthorizationUrl().setRedirectUri(redirectUri).build();

// Redirect the user to the authorization URL
    response.sendRedirect(authorizationUrl);

// After the user has a// Build the Google authorization flow
//    GoogleAuuthorized your application, exchange the authorization code for an access token
    GoogleTokenResponse tokenResponse = flow.newTokenRequest(authorizationCode)
            .setRedirectUri(redirectUri)
            .execute();

// Extract the access token
    String accessToken = tokenResponse.getAccessToken();

    GoogleCredential GoogleCredential = new GoogleCredential().setAccessToken()
    realm.getUserStorageProviders().
    StorageId.


            / Authenticate the user with Google
    KeycloakSession session = KeycloakSessionFactory.create();
    AuthenticationManager authManager = session.authenticationManager();
    AuthenticationFlowContext flow = authManager.authenticate(identityProvider("google").build());*/
    return ;
  }

  public static String extractAuthorizationCode(String callbackUrl) throws URISyntaxException {
    URI uri = new URI(callbackUrl);
    String query = uri.getQuery();
    Map<String, String> queryParams = Splitter.on('&').withKeyValueSeparator('=').split(query);
    return queryParams.get("code");
  }
}

