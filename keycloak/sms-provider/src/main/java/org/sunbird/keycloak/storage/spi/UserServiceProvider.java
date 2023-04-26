package org.sunbird.keycloak.storage.spi;

import java.io.FileInputStream;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.GeneralSecurityException;
import java.util.*;
import java.util.stream.Collectors;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.api.client.auth.oauth2.Credential;
import com.google.api.client.extensions.java6.auth.oauth2.AuthorizationCodeInstalledApp;
import com.google.api.client.extensions.jetty.auth.oauth2.LocalServerReceiver;
import com.google.api.client.googleapis.auth.oauth2.GoogleAuthorizationCodeFlow;
import com.google.api.client.googleapis.auth.oauth2.GoogleCredential;
import com.google.api.client.googleapis.auth.oauth2.GoogleTokenResponse;
import com.google.api.client.googleapis.javanet.GoogleNetHttpTransport;
import com.google.api.client.http.HttpRequestInitializer;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.http.json.JsonHttpContent;
import com.google.api.client.json.JsonFactory;
import com.google.api.client.json.gson.GsonFactory;
import com.google.api.services.people.v1.PeopleService;
import com.google.api.services.people.v1.PeopleServiceScopes;
import com.google.api.services.people.v1.model.ListConnectionsResponse;
import com.google.api.services.people.v1.model.Name;
import com.google.api.services.people.v1.model.Person;
import com.google.common.base.Splitter;
import org.apache.commons.lang3.StringUtils;
import org.jboss.logging.Logger;
import org.keycloak.component.ComponentModel;
import org.keycloak.models.*;
import org.keycloak.representations.AccessToken;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.storage.StorageId;
import org.keycloak.storage.UserStorageManager;
import org.keycloak.storage.UserStorageProvider;
import org.keycloak.storage.user.UserLookupProvider;
import org.keycloak.storage.user.UserQueryProvider;
import org.keycloak.storage.user.UserRegistrationProvider;
import org.sunbird.keycloak.utils.Constants;
import org.sunbird.keycloak.utils.HttpClientUtil;

import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.MediaType;

import static org.keycloak.models.Constants.CLIENT_ID;
//import com.google.api.client.json.JacksonFactory;

public class UserServiceProvider implements UserStorageProvider, UserLookupProvider, UserQueryProvider, UserProvider {
  private static final Logger logger = Logger.getLogger(UserStorageProvider.class);

  public static final String PASSWORD_CACHE_KEY = UserAdapter.class.getName() + ".password";
  private final KeycloakSession session;
  private final ComponentModel model;
  private final UserService userService;

  public UserServiceProvider(KeycloakSession session, ComponentModel model,
      UserService userService) {
    this.session = session;
    this.model = model;
    this.userService = userService;
  }

  @Override
  public void addFederatedIdentity(RealmModel realm, UserModel user, FederatedIdentityModel socialLink) {

  }

  @Override
  public boolean removeFederatedIdentity(RealmModel realm, UserModel user, String socialProvider) {
    return false;
  }

  @Override
  public void updateFederatedIdentity(RealmModel realm, UserModel federatedUser, FederatedIdentityModel federatedIdentityModel) {

  }

  @Override
  public Set<FederatedIdentityModel> getFederatedIdentities(UserModel user, RealmModel realm) {
    return null;
  }

  @Override
  public FederatedIdentityModel getFederatedIdentity(UserModel user, String socialProvider, RealmModel realm) {
    return null;
  }

  @Override
  public UserModel getUserByFederatedIdentity(FederatedIdentityModel socialLink, RealmModel realm) {
    return null;
  }

  @Override
  public void addConsent(RealmModel realm, String userId, UserConsentModel consent) {

  }

  @Override
  public UserConsentModel getConsentByClient(RealmModel realm, String userId, String clientInternalId) {
    return null;
  }

  @Override
  public List<UserConsentModel> getConsents(RealmModel realm, String userId) {
    return null;
  }

  @Override
  public void updateConsent(RealmModel realm, String userId, UserConsentModel consent) {

  }

  @Override
  public boolean revokeConsentForClient(RealmModel realm, String userId, String clientInternalId) {
    return false;
  }

  @Override
  public void setNotBeforeForUser(RealmModel realm, UserModel user, int notBefore) {

  }

  @Override
  public int getNotBeforeOfUser(RealmModel realm, UserModel user) {
    return 0;
  }

  @Override
  public UserModel getServiceAccount(ClientModel client) {
    return null;
  }

  @Override
  public List<UserModel> getUsers(RealmModel realm, boolean includeServiceAccounts) {
    return null;
  }

  @Override
  public List<UserModel> getUsers(RealmModel realm, int firstResult, int maxResults, boolean includeServiceAccounts) {
    return null;
  }

  @Override
  public UserModel addUser(RealmModel realm, String id, String username, boolean addDefaultRoles, boolean addDefaultRequiredActions) {
    logger.info("UserServiceProvider: addUser called");
    logger.info("UserServiceProvider: RealmModel :"+realm);
    logger.info("UserServiceProvider: username :"+username);
    logger.info("UserServiceProvider: username :"+id);
    return null;
  }

  @Override
  public void removeImportedUsers(RealmModel realm, String storageProviderId) {

  }

  @Override
  public void unlinkUsers(RealmModel realm, String storageProviderId) {

  }

  @Override
  public void preRemove(RealmModel realm, ClientModel client) {

  }

  @Override
  public void preRemove(ProtocolMapperModel protocolMapper) {

  }

  @Override
  public void preRemove(ClientScopeModel clientScope) {

  }

  @Override
  public void close() {}

  @Override
  public void preRemove(RealmModel realm, ComponentModel component) {

  }

  @Override
  public UserModel getUserById(String id, RealmModel realm) {
    logger.info("UserServiceProvider:getUserById: id = " + id);
    String externalId = StorageId.externalId(id);
    logger.info("UserServiceProvider:getUserById: externalId found = " + externalId);
    return new UserAdapter(session, realm, model, userService.getById(externalId));
  }

  @Override
  public UserModel getUserByUsername(String username, RealmModel realm) {
    logger.info("UserServiceProvider: getUserByUsername called");
    List<User> users = userService.getByUsername(username);
    if (users != null && users.size() == 1) {
      return new UserAdapter(session, realm, model, users.get(0));
    } else if (users != null && users.size() > 1) {
      throw new ModelDuplicateException(
          "Multiple users are associated with this login credentials.", "login credentials");
    } else {
      return null;
    }
  }

  @Override
  public UserModel getUserByEmail(String email, RealmModel realm) {
    logger.info("UserServiceProvider: getUserByEmail called");
    return getUserByUsername(email, realm);
  }

  @Override
  public int getUsersCount(RealmModel realm) {
    return 0;
  }

  @Override
  public int getUsersCount(RealmModel realm, boolean includeServiceAccount) {
    return 0;
  }

  @Override
  public List<UserModel> getUsers(RealmModel realm) {
    return Collections.emptyList();
  }

  @Override
  public List<UserModel> getUsers(RealmModel realm, int firstResult, int maxResults) {
    return Collections.emptyList();
  }

  @Override
  public List<UserModel> searchForUser(String search, RealmModel realm) {
    logger.info("UserServiceProvider: searchForUser called");
    return userService.getByUsername(search).stream()
        .map(user -> new UserAdapter(session, realm, model, user)).collect(Collectors.toList());
  }

  @Override
  public List<UserModel> searchForUser(String search, RealmModel realm, int firstResult,
      int maxResults) {
    logger.info("UserServiceProvider: searchForUser called with firstResult = " + firstResult);
    return searchForUser(search, realm);
  }

  @Override
  public List<UserModel> searchForUser(Map<String, String> params, RealmModel realm) {
    return Collections.emptyList();
  }

  @Override
  public List<UserModel> searchForUser(Map<String, String> params, RealmModel realm,
      int firstResult, int maxResults) {

    return Collections.emptyList();
  }

  @Override
  public List<UserModel> getGroupMembers(RealmModel realm, GroupModel group, int firstResult,
      int maxResults) {

    return Collections.emptyList();
  }

  @Override
  public List<UserModel> getRoleMembers(RealmModel realm, RoleModel role) {
    return null;
  }

  @Override
  public List<UserModel> getRoleMembers(RealmModel realm, RoleModel role, int firstResult, int maxResults) {
    return null;
  }

  @Override
  public List<UserModel> getGroupMembers(RealmModel realm, GroupModel group) {

    return Collections.emptyList();
  }

  @Override
  public List<UserModel> searchForUserByUserAttribute(String attrName, String attrValue,
      RealmModel realm) {
    logger.info("UserServiceProvider: searchForUserByUserAttribute called");
    if (Constants.PHONE.equalsIgnoreCase(attrName)) {
      return userService.getByKey(attrName, attrValue).stream()
          .map(user -> new UserAdapter(session, realm, model, user)).collect(Collectors.toList());
    }
    return Collections.emptyList();
  }

 /* @Override
  public UserModel addUser(RealmModel realm, String username) {
    //super.addUser( realm,  username);
    logger.info("UserServiceProvider: addUser called");
    logger.info("UserServiceProvider: RealmModel :"+realm);
    logger.info("UserServiceProvider: username :"+username);

    GoogleAuthorizationCodeFlow flow = new GoogleAuthorizationCodeFlow.Builder(
            new NetHttpTransport(), new GsonFactory(), "113975703552-4knb62rjo9ia27eh208tqc1dokrgcgvq.apps.googleusercontent.com", "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",
            Arrays.asList(PeopleServiceScopes.USERINFO_EMAIL, PeopleServiceScopes.USERINFO_PROFILE))
            .setAccessType("offline")
            .setApprovalPrompt("force")
            .build();
    logger.info("flow:"+ flow.newAuthorizationUrl().getHost());
    String authorizationUrl = flow.newAuthorizationUrl().setRedirectUri("http://localhost:8080/callback").build();
    logger.info("authorizationUrl:"+ authorizationUrl);


    *//*ObjectMapper mapper = new ObjectMapper();
    HttpClientUtil.getInstance();
    String authKey = Constants.BEARER + " " + authorizationKey;
    Map<String, String> headers = new HashMap<>();
    headers.put(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON);
    headers.put(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON);
    if (StringUtils.isNotBlank(authKey)) {
      headers.put(HttpHeaders.AUTHORIZATION, authKey);
    }
    String response = HttpClientUtil.post(uri, mapper.writeValueAsString(requestBody), headers);*//*


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
    HttpRequestInitializer requestInitializer = null;
    try {
       requestInitializer = new GoogleCredential.Builder()
              .setTransport(GoogleNetHttpTransport.newTrustedTransport())
              .setJsonFactory(new GsonFactory())

              .build().setAccessToken(accessToken);
    } catch (GeneralSecurityException e) {
      throw new RuntimeException(e);
    } catch (IOException e) {
      throw new RuntimeException(e);
    }

   *//* GoogleCredential credential = null;
    GoogleCredential credential1 = null;
    try {
      // Load the credentials from the downloaded JSON file.
      *//**//*credential = GoogleCredential.fromStream(new FileInputStream("/Users/harikumarpalemkota/Documents/workspace/sunbird-auth/keycloak/sms-provider/src/main/resources/credentials.json"))
              .createScoped(Collections.singleton("PLUS_ME"));*//**//*
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
    }*//*

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
    } catch (IOException e) {
      // Handle the exception.
      logger.error("error in profile:"+ e.getMessage());
    }

    // Create a new User object using the retrieved profile information.
    User user = new User();
    user.setUsername(username);
    user.setEmail(profile.getEmailAddresses().get(0).getValue());
    user.setFirstName(profile.getNames().get(0).getGivenName());
    user.setLastName(profile.getNames().get(0).getFamilyName());
    logger.info("UserServiceProvider: addUser info called");
    logger.info("UserServiceProvider: user-firstname :"+user.getFirstName());
    logger.info("UserServiceProvider: user-lastname :"+user.getLastName());
    logger.info("UserServiceProvider: user-email :"+user.getEmail());
    // Add the new User object to the Realm instance.
    //realm.add(user);

    *//*UserModel userModel =new UserStorageManager(session).addUser(realm,username);

    logger.info("UserServiceProvider: email :"+userModel.getEmail());
    logger.info("UserServiceProvider: firstname :"+userModel.getFirstName());
    logger.info("UserServiceProvider: id :"+userModel.getId());*//*
    *//*JsonHttpContent JsonHttpContent = new JsonHttpContent().getJsonFactory()
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
    AuthenticationFlowContext flow = authManager.authenticate(identityProvider("google").build());*//*
    return null;
  }*/

  @Override
  public UserModel addUser(RealmModel realm, String username) {
    //super.addUser( realm,  username);
    logger.info("UserServiceProvider: addUser called");
    logger.info("UserServiceProvider: RealmModel :"+realm);
    logger.info("UserServiceProvider: username :"+username);
    final JsonFactory JSON_FACTORY = GsonFactory.getDefaultInstance();
    final String APPLICATION_NAME = "Google People API Java Quickstart";

    final NetHttpTransport HTTP_TRANSPORT;
    try {
      HTTP_TRANSPORT = GoogleNetHttpTransport.newTrustedTransport();
    } catch (GeneralSecurityException e) {
      logger.error("NetHttpTransport: error 1 "+ e.getMessage());
      throw new RuntimeException(e);
    } catch (IOException e) {
      logger.error("NetHttpTransport: error 2 "+ e.getMessage());
      throw new RuntimeException(e);
    }

    PeopleService service = null;
    try {
      service =
              new PeopleService.Builder(HTTP_TRANSPORT, JSON_FACTORY, getCredentials(HTTP_TRANSPORT))
                      .setApplicationName(APPLICATION_NAME)
                      .build();
    } catch (IOException e) {
      logger.error("PeopleService: error "+ e.getMessage());
      throw new RuntimeException(e);
    }

    // Request 10 connections.
    ListConnectionsResponse response = null;
    try {
      response = service.people().connections()
              .list("people/me")
              .setPageSize(10)
              .setPersonFields("names,emailAddresses")
              .execute();
    } catch (IOException e) {
      logger.error("PeopleService response: error "+ e.getMessage());
      throw new RuntimeException(e);
    }

    // Print display name of connections if available.
    List<Person> connections = response.getConnections();
    if (connections != null && connections.size() > 0) {
      for (Person person : connections) {
        List<Name> names = person.getNames();
        if (names != null && names.size() > 0) {
          System.out.println("Name: " + person.getNames().get(0)
                  .getDisplayName());
        } else {
          System.out.println("No names available for connection.");
        }
      }
    } else {
      System.out.println("No connections found.");
    }


  return null;
  }

  public String extractAuthorizationCode(String callbackUrl) throws URISyntaxException {
    URI uri = new URI(callbackUrl);
    String query = uri.getQuery();
    Map<String, String> queryParams = Splitter.on('&').withKeyValueSeparator('=').split(query);
    return queryParams.get("code");
  }

//  @Override
//  public UserModel addUser(RealmModel realm, String id, String username, boolean addDefaultRoles, boolean addDefaultRequiredActions) {
//    new UserStorageManager().addUser()
//    logger.info("UserServiceProvider: addUser called");
//    logger.info("UserServiceProvider: RealmModel :"+realm);
//    logger.info("UserServiceProvider: id :"+id);
//    logger.info("UserServiceProvider: username :"+username);
//    return null;
//  }

  private static Credential getCredentials(final NetHttpTransport HTTP_TRANSPORT)
          throws IOException {
    // Load client secrets.
        /*InputStream in = PeopleQuickstart.class.getResourceAsStream(CREDENTIALS_FILE_PATH);
        if (in == null) {
            throw new FileNotFoundException("Resource not found: " + CREDENTIALS_FILE_PATH);
        }
        GoogleClientSecrets clientSecrets =
                GoogleClientSecrets.load(JSON_FACTORY, new InputStreamReader(in));

        // Build flow and trigger user authorization request.
        GoogleAuthorizationCodeFlow flow = new GoogleAuthorizationCodeFlow.Builder(
                HTTP_TRANSPORT, JSON_FACTORY, clientSecrets, SCOPES)
                .setDataStoreFactory(new FileDataStoreFactory(new java.io.File(TOKENS_DIRECTORY_PATH)))
                .setAccessType("offline")
                .build();*/

    GoogleAuthorizationCodeFlow flow = new GoogleAuthorizationCodeFlow.Builder(
            new NetHttpTransport(), new GsonFactory(), "113975703552-4knb62rjo9ia27eh208tqc1dokrgcgvq.apps.googleusercontent.com", "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",
            Arrays.asList(PeopleServiceScopes.USERINFO_EMAIL, PeopleServiceScopes.USERINFO_PROFILE,
                    PeopleServiceScopes.CONTACTS, PeopleServiceScopes.USER_ADDRESSES_READ, PeopleServiceScopes.DIRECTORY_READONLY,
                    PeopleServiceScopes.CONTACTS_READONLY, PeopleServiceScopes.USER_ADDRESSES_READ, PeopleServiceScopes.USER_ADDRESSES_READ,
                    PeopleServiceScopes.USER_BIRTHDAY_READ, PeopleServiceScopes.USER_EMAILS_READ, PeopleServiceScopes.USER_GENDER_READ,
                    PeopleServiceScopes.USER_PHONENUMBERS_READ))
            .setAccessType("offline")
            .setApprovalPrompt("force")
            .build();
    LocalServerReceiver receiver = new LocalServerReceiver.Builder().setPort(8888).build();
    return new AuthorizationCodeInstalledApp(flow, receiver).authorize("user");
  }

  @Override
  public boolean removeUser(RealmModel realm, UserModel user) {
    return false;
  }

  @Override
  public void grantToAllUsers(RealmModel realm, RoleModel role) {

  }

  @Override
  public void preRemove(RealmModel realm) {
    UserStorageProvider.super.preRemove(realm);
  }

  @Override
  public void preRemove(RealmModel realm, GroupModel group) {
    UserStorageProvider.super.preRemove(realm, group);
  }

  @Override
  public void preRemove(RealmModel realm, RoleModel role) {
    UserStorageProvider.super.preRemove(realm, role);
  }
}
