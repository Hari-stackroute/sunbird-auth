package org.sunbird.keycloak.storage.spi;

import com.datastax.driver.core.ResultSet;
import com.datastax.driver.core.Row;
import java.util.Collections;
import java.util.List;
import org.jboss.logging.Logger;
import org.sunbird.keycloak.utils.CassandraConnection;
import org.sunbird.keycloak.utils.Constants;

public class UserService {

  private static Logger logger = Logger.getLogger(UserService.class);

  private DecryptionService decryptionService = new DefaultDecryptionServiceImpl();
  private CassandraConnection connection;

  public UserService() {
    connection = CassandraConnection.getInstance();
  }

  public User getById(String id) {
    ResultSet rs =
        this.connection.getSession().execute("select * from sunbird.user where id = '" + id + "'");
    Row r = rs.one();
    User user = new User(r.getString(Constants.ID), r.getString(Constants.FIRST_NAME), "");
    String email = decrypt(r.getString(Constants.EMAIL));
    user.setEmail(email);
    String username = decrypt(r.getString(Constants.USERNAME.toLowerCase()));
    user.setUsername(username);
    String phone = decrypt(r.getString(Constants.PHONE));
    user.setPhone(phone);
    user.setLastName(r.getString(Constants.LAST_NAME));
    user.setCountryCode(r.getString("countrycode"));
    if (r.getBool("isdeleted")) {
      user.setEnabled(false);
    } else {
      user.setEnabled(true);
    }
    return user;
  }

  public List<User> getByUsername(String username) {
    List<User> users = null;
    String numberRegex = "\\d+";
    // mobile number length is of 10 digit
    if (username.matches(numberRegex) && 10 == username.length()) {
      users = getByKey(Constants.PHONE, username);
      if (users != null) {
        return users;
      }
    }
    String emailRegex = "^[_A-Za-z0-9-\\+]+(\\.[_A-Za-z0-9-]+)*@"
        + "[A-Za-z0-9-]+(\\.[A-Za-z0-9]+)*(\\.[A-Za-z]{2,})$";
    if (username.matches(emailRegex)) {
      users = getByKey(Constants.EMAIL, username);
      if (users != null)
        return users;
    } else {
      users = getByKey(Constants.USERNAME, username);
      if (users != null)
        return users;
    }
    return Collections.emptyList();
  }


  private String decrypt(String data) {
    return decryptionService.decryptData(data);
  }

  public List<User> getByKey(String key, String searchValue) {
    logger.info("calling ES search api");
    return EsOperation.getUserByKey(key, searchValue);
  }
}
