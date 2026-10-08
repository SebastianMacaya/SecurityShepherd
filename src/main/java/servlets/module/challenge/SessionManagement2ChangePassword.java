package servlets.module.challenge;

import dbProcs.Database;
import java.io.IOException;
import java.io.Serializable;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Base64;
import java.util.Locale;
import java.util.Properties;
import java.util.ResourceBundle;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;
import javax.mail.Authenticator;
import javax.mail.Message;
import javax.mail.MessagingException;
import javax.mail.PasswordAuthentication;
import javax.mail.Transport;
import javax.mail.internet.AddressException;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeMessage;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import utils.ShepherdLogManager;
import utils.Validate;

/**
 * Session Management Challenge Two - Password recovery servlet. This file is part of the Security
 * Shepherd Project and is distributed under the GNU General Public License, version 3 or later.
 *
 * @author Mark Denihan
 */
public class SessionManagement2ChangePassword extends HttpServlet {

  private static final long serialVersionUID = 1L;
  private static final Logger log = LogManager.getLogger(SessionManagement2ChangePassword.class);
  private static final String CHALLENGE_SCHEMA = "BrokenAuthAndSessMangChalTwo";
  private static final String PENDING_RESET = "sessionManagement2PendingReset";
  private static final long RESET_TTL_MILLIS = 10 * 60 * 1000L;
  private static final long SEND_COOLDOWN_MILLIS = 60 * 1000L;
  private static final SecureRandom RANDOM = new SecureRandom();
  private final ConcurrentHashMap<String, Long> lastSentAtByEmail = new ConcurrentHashMap<>();

  public static String levelHash =
      "f5ddc0ed2d30e597ebacf5fdd117083674b19bb92ffc3499121b9e6a12c92959";

  @Override
  public void doPost(HttpServletRequest request, HttpServletResponse response)
      throws ServletException, IOException {
    ShepherdLogManager.setRequestIp(request.getRemoteAddr(), request.getHeader("X-Forwarded-For"));
    HttpSession session = request.getSession(false);
    Locale locale = new Locale(Validate.validateLanguage(session));
    ResourceBundle bundle =
        ResourceBundle.getBundle(
            "i18n.servlets.challenges.sessionManagement.sessionManagement2", locale);

    if (!Validate.validateSession(session)) {
      response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
      return;
    }

    ShepherdLogManager.setRequestIp(
        request.getRemoteAddr(),
        request.getHeader("X-Forwarded-For"),
        session.getAttribute("userName").toString());

    String email = request.getParameter("subEmail");
    if (!validEmail(email)) {
      response.sendError(HttpServletResponse.SC_BAD_REQUEST);
      return;
    }

    String code = request.getParameter("resetCode");
    String newPassword = request.getParameter("newPassword");
    boolean requestingCode = code == null && newPassword == null;
    if (requestingCode && !smtpConfigured()) {
      response.sendError(HttpServletResponse.SC_SERVICE_UNAVAILABLE);
      return;
    }

    try (Connection connection = openChallengeConnection()) {
      if (requestingCode) {
        // Give the same response whether or not the address belongs to an account.
        try {
          requestReset(connection, session, email);
        } catch (MessagingException e) {
          log.error("Challenge 2 reset message could not be delivered", e);
        }
        response.getWriter().write(bundle.getString("response.requestAccepted"));
      } else if (confirmReset(connection, session, email, code, newPassword)) {
        response.getWriter().write(bundle.getString("response.passwordChanged"));
      } else {
        response.sendError(HttpServletResponse.SC_BAD_REQUEST);
      }
    } catch (Exception e) {
      log.error("Challenge 2 password reset failed", e);
      response.sendError(HttpServletResponse.SC_SERVICE_UNAVAILABLE);
    }
  }

  /** Issues a code only to the stored address. Asking for a code never changes a password. */
  boolean requestReset(Connection connection, HttpSession session, String email) throws Exception {
    if (!validEmail(email)) {
      return false;
    }

    int userId;
    try (PreparedStatement statement =
        connection.prepareStatement("SELECT userId FROM users WHERE userAddress = ?")) {
      statement.setString(1, email);
      try (ResultSet result = statement.executeQuery()) {
        if (!result.next()) {
          return false;
        }
        userId = result.getInt(1);
        // A shared address cannot identify one account safely.
        if (result.next()) {
          return false;
        }
      }
    }

    long now = nowMillis();
    AtomicBoolean permitted = new AtomicBoolean();
    lastSentAtByEmail.compute(
        email,
        (address, previous) -> {
          if (previous != null && now - previous < SEND_COOLDOWN_MILLIS) {
            return previous;
          }
          permitted.set(true);
          return now;
        });
    if (!permitted.get()) {
      return false;
    }

    byte[] codeBytes = new byte[16];
    RANDOM.nextBytes(codeBytes);
    String code = Base64.getUrlEncoder().withoutPadding().encodeToString(codeBytes);
    try {
      sendResetCode(email, code);
    } catch (Exception e) {
      lastSentAtByEmail.remove(email, now);
      throw e;
    }
    session.setAttribute(
        PENDING_RESET, new PendingReset(userId, email, digest(code), now + RESET_TTL_MILLIS));
    return true;
  }

  /** Accepts a code once, for its original account, before changing that account's password. */
  boolean confirmReset(
      Connection connection, HttpSession session, String email, String code, String newPassword)
      throws SQLException {
    if (!validEmail(email)
        || code == null
        || code.length() > 64
        || newPassword == null
        || !Validate.isValidPassword(newPassword)) {
      return false;
    }

    PendingReset pending;
    synchronized (session) {
      Object stored = session.getAttribute(PENDING_RESET);
      if (!(stored instanceof PendingReset)) {
        return false;
      }
      pending = (PendingReset) stored;
      if (nowMillis() > pending.expiresAt) {
        session.removeAttribute(PENDING_RESET);
        return false;
      }
      if (!pending.email.equals(email) || !MessageDigest.isEqual(pending.codeHash, digest(code))) {
        return false;
      }
      session.removeAttribute(PENDING_RESET);
    }

    try (PreparedStatement statement =
        connection.prepareStatement(
            "UPDATE users SET userPassword = SHA(?) WHERE userId = ? AND userAddress = ?")) {
      statement.setString(1, newPassword);
      statement.setInt(2, pending.userId);
      statement.setString(3, pending.email);
      return statement.executeUpdate() == 1;
    }
  }

  protected long nowMillis() {
    return System.currentTimeMillis();
  }

  protected Connection openChallengeConnection() throws SQLException {
    return Database.getChallengeConnection(getServletContext().getRealPath(""), CHALLENGE_SCHEMA);
  }

  /**
   * SMTP is configured with SECURITY_SHEPHERD_CHAL2_SMTP_HOST, _PORT, _FROM, _USER and _PASSWORD.
   * STARTTLS is mandatory. Tests replace this method with an in-memory sender.
   */
  protected void sendResetCode(String email, String code) throws MessagingException {
    if (!smtpConfigured()) {
      throw new MessagingException("Challenge 2 SMTP is not configured");
    }

    String host = System.getenv("SECURITY_SHEPHERD_CHAL2_SMTP_HOST");
    String port = System.getenv("SECURITY_SHEPHERD_CHAL2_SMTP_PORT");
    String from = System.getenv("SECURITY_SHEPHERD_CHAL2_SMTP_FROM");
    String user = System.getenv("SECURITY_SHEPHERD_CHAL2_SMTP_USER");
    String password = System.getenv("SECURITY_SHEPHERD_CHAL2_SMTP_PASSWORD");

    Properties properties = new Properties();
    properties.setProperty("mail.smtp.host", host);
    properties.setProperty("mail.smtp.port", port);
    properties.setProperty("mail.smtp.auth", "true");
    properties.setProperty("mail.smtp.starttls.enable", "true");
    properties.setProperty("mail.smtp.starttls.required", "true");
    properties.setProperty("mail.smtp.ssl.checkserveridentity", "true");
    properties.setProperty("mail.smtp.connectiontimeout", "5000");
    properties.setProperty("mail.smtp.timeout", "5000");
    properties.setProperty("mail.smtp.writetimeout", "5000");

    javax.mail.Session mailSession =
        javax.mail.Session.getInstance(
            properties,
            new Authenticator() {
              @Override
              protected PasswordAuthentication getPasswordAuthentication() {
                return new PasswordAuthentication(user, password);
              }
            });
    MimeMessage message = new MimeMessage(mailSession);
    message.setFrom(new InternetAddress(from));
    message.setRecipient(Message.RecipientType.TO, new InternetAddress(email));
    message.setSubject("Security Shepherd Challenge 2 reset code", StandardCharsets.UTF_8.name());
    message.setText(
        "Enter this code in the same browser to reset your Challenge 2 password: "
            + code
            + "\nThe code expires in 10 minutes.\n",
        StandardCharsets.UTF_8.name());
    Transport.send(message);
  }

  protected boolean smtpConfigured() {
    String host = System.getenv("SECURITY_SHEPHERD_CHAL2_SMTP_HOST");
    String port = System.getenv("SECURITY_SHEPHERD_CHAL2_SMTP_PORT");
    String from = System.getenv("SECURITY_SHEPHERD_CHAL2_SMTP_FROM");
    String user = System.getenv("SECURITY_SHEPHERD_CHAL2_SMTP_USER");
    String password = System.getenv("SECURITY_SHEPHERD_CHAL2_SMTP_PASSWORD");
    if (host == null
        || host.isEmpty()
        || port == null
        || !validEmail(from)
        || user == null
        || user.isEmpty()
        || password == null
        || password.isEmpty()) {
      return false;
    }
    try {
      int parsedPort = Integer.parseInt(port);
      return parsedPort > 0 && parsedPort <= 65535;
    } catch (NumberFormatException e) {
      return false;
    }
  }

  private static boolean validEmail(String email) {
    if (email == null
        || email.isEmpty()
        || email.length() > 128
        || email.contains("\r")
        || email.contains("\n")) {
      return false;
    }
    try {
      InternetAddress address = new InternetAddress(email, true);
      address.validate();
      return email.equals(address.getAddress());
    } catch (AddressException e) {
      return false;
    }
  }

  private static byte[] digest(String code) {
    try {
      return MessageDigest.getInstance("SHA-256").digest(code.getBytes(StandardCharsets.UTF_8));
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException("SHA-256 unavailable", e);
    }
  }

  private static final class PendingReset implements Serializable {
    private static final long serialVersionUID = 1L;
    private final int userId;
    private final String email;
    private final byte[] codeHash;
    private final long expiresAt;

    private PendingReset(int userId, String email, byte[] codeHash, long expiresAt) {
      this.userId = userId;
      this.email = email;
      this.codeHash = codeHash;
      this.expiresAt = expiresAt;
    }
  }
}
