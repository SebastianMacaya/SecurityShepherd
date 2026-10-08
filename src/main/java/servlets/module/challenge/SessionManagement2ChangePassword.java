package servlets.module.challenge;

import dbProcs.Database;
import java.io.IOException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Locale;
import java.util.ResourceBundle;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.owasp.encoder.Encode;
import utils.Hash;
import utils.ShepherdLogManager;
import utils.Validate;

/**
 * Session Management Challenge Two - Password Reset Servlet Does not return result key <br>
 * <br>
 * This file is part of the Security Shepherd Project.
 *
 * <p>The Security Shepherd project is free software: you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free Software Foundation, either
 * version 3 of the License, or (at your option) any later version.<br>
 *
 * <p>The Security Shepherd project is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
 * PURPOSE. See the GNU General Public License for more details.<br>
 *
 * <p>You should have received a copy of the GNU General Public License along with the Security
 * Shepherd project. If not, see <http://www.gnu.org/licenses/>.
 *
 * @author Mark Denihan
 */
public class SessionManagement2ChangePassword extends HttpServlet {

  private static final long serialVersionUID = 1L;
  private static final Logger log = LogManager.getLogger(SessionManagement2ChangePassword.class);
  private static final String CHALLENGE_SCHEMA = "BrokenAuthAndSessMangChalTwo";
  private static final String BLOCKED_ACCOUNT = "admin";
  public static String levelHash =
      "f5ddc0ed2d30e597ebacf5fdd117083674b19bb92ffc3499121b9e6a12c92959";

  @Override
  public void doPost(HttpServletRequest request, HttpServletResponse response)
      throws ServletException, IOException {
    ShepherdLogManager.setRequestIp(request.getRemoteAddr(), request.getHeader("X-Forwarded-For"));
    HttpSession session = request.getSession(false);
    if (!Validate.validateSession(session)) {
      response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
      return;
    }

    ShepherdLogManager.setRequestIp(
        request.getRemoteAddr(),
        request.getHeader("X-Forwarded-For"),
        session.getAttribute("userName").toString());

    String email = request.getParameter("subEmail");
    if (email == null || email.length() > 128 || !email.matches("[^\\s@]+@[^\\s@]+\\.[^\\s@]+")) {
      response.sendError(HttpServletResponse.SC_BAD_REQUEST);
      return;
    }

    Locale locale = new Locale(Validate.validateLanguage(session));
    ResourceBundle bundle =
        ResourceBundle.getBundle(
            "i18n.servlets.challenges.sessionManagement.sessionManagement2", locale);
    String changedTo = bundle.getString("response.changedTo");
    String newPassword = Hash.randomString();

    try (Connection connection = openChallengeConnection()) {
      if (resetPassword(connection, email, newPassword)) {
        response.getWriter().write(changedTo + " " + Encode.forHtml(newPassword));
      } else {
        response.setStatus(HttpServletResponse.SC_FORBIDDEN);
        response.getWriter().write("Password unchanged. " + changedTo + " Unchanged");
      }
    } catch (SQLException e) {
      log.error("Challenge 2 password reset failed", e);
      response.sendError(HttpServletResponse.SC_SERVICE_UNAVAILABLE);
    }
  }

  /** Preserves the legacy reset for non-admin accounts, but never updates the admin account. */
  boolean resetPassword(Connection connection, String email, String newPassword)
      throws SQLException {
    boolean originalAutoCommit = connection.getAutoCommit();
    connection.setAutoCommit(false);
    try {
      int userId;
      try (PreparedStatement lookup =
          connection.prepareStatement(
              "SELECT userId, userName FROM users WHERE userAddress = ? FOR UPDATE")) {
        lookup.setString(1, email);
        try (ResultSet users = lookup.executeQuery()) {
          if (!users.next()) {
            connection.rollback();
            return false;
          }
          userId = users.getInt("userId");
          String userName = users.getString("userName");
          if (userName == null
              || BLOCKED_ACCOUNT.equalsIgnoreCase(userName.trim())
              || users.next()) {
            connection.rollback();
            return false;
          }
        }
      }

      try (PreparedStatement update =
          connection.prepareStatement(
              "UPDATE users SET userPassword = SHA(?) WHERE userId = ? AND userAddress = ?")) {
        update.setString(1, newPassword);
        update.setInt(2, userId);
        update.setString(3, email);
        if (update.executeUpdate() != 1) {
          connection.rollback();
          return false;
        }
      }
      connection.commit();
      return true;
    } catch (SQLException e) {
      try {
        connection.rollback();
      } catch (SQLException rollbackError) {
        e.addSuppressed(rollbackError);
      }
      throw e;
    } finally {
      connection.setAutoCommit(originalAutoCommit);
    }
  }

  protected Connection openChallengeConnection() throws SQLException {
    return Database.getChallengeConnection(getServletContext().getRealPath(""), CHALLENGE_SCHEMA);
  }
}
