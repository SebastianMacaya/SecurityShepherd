package servlets.module.challenge;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import javax.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockServletConfig;

class SessionManagement2ChangePasswordTest {

  private static final String ORDINARY_EMAIL = "alice@example.test";
  private static final String ADMIN_EMAIL = "zoidberg22@shepherd.com";
  private static final String ROOT_EMAIL = "elitehacker@shepherd.com";
  private static final String NEW_PASSWORD = "GeneratedPassword2026";

  @Test
  void ordinaryAccountCanBeResetInAScopedTransaction() throws Exception {
    Fixture fixture = new Fixture();

    assertTrue(fixture.servlet.resetPassword(fixture.connection, ORDINARY_EMAIL, NEW_PASSWORD));

    assertEquals(1, fixture.updateCount);
    assertEquals(NEW_PASSWORD, fixture.boundPassword);
    assertEquals(ORDINARY_EMAIL, fixture.boundUpdateEmail);
    assertEquals(1001, fixture.boundUserId);
    assertTrue(fixture.selectSql.toUpperCase(Locale.ROOT).contains("FOR UPDATE"));
    assertTrue(fixture.updateSql.toLowerCase(Locale.ROOT).contains("userid = ?"));
    assertTrue(fixture.updateSql.toLowerCase(Locale.ROOT).contains("useraddress = ?"));
    verify(fixture.connection).setAutoCommit(false);
    verify(fixture.connection).commit();
    verify(fixture.connection, never()).rollback();
    verify(fixture.connection).setAutoCommit(true);
  }

  @Test
  void adminAccountRemainsUnchangedEvenWithMixedCaseName() throws Exception {
    Fixture fixture = new Fixture();

    assertFalse(fixture.servlet.resetPassword(fixture.connection, ADMIN_EMAIL, NEW_PASSWORD));

    assertEquals(0, fixture.updateCount);
    verify(fixture.connection).rollback();
    verify(fixture.connection, never()).commit();
  }

  @Test
  void missingAccountRemainsUnchanged() throws Exception {
    Fixture fixture = new Fixture();

    assertFalse(
        fixture.servlet.resetPassword(fixture.connection, "missing@example.test", NEW_PASSWORD));

    assertEquals(0, fixture.updateCount);
    verify(fixture.connection).rollback();
    verify(fixture.connection, never()).commit();
  }

  @Test
  void sharedAddressCannotIdentifyOneAccount() throws Exception {
    Fixture fixture = new Fixture();
    fixture.duplicateSelectedEmail = true;

    assertFalse(fixture.servlet.resetPassword(fixture.connection, ORDINARY_EMAIL, NEW_PASSWORD));

    assertEquals(0, fixture.updateCount);
    verify(fixture.connection).rollback();
    verify(fixture.connection, never()).commit();
  }

  @Test
  void zeroUpdatedRowsCausesRollback() throws Exception {
    Fixture fixture = new Fixture();
    fixture.affectedRowsOverride = 0;

    assertFalse(fixture.servlet.resetPassword(fixture.connection, ORDINARY_EMAIL, NEW_PASSWORD));

    assertEquals(1, fixture.updateCount);
    verify(fixture.connection).rollback();
    verify(fixture.connection, never()).commit();
  }

  @Test
  void multipleUpdatedRowsCannotBeReportedAsSuccess() throws Exception {
    Fixture fixture = new Fixture();
    fixture.affectedRowsOverride = 2;

    assertFalse(fixture.servlet.resetPassword(fixture.connection, ORDINARY_EMAIL, NEW_PASSWORD));

    assertEquals(1, fixture.updateCount);
    verify(fixture.connection).rollback();
    verify(fixture.connection, never()).commit();
  }

  @Test
  void anotherPrivilegedNameStillFollowsLegacyResetBehavior() throws Exception {
    Fixture fixture = new Fixture();

    assertTrue(fixture.servlet.resetPassword(fixture.connection, ROOT_EMAIL, NEW_PASSWORD));

    assertEquals(1, fixture.updateCount);
    assertEquals(ROOT_EMAIL, fixture.boundUpdateEmail);
    verify(fixture.connection).commit();
  }

  @Test
  void validHttpRequestReturnsChangedPassword() throws Exception {
    Fixture fixture = new Fixture();
    MockHttpServletRequest request = fixture.authenticatedRequest(ORDINARY_EMAIL);
    MockHttpServletResponse response = new MockHttpServletResponse();

    fixture.servlet.doPost(request, response);

    assertEquals(HttpServletResponse.SC_OK, response.getStatus());
    assertEquals(1, fixture.updateCount);
    assertNotNull(fixture.boundPassword);
    assertTrue(response.getContentAsString().contains("Changed To: " + fixture.boundPassword));
  }

  @Test
  void adminHttpRequestReturnsForbiddenAndNoPassword() throws Exception {
    Fixture fixture = new Fixture();
    MockHttpServletRequest request = fixture.authenticatedRequest(ADMIN_EMAIL);
    MockHttpServletResponse response = new MockHttpServletResponse();

    fixture.servlet.doPost(request, response);

    assertEquals(HttpServletResponse.SC_FORBIDDEN, response.getStatus());
    assertEquals(0, fixture.updateCount);
    assertTrue(response.getContentAsString().contains("Password unchanged. Changed To: Unchanged"));
    verify(fixture.connection, never()).commit();
  }

  @Test
  void unknownEmailHttpRequestReturnsForbidden() throws Exception {
    Fixture fixture = new Fixture();
    MockHttpServletRequest request = fixture.authenticatedRequest("missing@example.test");
    MockHttpServletResponse response = new MockHttpServletResponse();

    fixture.servlet.doPost(request, response);

    assertEquals(HttpServletResponse.SC_FORBIDDEN, response.getStatus());
    assertEquals(0, fixture.updateCount);
    assertTrue(response.getContentAsString().contains("Password unchanged. Changed To: Unchanged"));
  }

  @Test
  void invalidEmailHttpRequestReturnsBadRequestWithoutDatabaseUpdate() throws Exception {
    Fixture fixture = new Fixture();
    MockHttpServletRequest request = fixture.authenticatedRequest("not-an-email");
    MockHttpServletResponse response = new MockHttpServletResponse();

    fixture.servlet.doPost(request, response);

    assertEquals(HttpServletResponse.SC_BAD_REQUEST, response.getStatus());
    assertEquals(0, fixture.updateCount);
    assertEquals(0, fixture.servlet.openCount);
  }

  @Test
  void missingSessionReturnsUnauthorizedWithoutDatabaseUpdate() throws Exception {
    Fixture fixture = new Fixture();
    MockHttpServletRequest request = new MockHttpServletRequest();
    request.setMethod("POST");
    request.addParameter("subEmail", ORDINARY_EMAIL);
    MockHttpServletResponse response = new MockHttpServletResponse();

    fixture.servlet.doPost(request, response);

    assertEquals(HttpServletResponse.SC_UNAUTHORIZED, response.getStatus());
    assertEquals(0, fixture.updateCount);
    assertEquals(0, fixture.servlet.openCount);
  }

  private static final class TestServlet extends SessionManagement2ChangePassword {
    private Connection connection;
    private int openCount;

    @Override
    protected Connection openChallengeConnection() {
      openCount++;
      return connection;
    }
  }

  private static final class Account {
    private final int id;
    private final String name;

    private Account(int id, String name) {
      this.id = id;
      this.name = name;
    }
  }

  private static final class Fixture {
    private final Map<String, Account> users = new HashMap<>();
    private final Connection connection = mock(Connection.class);
    private final PreparedStatement select = mock(PreparedStatement.class);
    private final PreparedStatement update = mock(PreparedStatement.class);
    private final TestServlet servlet = new TestServlet();
    private String selectSql;
    private String updateSql;
    private String boundSelectEmail;
    private String boundUpdateEmail;
    private String boundPassword;
    private int boundUserId;
    private boolean duplicateSelectedEmail;
    private Integer affectedRowsOverride;
    private int updateCount;

    private Fixture() throws Exception {
      users.put(ORDINARY_EMAIL, new Account(1001, "alice"));
      users.put(ADMIN_EMAIL, new Account(12, "ADMIN"));
      users.put(ROOT_EMAIL, new Account(3212, "root"));
      servlet.connection = connection;
      servlet.init(new MockServletConfig("SessionManagement2ChangePassword"));

      when(connection.getAutoCommit()).thenReturn(true);
      when(connection.prepareStatement(anyString()))
          .thenAnswer(
              invocation -> {
                String sql = invocation.getArgument(0);
                if (sql.trim().toUpperCase(Locale.ROOT).startsWith("SELECT")) {
                  selectSql = sql;
                  return select;
                }
                updateSql = sql;
                return update;
              });
      org.mockito.Mockito.doAnswer(
              invocation -> {
                boundSelectEmail = invocation.getArgument(1);
                return null;
              })
          .when(select)
          .setString(org.mockito.ArgumentMatchers.eq(1), anyString());
      when(select.executeQuery())
          .thenAnswer(
              invocation -> {
                ResultSet result = mock(ResultSet.class);
                Account account = users.get(boundSelectEmail);
                int[] cursor = {0};
                when(result.next())
                    .thenAnswer(
                        ignored -> {
                          cursor[0]++;
                          return account != null && cursor[0] <= (duplicateSelectedEmail ? 2 : 1);
                        });
                when(result.getInt(1)).thenReturn(account == null ? 0 : account.id);
                when(result.getInt("userId")).thenReturn(account == null ? 0 : account.id);
                when(result.getString(2)).thenReturn(account == null ? null : account.name);
                when(result.getString("userName"))
                    .thenReturn(account == null ? null : account.name);
                return result;
              });
      org.mockito.Mockito.doAnswer(
              invocation -> {
                int index = invocation.getArgument(0);
                String value = invocation.getArgument(1);
                if (index == 1) {
                  boundPassword = value;
                } else if (index == 3) {
                  boundUpdateEmail = value;
                }
                return null;
              })
          .when(update)
          .setString(org.mockito.ArgumentMatchers.anyInt(), anyString());
      org.mockito.Mockito.doAnswer(
              invocation -> {
                boundUserId = invocation.getArgument(1);
                return null;
              })
          .when(update)
          .setInt(org.mockito.ArgumentMatchers.eq(2), org.mockito.ArgumentMatchers.anyInt());
      when(update.executeUpdate())
          .thenAnswer(
              invocation -> {
                updateCount++;
                if (affectedRowsOverride != null) {
                  return affectedRowsOverride;
                }
                Account account = users.get(boundUpdateEmail);
                return account != null && account.id == boundUserId ? 1 : 0;
              });
    }

    private MockHttpServletRequest authenticatedRequest(String email) {
      MockHttpServletRequest request = new MockHttpServletRequest();
      request.setMethod("POST");
      request.getSession().setAttribute("userName", "challengePlayer");
      request.getSession().setAttribute("userRole", "player");
      request.addParameter("subEmail", email);
      return request;
    }
  }
}
