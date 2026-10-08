package servlets.module.challenge;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.HashMap;
import java.util.Map;
import javax.mail.MessagingException;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockHttpSession;

class SessionManagement2ChangePasswordTest {

  private static final String ORDINARY_EMAIL = "alice@example.test";
  private static final String NEW_PASSWORD = "A-new-password-2026!";

  @Test
  void validRequestOnlySendsCodeAndValidConfirmationChangesPassword() throws Exception {
    Fixture fixture = new Fixture();

    assertTrue(fixture.servlet.requestReset(fixture.connection, fixture.session, ORDINARY_EMAIL));
    assertNotNull(fixture.servlet.lastCode);
    assertFalse(fixture.servlet.lastCode.isEmpty());
    assertEquals(0, fixture.updateCount, "Requesting a reset must not change a password");

    assertTrue(
        fixture.servlet.confirmReset(
            fixture.connection,
            fixture.session,
            ORDINARY_EMAIL,
            fixture.servlet.lastCode,
            NEW_PASSWORD));
    assertEquals(1, fixture.updateCount);
    assertEquals(NEW_PASSWORD, fixture.boundNewPassword);
    assertEquals(ORDINARY_EMAIL, fixture.boundEmail);
    assertEquals(1001, fixture.boundUserId);
    assertTrue(
        fixture.updateSql.matches(
            "(?is).*\\bWHERE\\s+userId\\s*=\\s*\\?\\s+AND\\s+userAddress\\s*=\\s*\\?.*"),
        "The update must be scoped by the verified user ID and email");
  }

  @Test
  void invalidOrUnknownEmailDoesNotIssueCodeOrChangePassword() throws Exception {
    Fixture fixture = new Fixture();

    assertFalse(fixture.servlet.requestReset(fixture.connection, fixture.session, ""));
    assertFalse(fixture.servlet.requestReset(fixture.connection, fixture.session, "not-an-email"));
    assertFalse(
        fixture.servlet.requestReset(fixture.connection, fixture.session, "missing@example.test"));
    assertTrue(fixture.servlet.lastCode == null);
    assertEquals(0, fixture.updateCount);
  }

  @Test
  void wrongCodeCannotChangePassword() throws Exception {
    Fixture fixture = new Fixture();
    assertTrue(fixture.servlet.requestReset(fixture.connection, fixture.session, ORDINARY_EMAIL));

    assertFalse(
        fixture.servlet.confirmReset(
            fixture.connection, fixture.session, ORDINARY_EMAIL, "wrong-code", NEW_PASSWORD));
    assertEquals(0, fixture.updateCount);
  }

  @Test
  void codeForOneAccountCannotChangeAnotherAccount() throws Exception {
    Fixture fixture = new Fixture();
    assertTrue(fixture.servlet.requestReset(fixture.connection, fixture.session, ORDINARY_EMAIL));

    assertFalse(
        fixture.servlet.confirmReset(
            fixture.connection,
            fixture.session,
            "zoidberg22@shepherd.com",
            fixture.servlet.lastCode,
            NEW_PASSWORD));
    assertEquals(0, fixture.updateCount);
  }

  @Test
  void expiredCodeCannotChangePassword() throws Exception {
    Fixture fixture = new Fixture();
    assertTrue(fixture.servlet.requestReset(fixture.connection, fixture.session, ORDINARY_EMAIL));

    fixture.servlet.currentTimeMillis += 600_001L;
    assertFalse(
        fixture.servlet.confirmReset(
            fixture.connection,
            fixture.session,
            ORDINARY_EMAIL,
            fixture.servlet.lastCode,
            NEW_PASSWORD));
    assertEquals(0, fixture.updateCount);
  }

  @Test
  void usedCodeCannotChangePasswordAgain() throws Exception {
    Fixture fixture = new Fixture();
    assertTrue(fixture.servlet.requestReset(fixture.connection, fixture.session, ORDINARY_EMAIL));
    String code = fixture.servlet.lastCode;
    assertTrue(
        fixture.servlet.confirmReset(
            fixture.connection, fixture.session, ORDINARY_EMAIL, code, NEW_PASSWORD));

    assertFalse(
        fixture.servlet.confirmReset(
            fixture.connection, fixture.session, ORDINARY_EMAIL, code, "Second-password-2026!"));
    assertEquals(1, fixture.updateCount);
  }

  @Test
  void missingNewPasswordCannotChangePassword() throws Exception {
    Fixture fixture = new Fixture();
    assertTrue(fixture.servlet.requestReset(fixture.connection, fixture.session, ORDINARY_EMAIL));

    assertFalse(
        fixture.servlet.confirmReset(
            fixture.connection, fixture.session, ORDINARY_EMAIL, fixture.servlet.lastCode, ""));
    assertEquals(0, fixture.updateCount);
  }

  @Test
  void privilegedAccountsRequireTheirOwnCode() throws Exception {
    String[] privilegedEmails = {
      "zoidberg22@shepherd.com",
      "buzzthebald@shepherd.com",
      "elitehacker@shepherd.com",
      "superman@security.com",
      "spoiltbrat@security.com"
    };

    for (String email : privilegedEmails) {
      Fixture fixture = new Fixture();
      assertFalse(
          fixture.servlet.confirmReset(
              fixture.connection, fixture.session, email, "guessed-code", NEW_PASSWORD));
      assertEquals(0, fixture.updateCount, email);

      assertTrue(fixture.servlet.requestReset(fixture.connection, fixture.session, email), email);
      assertEquals(0, fixture.updateCount, email);
      assertTrue(
          fixture.servlet.confirmReset(
              fixture.connection, fixture.session, email, fixture.servlet.lastCode, NEW_PASSWORD),
          email);
      assertEquals(1, fixture.updateCount, email);
      assertEquals(email, fixture.boundEmail, email);
    }
  }

  @Test
  void repeatedRequestsAreLimitedWithoutInvalidatingTheFirstCode() throws Exception {
    Fixture fixture = new Fixture();
    assertTrue(fixture.servlet.requestReset(fixture.connection, fixture.session, ORDINARY_EMAIL));
    String firstCode = fixture.servlet.lastCode;

    assertFalse(fixture.servlet.requestReset(fixture.connection, fixture.session, ORDINARY_EMAIL));
    assertEquals(1, fixture.servlet.sentCount);
    assertTrue(
        fixture.servlet.confirmReset(
            fixture.connection, fixture.session, ORDINARY_EMAIL, firstCode, NEW_PASSWORD));

    fixture.servlet.currentTimeMillis += 60_000L;
    assertTrue(fixture.servlet.requestReset(fixture.connection, fixture.session, ORDINARY_EMAIL));
    assertEquals(2, fixture.servlet.sentCount);
  }

  @Test
  void failedDeliveryDoesNotUseUpTheSendCooldown() throws Exception {
    Fixture fixture = new Fixture();
    fixture.servlet.failDelivery = true;
    assertThrows(
        MessagingException.class,
        () -> fixture.servlet.requestReset(fixture.connection, fixture.session, ORDINARY_EMAIL));

    fixture.servlet.failDelivery = false;
    assertTrue(fixture.servlet.requestReset(fixture.connection, fixture.session, ORDINARY_EMAIL));
    assertEquals(1, fixture.servlet.sentCount);
  }

  @Test
  void httpFlowRequiresSessionAndNeverReturnsTheCodeOrPassword() throws Exception {
    Fixture fixture = new Fixture();
    MockHttpServletRequest anonymous = new MockHttpServletRequest("POST", "/challenge2/reset");
    anonymous.setParameter("subEmail", ORDINARY_EMAIL);
    MockHttpServletResponse unauthorized = new MockHttpServletResponse();
    fixture.servlet.doPost(anonymous, unauthorized);
    assertEquals(401, unauthorized.getStatus());
    assertEquals(0, fixture.updateCount);

    fixture.session.setAttribute("userRole", "player");
    fixture.session.setAttribute("userName", "testPlayer");
    MockHttpServletRequest request = new MockHttpServletRequest("POST", "/challenge2/reset");
    request.setSession(fixture.session);
    request.setParameter("subEmail", ORDINARY_EMAIL);
    MockHttpServletResponse requestResponse = new MockHttpServletResponse();
    fixture.servlet.doPost(request, requestResponse);
    assertEquals(200, requestResponse.getStatus());
    assertFalse(requestResponse.getContentAsString().contains(fixture.servlet.lastCode));
    assertEquals(0, fixture.updateCount);

    MockHttpServletRequest confirmation = new MockHttpServletRequest("POST", "/challenge2/reset");
    confirmation.setSession(fixture.session);
    confirmation.setParameter("subEmail", ORDINARY_EMAIL);
    confirmation.setParameter("resetCode", fixture.servlet.lastCode);
    confirmation.setParameter("newPassword", NEW_PASSWORD);
    MockHttpServletResponse changed = new MockHttpServletResponse();
    fixture.servlet.doPost(confirmation, changed);
    assertEquals(200, changed.getStatus());
    assertFalse(changed.getContentAsString().contains(NEW_PASSWORD));
    assertEquals(1, fixture.updateCount);
  }

  @Test
  void httpRequestFailsClosedWithoutMailAndDoesNotRevealUnknownAccounts() throws Exception {
    Fixture fixture = new Fixture();
    fixture.session.setAttribute("userRole", "player");
    fixture.session.setAttribute("userName", "testPlayer");

    MockHttpServletRequest unknown = new MockHttpServletRequest("POST", "/challenge2/reset");
    unknown.setSession(fixture.session);
    unknown.setParameter("subEmail", "missing@example.test");
    MockHttpServletResponse unknownResponse = new MockHttpServletResponse();
    fixture.servlet.doPost(unknown, unknownResponse);
    assertEquals(200, unknownResponse.getStatus());

    MockHttpServletRequest known = new MockHttpServletRequest("POST", "/challenge2/reset");
    known.setSession(fixture.session);
    known.setParameter("subEmail", ORDINARY_EMAIL);
    MockHttpServletResponse knownResponse = new MockHttpServletResponse();
    fixture.servlet.doPost(known, knownResponse);
    assertEquals(200, knownResponse.getStatus());
    assertEquals(unknownResponse.getContentAsString(), knownResponse.getContentAsString());

    fixture.servlet.currentTimeMillis += 60_000L;
    fixture.servlet.failDelivery = true;
    MockHttpServletResponse mailFailure = new MockHttpServletResponse();
    fixture.servlet.doPost(known, mailFailure);
    assertEquals(200, mailFailure.getStatus());
    assertEquals(unknownResponse.getContentAsString(), mailFailure.getContentAsString());
    fixture.servlet.failDelivery = false;

    fixture.servlet.mailAvailable = false;
    MockHttpServletResponse unavailable = new MockHttpServletResponse();
    fixture.servlet.doPost(known, unavailable);
    assertEquals(503, unavailable.getStatus());
    assertEquals(0, fixture.updateCount);
  }

  private static final class CapturingServlet extends SessionManagement2ChangePassword {
    private long currentTimeMillis = 1_000_000L;
    private String lastCode;
    private int sentCount;
    private boolean failDelivery;
    private boolean mailAvailable = true;
    private Connection connection;

    @Override
    protected long nowMillis() {
      return currentTimeMillis;
    }

    @Override
    protected void sendResetCode(String email, String code) throws MessagingException {
      if (failDelivery) {
        throw new MessagingException("local delivery failure");
      }
      lastCode = code;
      sentCount++;
    }

    @Override
    protected boolean smtpConfigured() {
      return mailAvailable;
    }

    @Override
    protected Connection openChallengeConnection() {
      return connection;
    }
  }

  private static final class Fixture {
    private final Map<String, Integer> userIds = new HashMap<>();
    private final Connection connection = mock(Connection.class);
    private final PreparedStatement select = mock(PreparedStatement.class);
    private final PreparedStatement update = mock(PreparedStatement.class);
    private final MockHttpSession session = new MockHttpSession();
    private final CapturingServlet servlet = new CapturingServlet();
    private String selectedEmail;
    private String boundEmail;
    private String boundNewPassword;
    private String updateSql;
    private int boundUserId;
    private int updateCount;

    private Fixture() throws SQLException {
      servlet.connection = connection;
      userIds.put(ORDINARY_EMAIL, 1001);
      userIds.put("zoidberg22@shepherd.com", 12);
      userIds.put("buzzthebald@shepherd.com", 321);
      userIds.put("elitehacker@shepherd.com", 3212);
      userIds.put("superman@security.com", 634);
      userIds.put("spoiltbrat@security.com", 4524);

      when(connection.prepareStatement(anyString()))
          .thenAnswer(
              invocation -> {
                String sql = invocation.getArgument(0);
                if (sql.trim().toUpperCase().startsWith("UPDATE")) {
                  updateSql = sql;
                  return update;
                }
                return select;
              });
      when(select.executeQuery())
          .thenAnswer(
              invocation -> {
                ResultSet result = mock(ResultSet.class);
                Integer userId = userIds.get(selectedEmail);
                boolean[] firstCall = {true};
                when(result.next())
                    .thenAnswer(
                        ignored -> {
                          if (firstCall[0]) {
                            firstCall[0] = false;
                            return userId != null;
                          }
                          return false;
                        });
                when(result.getInt(1)).thenReturn(userId == null ? 0 : userId);
                return result;
              });
      org.mockito.Mockito.doAnswer(
              invocation -> {
                selectedEmail = invocation.getArgument(1);
                return null;
              })
          .when(select)
          .setString(org.mockito.ArgumentMatchers.eq(1), anyString());
      org.mockito.Mockito.doAnswer(
              invocation -> {
                int index = invocation.getArgument(0);
                String value = invocation.getArgument(1);
                if (index == 1) {
                  boundNewPassword = value;
                } else if (index == 3) {
                  boundEmail = value;
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
                Integer expectedId = userIds.get(boundEmail);
                return expectedId != null && expectedId == boundUserId ? 1 : 0;
              });
    }
  }
}
