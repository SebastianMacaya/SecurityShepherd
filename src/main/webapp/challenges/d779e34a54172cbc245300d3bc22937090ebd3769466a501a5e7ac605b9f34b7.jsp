<%@ page contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"
	language="java" import="utils.*" errorPage=""%>
<%@ page import="java.util.Locale, java.util.ResourceBundle"%>
<%
// Broken Authentication and Session Management Challenge Two

/**
 * <br/><br/>
 * This file is part of the Security Shepherd Project.
 * 
 * The Security Shepherd project is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.<br/>
 * 
 * The Security Shepherd project is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.<br/>
 * 
 * You should have received a copy of the GNU General Public License
 * along with the Security Shepherd project.  If not, see <http://www.gnu.org/licenses/>. 
 *
 * @author Mark Denihan
 */

String levelHash = "d779e34a54172cbc245300d3bc22937090ebd3769466a501a5e7ac605b9f34b7";
String levelName = "Session Management Challenge Two";

//Translation Stuff
Locale locale = new Locale(Validate.validateLanguage(request.getSession()));
ResourceBundle bundle = ResourceBundle.getBundle("i18n.challenges.sessionManagement." + levelHash, locale);
//Used more than once translations
String translatedLevelName = bundle.getString("challenge.challengeName");

ShepherdLogManager.logEvent(request.getRemoteAddr(), request.getHeader("X-Forwarded-For"), levelName + " Accessed");
if (request.getSession() != null)
{
 	HttpSession ses = request.getSession();
 	//Getting CSRF Token from client
 	Cookie tokenCookie = null;
 	try
 	{
 		tokenCookie = Validate.getToken(request.getCookies());
 	}
 	catch(Exception htmlE)
 	{
 		ShepherdLogManager.logEvent(request.getRemoteAddr(), request.getHeader("X-Forwarded-For"), levelName +".jsp: tokenCookie Error:" + htmlE.toString());
 	}
 	// validateSession ensures a valid session, and valid role credentials
 	// If tokenCookie == null, then the page is not going to continue loading
 	if (Validate.validateSession(ses) && tokenCookie != null)
 	{
 		ShepherdLogManager.logEvent(request.getRemoteAddr(), request.getHeader("X-Forwarded-For"), levelName + " has been accessed by " + ses.getAttribute("userName").toString(), ses.getAttribute("userName"));

%>
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<meta http-equiv="content-type" content="text/html; charset=utf-8" />
<title>Security Shepherd - <%= translatedLevelName %></title>
<link href="../css/lessonCss/theCss.css" rel="stylesheet"
	type="text/css" media="screen" />

</head>
<body>
	<script type="text/javascript" src="../js/jquery.js"></script>
	<script type="text/javascript"
		src="../js/clipboard-js/clipboard.min.js"></script>
	<script type="text/javascript" src="../js/clipboard-js/tooltips.js"></script>
	<script type="text/javascript"
		src="../js/clipboard-js/clipboard-events.js"></script>
	<div id="contentDiv">
		<h2 class="title"><%= translatedLevelName %></h2>
		<p>
			<%= bundle.getString("challenge.description") %>
			<br />
		<form id="leForm" action="javascript:;">
			<div id="resultsDiv">
				<table>
					<tr>
						<td><%= bundle.getString("challenge.form.userName") %></td>
						<td><input type="text" id="subName" autocomplete="off" /></td>
					</tr>
					<tr>
						<td><%= bundle.getString("challenge.form.password") %></td>
						<td><input type="password" id="subPassword"
							autocomplete="off" /></td>
					</tr>
					<tr>
						<td colspan="2">
							<div id="submitButton">
								<input type="submit"
									value="<%= bundle.getString("challenge.form.signIn") %>" />
							</div>
						</td>
					</tr>
				</table>
			</div>
			<small><a id="forgottenPasswordLink" href="#"><%= bundle.getString("challenge.form.forgotPass") %></a></small>
		</form>
		<p style="display: none;" id="loadingSign"><%= bundle.getString("challenge.form.loading") %></p>
		<br />
		<div id="forgottenPassDiv" style="display: none;">
			<h2 class='title'><%= bundle.getString("reset.header") %></h2>
			<p><%= bundle.getString("reset.whatToDo") %></p>
			<form id="leForm2" action="javascript:;">
				<label for="resetEmail"><%= bundle.getString("reset.email") %></label>
				<input id="resetEmail" type="email" autocomplete="email" required />
				<input id="resetSubmit" type="submit" value="<%= bundle.getString("reset.requestCode") %>" />
			</form>
			<form id="leForm3" action="javascript:;" style="display: none;">
				<p><%= bundle.getString("reset.enterCode") %></p>
				<label for="resetCode"><%= bundle.getString("reset.code") %></label>
				<input id="resetCode" type="text" autocomplete="one-time-code" required />
				<label for="newPassword"><%= bundle.getString("reset.newPassword") %></label>
				<input id="newPassword" type="password" autocomplete="new-password" minlength="8" required />
				<input id="confirmResetSubmit" type="submit" value="<%= bundle.getString("reset.confirm") %>" />
			</form>
			<p style="display: none;" id="resetLoadingSign"><%= bundle.getString("challenge.form.loading") %></p>
			<div id="resultsDiv2" role="status" aria-live="polite"></div>
		</div>

		</p>
	</div>
	<script>
			$("#leForm").submit(function(){
				
				var theSubName = $("#subName").val();
				var theSubPassword = $("#subPassword").val();
				$("#loadingSign").show("slow");
				$("#forgottenPassDiv").hide("slow");
				$("#resultsDiv").hide("slow", function(){
					var ajaxCall = $.ajax({
						type: "POST",
						url: "<%= levelHash %>",
						data: {
							subName: theSubName,
							subPassword: theSubPassword
						},
						async: false
					});
					if(ajaxCall.status == 200)
					{
						$("#resultsDiv").html(ajaxCall.responseText);
					}
					else
					{
						$("#resultsDiv").html("<p> <%= bundle.getString("error.occurred") %>: " + ajaxCall.status + " " + ajaxCall.statusText + "</p>");
					}
					$("#loadingSign").hide("fast", function(){
						$("#resultsDiv").show("slow");
					});
				});
			});
			
			var requestedEmail = "";
			var resetEndpoint = "f5ddc0ed2d30e597ebacf5fdd117083674b19bb92ffc3499121b9e6a12c92959";

			$("#leForm2").submit(function(event){
				event.preventDefault();
				var email = $("#resetEmail").val();
				requestedEmail = "";
				$("#leForm3").hide();
				$("#resetCode").val("");
				$("#newPassword").val("");
				$("#resetSubmit").prop("disabled", true);
				$("#resetLoadingSign").show();
				$("#resultsDiv2").empty();
				$.ajax({
					type: "POST",
					url: resetEndpoint,
					data: { subEmail: email }
				}).done(function(){
					requestedEmail = email;
					$("#resultsDiv2").text("<%= bundle.getString("reset.requestSent") %>");
					$("#leForm3").show();
				}).fail(function(){
					$("#resultsDiv2").text("<%= bundle.getString("error.occurred") %>");
				}).always(function(){
					$("#resetLoadingSign").hide();
					$("#resetSubmit").prop("disabled", false);
				});
			});

			$("#leForm3").submit(function(event){
				event.preventDefault();
				$("#confirmResetSubmit").prop("disabled", true);
				$("#resetLoadingSign").show();
				$("#resultsDiv2").empty();
				$.ajax({
					type: "POST",
					url: resetEndpoint,
					data: {
						subEmail: requestedEmail,
						resetCode: $("#resetCode").val(),
						newPassword: $("#newPassword").val()
					}
				}).done(function(){
					$("#resultsDiv2").text("<%= bundle.getString("reset.changed") %>");
					$("#leForm3").hide();
					$("#resetCode").val("");
					$("#newPassword").val("");
				}).fail(function(){
					$("#resultsDiv2").text("<%= bundle.getString("reset.failed") %>");
				}).always(function(){
					$("#resetLoadingSign").hide();
					$("#confirmResetSubmit").prop("disabled", false);
				});
			});

			$("#forgottenPasswordLink").click(function(){
				$("#forgottenPassDiv").toggle("slow", function(){
					//Animation Complete
					;
				});
			});
		</script>
	<% if(Analytics.googleAnalyticsOn) { %><%= Analytics.googleAnalyticsScript %>
	<% } %>
</body>
</html>
<% 
	}
	else
	{
		response.sendRedirect("../loggedOutSheep.html");
	}
}
else
{
	response.sendRedirect("../loggedOutSheep.html");
}
%>