package org.minima.system.mds.hub;

public class MDSHubLogon {

	/**
	 * Page shown when IP is blocked after too many failed login attempts
	 * Страница при блокировке IP после слишком многих неудачных попыток входа
	 */
	public static String createBlockedPage() {

		String page = MDSUtil.HUB_START;

		page += MDSUtil.returnLogonHeader();

		page +=
		"<center>"
		+ "<div class='mainlogon'>\n"
		+ "	<h2>Access Blocked</h2>\n"
		+ "	<br>\n"
		+ "	<p style='color:#ff6666;font-size:16px;'>Too many failed login attempts.<br>"
		+ " Your IP is blocked for <b>3 minutes</b>.</p>\n"
		+ "	<br>\n"
		+ "	<p style='color:#aaa;font-size:13px;'>Слишком много неудачных попыток входа.<br>"
		+ " Ваш IP заблокирован на <b>3 минуты</b>.</p>\n"
		+ "	<br><br>\n"
		+ "	<a class='logonbutton' href='index.html' style='text-decoration:none;'>Try Again</a>\n"
		+ "</div>"
		+ "</center>";

		page += MDSUtil.HUB_END;

		return page;
	}

	public static String createHubPage(String zLoginID) {
		
		//Start the HTML
		String page = MDSUtil.HUB_START;
		
		page += MDSUtil.returnLogonHeader();
		
		//Now the Login Form
		page += 
		"<center>"
		+ "<div class='mainlogon'>\n"
		+ "	<h2>MDS Login</h2>\n"
		+ "	<br>\n"
		+"	<form action='login.html' method='post'>\n"
		+ "	\n"
		+ "		<input type='hidden' name='loginid' value='"+zLoginID+"'>\n"
		+ "		<input class='logonentry' type='password' name='password' required/>\n"
		+ "		\n"
		+ "		<input class='logonbutton' style='width:100;' type='submit' value='login' onClick=\"this.form.submit(); this.disabled=true; this.value='Checking..';\"/>\n"
		+ "		\n"
		+ "	</form>\n"
		+ "</div>"
//		+ "<br>"
//		+ "You may only open <b>1</b> MiniHUB at a time<br>"
		+ "</center>";

		
		page += MDSUtil.HUB_END;
		
		return page;
		
	}
}
