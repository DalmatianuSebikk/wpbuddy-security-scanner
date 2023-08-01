# WsBuddy output scan for http://192.168.100.28:8000/
## WordPress Core Version discovery and vulnerabilities
WordPress version was found in a **Meta tag** in the homepage: http://192.168.100.28:8000/

WordPress has the version **5.5.11**

Vulnerabilities were found for the current version of WordPress used on the website (**5.5.11**):

- **CVE-2022-21661**: WordPress is a free and open-source content management system written in PHP and paired with a MariaDB database. Due to improper sanitization in WP_Query, there can be cases where SQL injection is possible through plugins or themes that use it in a certain way. This has been patched in WordPress version 5.8.3. Older affected versions are also fixed via security release, that go back till 3.7.37. We strongly recommend that you keep auto-updates enabled. There are no known workarounds for this vulnerability.

- **WordPress <= 5.8.2 - SQL Injection (SQLi) vulnerability**: SQL Injection (SQLi) vulnerability discovered by Ngocnb and Khuyenn (GiaoHangTietKiem JSC) in WordPress (versions <= 5.8.2).

- **WordPress Core &lt; 5.8.3 - SQL Injection via WP_Query**: WordPress is a free and open-source content management system written in PHP and paired with a MariaDB database. Due to improper sanitization in WP_Query, there can be cases where SQL injection is possible through plugins or themes that use it in a certain way. This has been patched in WordPress version 5.8.3. Older affected versions are also fixed via security release, that go back till 3.7.37. We strongly recommend that you keep auto-updates enabled. There are no known workarounds for this vulnerability.

- **CVE-2022-21662**: WordPress is a free and open-source content management system written in PHP and paired with a MariaDB database. Low-privileged authenticated users (like author) in WordPress core are able to execute JavaScript/perform stored XSS attack, which can affect high-privileged users. This has been patched in WordPress version 5.8.3. Older affected versions are also fixed via security release, that go back till 3.7.37. We strongly recommend that you keep auto-updates enabled. There are no known workarounds for this issue.

- **WordPress <= 5.8.2 - Stored Cross-Site Scripting (XSS) vulnerability**: Stored Cross-Site Scripting (XSS) vulnerability discovered by Karim El Ouerghemmi and Simon Scannell (SonarSource) in WordPress (versions <= 5.8.2).

- **WordPress Core &lt; 5.8.3 - Authenticated (Author+) Stored Cross Site Scripting**: WordPress is a free and open-source content management system written in PHP and paired with a MariaDB database. Low-privileged authenticated users (like author) in WordPress core are able to execute JavaScript/perform stored XSS attack, which can affect high-privileged users. This has been patched in WordPress version 5.8.3. Older affected versions are also fixed via security release, that go back till 3.7.37. We strongly recommend that you keep auto-updates enabled. There are no known workarounds for this issue.

- **CVE-2022-21663**: WordPress is a free and open-source content management system written in PHP and paired with a MariaDB database. On a multisite, users with Super Admin role can bypass explicit/additional hardening under certain conditions through object injection. This has been patched in WordPress version 5.8.3. Older affected versions are also fixed via security release, that go back till 3.7.37. We strongly recommend that you keep auto-updates enabled. There are no known workarounds for this issue.

- **WordPress <= 5.8.2 - Authenticated Object Injection in Multisites**: Authenticated Object Injection in Multisites discovered by Simon Scannell (SonarSource) in WordPress (versions <= 5.8.2).

- **WordPress Core &lt; 5.8.3 - Super Admin Multi-Site Installation Object Injection**: WordPress is a free and open-source content management system written in PHP and paired with a MariaDB database. On a multisite, users with Super Admin role can bypass explicit/additional hardening under certain conditions through object injection. This has been patched in WordPress version 5.8.3. Older affected versions are also fixed via security release, that go back till 3.7.37. We strongly recommend that you keep auto-updates enabled. There are no known workarounds for this issue.

- **CVE-2022-21664**: WordPress is a free and open-source content management system written in PHP and paired with a MariaDB database. Due to lack of proper sanitization in one of the classes, there's potential for unintended SQL queries to be executed. This has been patched in WordPress version 5.8.3. Older affected versions are also fixed via security release, that go back till 4.1.34. We strongly recommend that you keep auto-updates enabled. There are no known workarounds for this issue.

- **WordPress <= 5.8.2 - SQL Injection (SQLi) vulnerability**: SQL Injection (SQLi) vulnerability discovered by Ben Bidner in WordPress (versions <= 5.8.2).

- **WordPress Core &lt; 5.8.3 - SQL Injection via WP_Meta_Query**: WordPress is a free and open-source content management system written in PHP and paired with a MariaDB database. Due to lack of proper sanitization in one of the classes, there&#039;s potential for unintended SQL queries to be executed. This has been patched in WordPress version 5.8.3. Older affected versions are also fixed via security release, that go back till 4.1.34. We strongly recommend that you keep auto-updates enabled. There are no known workarounds for this issue.

- **CVE-2021-44223**: WordPress before 5.8 lacks support for the Update URI plugin header. This makes it easier for remote attackers to execute arbitrary code via a supply-chain attack against WordPress installations that use any plugin for which the slug satisfies the naming constraints of the WordPress.org Plugin Directory but is not yet present in that directory.

- **WordPress <= 5.7.4 - Plugin Confusion vulnerability**: Plugin Confusion vulnerability discovered by Kamil Vavra in WordPress (versions <= 5.7.4).

- **WordPress Core &lt; 5.8 - Dependency Confusion**: WordPress before 5.8 lacks support for the Update URI plugin header. This makes it easier for remote attackers to execute arbitrary code via a supply-chain attack against WordPress installations that use any plugin for which the slug satisfies the naming constraints of the WordPress.org Plugin Directory but is not yet present in that directory.

- **CVE-2021-39200**: WordPress is a free and open-source content management system written in PHP and paired with a MySQL or MariaDB database. In affected versions output data of the function wp_die() can be leaked under certain conditions, which can include data like nonces. It can then be used to perform actions on your behalf. This has been patched in WordPress 5.8.1, along with any older affected versions via minor releases. It's strongly recommended that you keep auto-updates enabled to receive the fix.

- **WordPress core <= 5.8 - Data Exposure via REST API vulnerability**: Data Exposure via REST API vulnerability discovered by Michael Adams in WordPress core (versions <= 5.8).

Version update list: 5.8 updated to 5.8.1, 5.7.2 updated to 5.7.3, 5.7.1 updated to 5.7.3, 5.7 updated to 5.7.3, 5.6.4 updated to 5.6.5, 5.6.3 updated to 5.6.5, 5.6.2 updated to 5.6.5, 5.6.1 updated to 5.6.5, 5.6 updated to 5.6.5, 5.5.5 updated to 5.5.6, 5.5.4 updated to 5.5.6, 5.5.3 updated to 5.5.6, 5.5.2 updated to 5.5.6, 5.5.1 updated to 5.5.6, 5.5 updated to 5.5.6, 5.4.6 updated to 5.4.7, 5.4.5 updated to 5.4.7, 5.4.4 updated to 5.4.7, 5.4.3 updated to 5.4.7, 5.4.2 updated to 5.4.7, 5.4.1 updated to 5.4.7, 5.4 updated to 5.4.7

- **CVE-2021-39201**: WordPress is a free and open-source content management system written in PHP and paired with a MySQL or MariaDB database. ### Impact The issue allows an authenticated but low-privileged user (like contributor/author) to execute XSS in the editor. This bypasses the restrictions imposed on users who do not have the permission to post `unfiltered_html`. ### Patches This has been patched in WordPress 5.8, and will be pushed to older versions via minor releases (automatic updates). It's strongly recommended that you keep auto-updates enabled to receive the fix. ### References https://wordpress.org/news/category/releases/ https://hackerone.com/reports/1142140 ### For more information If you have any questions or comments about this advisory: * Open an issue in [HackerOne](https://hackerone.com/wordpress)

- **WordPress core <= 5.8 - Authenticated Cross-Site Scripting (XSS) vulnerability**: Authenticated Cross-Site Scripting (XSS) vulnerability discovered by Michal Bentkowski (Securitum) in WordPress core block editor (versions <= 5.8).

The issue allows an authenticated but low-privileged user (like contributor/author) to execute XSS in the editor. This bypasses the restrictions imposed on users who do not have permission to post unfiltered_html.

Version update list: 5.8 updated to 5.8.1, 5.7.2 updated to 5.7.3, 5.7.1 updated to 5.7.3, 5.7 updated to 5.7.3, 5.6.4 updated to 5.6.5, 5.6.3 updated to 5.6.5, 5.6.2 updated to 5.6.5, 5.6.1 updated to 5.6.5, 5.6 updated to 5.6.5, 5.5.5 updated to 5.5.6, 5.5.4 updated to 5.5.6, 5.5.3 updated to 5.5.6, 5.5.2 updated to 5.5.6, 5.5.1 updated to 5.5.6, 5.5 updated to 5.5.6, 5.4.6 updated to 5.4.7, 5.4.5 updated to 5.4.7, 5.4.4 updated to 5.4.7, 5.4.3 updated to 5.4.7, 5.4.2 updated to 5.4.7, 5.4.1 updated to 5.4.7, 5.4 updated to 5.4.7

- **CVE-2021-29450**: Wordpress is an open source CMS. One of the blocks in the WordPress editor can be exploited in a way that exposes password-protected posts and pages. This requires at least contributor privileges. This has been patched in WordPress 5.7.1, along with the older affected versions via minor releases. It's strongly recommended that you keep auto-updates enabled to receive the fix.

- **WordPress Core &lt; 5.7.1 - Sensitive Information Disclosure**: Wordpress is an open source CMS. One of the blocks in the WordPress editor can be exploited in a way that exposes password-protected posts and pages. This requires at least contributor privileges. This has been patched in WordPress 5.7.1, along with the older affected versions via minor releases. It&#039;s strongly recommended that you keep auto-updates enabled to receive the fix.

- **CVE-2020-28032**: WordPress before 5.5.2 mishandles deserialization requests in wp-includes/Requests/Utility/FilteredIterator.php.

- **CVE-2020-28033**: WordPress before 5.5.2 mishandles embeds from disabled sites on a multisite network, as demonstrated by allowing a spam embed.

- **CVE-2020-28034**: WordPress before 5.5.2 allows XSS associated with global variables.

- **CVE-2020-28035**: WordPress before 5.5.2 allows attackers to gain privileges via XML-RPC.

- **CVE-2020-28036**: wp-includes/class-wp-xmlrpc-server.php in WordPress before 5.5.2 allows attackers to gain privileges by using XML-RPC to comment on a post.

- **CVE-2020-28037**: is_blog_installed in wp-includes/functions.php in WordPress before 5.5.2 improperly determines whether WordPress is already installed, which might allow an attacker to perform a new installation, leading to remote code execution (as well as a denial of service for the old installation).

- **CVE-2020-28038**: WordPress before 5.5.2 allows stored XSS via post slugs.

- **CVE-2020-28039**: is_protected_meta in wp-includes/meta.php in WordPress before 5.5.2 allows arbitrary file deletion because it does not properly determine whether a meta key is considered protected.

- **CVE-2020-28040**: WordPress before 5.5.2 allows CSRF attacks that change a theme's background image.

- **WordPress <= 5.9.1 - Stored Cross-Site Scripting (XSS) vulnerability**: Stored Cross-Site Scripting (XSS) vulnerability discovered by Ben Bidner in WordPress (versions <= 5.9.1).

- **WordPress core <= 5.8.1 - Expired DST Root CA X3 Certificate issue**: Expired DST Root CA X3 Certificate issue discovered by Bradley Taylor in WordPress core (versions <= 5.8.1).

- **WordPress core <= 5.8 - Command injection vulnerability in the Lodash library**: Command injection vulnerability in the Lodash library in WordPress core (versions <= 5.8).

Version update list: 5.8 updated to 5.8.1, 5.7.2 updated to 5.7.3, 5.7.1 updated to 5.7.3, 5.7 updated to 5.7.3, 5.6.4 updated to 5.6.5, 5.6.3 updated to 5.6.5, 5.6.2 updated to 5.6.5, 5.6.1 updated to 5.6.5, 5.6 updated to 5.6.5, 5.5.5 updated to 5.5.6, 5.5.4 updated to 5.5.6, 5.5.3 updated to 5.5.6, 5.5.2 updated to 5.5.6, 5.5.1 updated to 5.5.6, 5.5 updated to 5.5.6, 5.4.6 updated to 5.4.7, 5.4.5 updated to 5.4.7, 5.4.4 updated to 5.4.7, 5.4.3 updated to 5.4.7, 5.4.2 updated to 5.4.7, 5.4.1 updated to 5.4.7, 5.4 updated to 5.4.7

- **WordPress <= 5.7.1 - Object injection in PHPMailer vulnerability**: Object injection in PHPMailer vulnerability discovered in WordPress (one security issue affecting WordPress versions between 3.7 and 5.7).

- **CVE-2020-36326**: PHPMailer 6.1.8 through 6.4.0 allows object injection through Phar Deserialization via addAttachment with a UNC pathname. NOTE: this is similar to CVE-2018-19296, but arose because 6.1.8 fixed a functionality problem in which UNC pathnames were always considered unreadable by PHPMailer, even in safe contexts. As an unintended side effect, this fix eliminated the code that blocked addAttachment exploitation.

- **WordPress <= 6.0.1 - Authenticated Cross-Site Scripting (XSS) vulnerability**: Authenticated Cross-Site Scripting (XSS) vulnerability discovered by Khalilov Moe in WordPress <= 6.0.1
Update the WordPress to the latest available version (at least 6.0.2 or another patched version).

- **WordPress  <= 6.0.1 - Authenticated Stored Cross-Site Scripting (XSS) vulnerability**: Authenticated Stored Cross-Site Scripting (XSS) vulnerability discovered by John Blackbourn in WordPress (versions <= 6.0.1)
Update the WordPress to the latest available version (at least 6.0.2 or another patched version).

- **WordPress <= 6.0.1 - Authenticated SQL Injection (SQLi) vulnerability via Link API**: Authenticated SQL Injection (SQLi) vulnerability via Link API discovered by FVD in WordPress core (versions <= 6.0.1).
Update the WordPress to the latest available version (at least 6.0.2 or another patched version).

- **WordPress core <= 6.0.2 - Data Exposure vulnerability via REST API**: Data Exposure vulnerability via REST API discovered by Than Taintor in WordPress core (versions <= 6.0.2).
Update the WordPress to the latest available version (at least 6.0.3).

- **WordPress core <= 6.0.2 - Sender’s Email Address Exposure vulnerability**: Sender’s Email Address Exposure vulnerability via wp-mail.php was discovered by Toshitsugu Yoneyama (Mitsui Bussan Secure Directions, Inc. via JPCERT) in the WordPress core (versions <= 6.0.2).
Update the WordPress to the latest available version (at least 6.0.3).

- **WordPress core <= 6.0.2 - Stored Cross-Site Scripting (XSS) vulnerability**: Stored Cross-Site Scripting (XSS) vulnerability via wp-mail.php discovered by Toshitsugu Yoneyama (Mitsui Bussan Secure Directions, Inc. via JPCERT) in WordPress core (versions <= 6.0.2)
Update the WordPress to the latest available version (at least 6.0.3).

- **WordPress core <= 6.0.2 - Cross-Site Scripting (XSS) vulnerability**: Cross-Site Scripting (XSS) vulnerability in the Widget block discovered in WordPress core (versions <= 6.0.2)
Update the WordPress to the latest available version (at least 6.0.3).

- **WordPress core <= 6.0.2 - Stored Cross-Site Scripting (XSS) vulnerability**: Stored Cross-Site Scripting (XSS) vulnerability via Customizer discovered by Alex Concha (WordPress security team) in WordPress core (versions <= 6.0.2).
Update the WordPress WordPress wordpress to the latest available version (at least 6.0.3).

- **WordPress core <= 6.0.2 - Reflected Cross-Site Scripting (XSS) vulnerability**: Reflected Cross-Site Scripting (XSS) vulnerability via SQL Injection (SQLi) in Media Library discovered by Ben Bidner (WordPress security team) and Marc Montpas (Automattic) in WordPress core (versions <= 6.0.2).
Update the WordPress to the latest available version (at least 6.0.3).

- **WordPress core <= 6.0.2 - Stored Cross-Site Scripting (XSS) vulnerability in Comment editing**: Stored Cross-Site Scripting (XSS) vulnerability in Comment editing discovered by Alex Concha (WordPress security team) in WordPress core (versions <= 6.0.2)
Update the WordPress to the latest available version (at least 6.0.3).

- **WordPress core <= 6.0.2 - Cross-Site Scripting (XSS) vulnerability**: Cross-Site Scripting (XSS) vulnerability in the Feature Image block discovered in WordPress core (versions <= 6.0.2)
Update the WordPress to the latest available version (at least 6.0.3).

- **WordPress core <= 6.0.2 - Stored Cross-Site Scripting (XSS) vulnerability**: Stored Cross-Site Scripting (XSS) vulnerability in RSS Block discovered in WordPress core (versions <= 6.0.2).
Update the WordPress to the latest available version (at least 6.0.3).

- **WordPress core <= 6.0.2 - Cross-Site Scripting (XSS) vulnerability**: Cross-Site Scripting (XSS) vulnerability in the Search block discovered by Alex Concha (WP Security team) in WordPress core (versions <= 6.0.2).
Update the WordPress to the latest available version (at least 6.0.3).

- **WordPress core <= 6.0.2 - SQL Injection (SQLi) vulnerability**: SQL Injection (SQLi) vulnerability due to improper sanitization in WP_Date_Query discovered by Michael Mazzolini in WordPress core (versions <= 6.0.2).
Update the WordPress WordPress wordpress to the latest available version (at least 6.0.3).

- **WordPress core <= 6.0.2 - Content From Multipart Emails Leak vulnerability**: Content From Multipart Emails Leak vulnerability when HTML/plaintext used discovered by Thomas Kräftner in WordPress core (versions <= 6.0.2).
Update the WordPress WordPress wordpress to the latest available version (at least 6.0.3).

- **WordPress core <= 6.0.2 - Cross-Site Request Forgery (CSRF) vulnerability in wp-trackback.php**: Cross-Site Request Forgery (CSRF) vulnerability in wp-trackback.php discovered by Simon Scannell in WordPress core (versions <= 6.0.2).
Update the WordPress to the latest available version (at least 6.0.3).

- **WordPress core <= 6.0.2 - Stored Cross-Site Scripting (XSS) vulnerability**: Stored Cross-Site Scripting (XSS) vulnerability in RSS Widget discovered in WordPress core (versions <= 6.0.2).
Update the WordPress to the latest available version (at least 6.0.3).

- **WordPress core <= 6.0.2 - Open redirect vulnerability**: Open redirect vulnerability in wp_nonce_ays discovered by devrayn in WordPress core (versions <= 6.0.2)
Update the WordPress to the latest available version (at least 6.0.3).

- **Multiple vulnerabilities in WordPress**: WordPress contains multiple vulnerabilities listed below which are to the WordPress Post by Email Feature. <ul><li>Stored Cross-site scripting (CWE-79) - CVE-2022-43497</li><li>Stored Cross-site scripting (CWE-79) - CVE-2022-43500</li><li>Improper authentication (CWE-287) - CVE-2022-43504</li></ul> Toshitsugu Yoneyama of Mitsui Bussan Secure Directions, Inc. reported these vulnerabilities to IPA. JPCERT/CC coordinated with the developer under Information Security Early Warning Partnership.

Solution: [Update the Software] Update to the latest version according to the information provided by the developer. According to the developer, these vulnerabilities have been fixed in version 6.0.3.

- **CVE-2022-43504**: Improper authentication vulnerability in WordPress versions prior to 6.0.3 allows a remote unauthenticated attacker to obtain the email address of the user who posted a blog using the WordPress Post by Email Feature. The developer also provides new patched releases for all versions since 3.7.

- **CVE-2022-43500**: Cross-site scripting vulnerability in WordPress versions prior to 6.0.3 allows a remote unauthenticated attacker to inject an arbitrary script. The developer also provides new patched releases for all versions since 3.7.

- **CVE-2022-43497**: Cross-site scripting vulnerability in WordPress versions prior to 6.0.3 allows a remote unauthenticated attacker to inject an arbitrary script. The developer also provides new patched releases for all versions since 3.7.

- **WordPress Core &lt; 6.0.3 - Shared User Instance Weakness**: WordPress Core in versions up to 6.0.3 had a weakness in how Share User Instances were handled. This fix appears to have been necessary to safely use the wp_set_current_user( 0 ); method to patch the previously mentioned XSS and CSRF in wp-mail.php and wp-trackback.php vulnerabilities. The previous functionality may have resulted in third party plugins or themes using the wp_set_current_user function in a way that could lead to privilege escalation and users being able to perform more actions than originally intended.

- **WordPress Core &lt; 6.0.3 - Open Redirect**: WordPress Core is vulnerable to open redirect in versions up to 6.0.3. This is due to insufficient validation of the &#039;Referer&#039; header and _wp_http_referer request parameter when a user accesses a link with an expired or invalid nonce. This would make it possible for an attacker to redirect a victim to a potentially malicious site, granted they could trick the victim into performing an action such as clicking on a link.

- **WordPress Core &lt; 6.0.3 - Information Disclosure (Multi-Part Email Leak)**: WordPress Core is vulnerable to information disclosure via a REST-API endpoint in versions up to 6.0.3. The endpoint for terms and tags did not perform enough validation on the user requesting information about terms and tags for a given post. This made it possible for users with access to terms and tags, such as a contributor, to determine those details on all posts not belonging to them, even when in a private status. This does not reveal critical information, and as such it is not likely to be exploited.

- **WordPress Core &lt; 6.0.3 - Authenticated (Admin+) Stored Cross-Site Scripting via Customizer**: WordPress Core is vulnerable to Stored Cross-Site Scripting via the Customizer in versions up to 6.0.3. This is due to insufficient escaping on the &#039;Blog Name&#039; value that could be edited and become executable with the right payload while in the theme customizer. This would make it possible for authenticated attacker with access to customize a theme, such as administrators to inject malicious JavaScript into the page.

- **WordPress Core &lt; 6.0.3 - Authenticated Information Disclosure via REST-API**: WordPress Core is vulnerable to information disclosure via the REST-API in versions up to 6.0.3. The REST API endpoint for terms and tags did not perform enough validation on the user requesting information about terms and tags for a given post. This made it possible for users with access to terms and tags, such as a contributor, to determine those details on all posts not belonging to them, even when in a private status. This does not reveal critical information.

- **WordPress Core &lt; 6.0.3 - Reflected Cross-Site Scripting via SQL Injection**: WordPress Core is vulnerable to SQL Injection in the Media Library that can be leveraged to exploit a Reflected Cross-Site Scripting issue in versions up to 6.0.3. This is due to insufficient escaping on user supplied values passed to a SQL query.  This makes it possible for an attacker to achieved JavaScript code execution in a victims browser, granted they can trick the victim into performing an action such as clicking on a link.

- **WordPress Core &lt; 6.0.3 - Cross-Site Request Forgery via wp-trackback.php**: WordPress Core is vulnerable to Cross-Site Request Forgery via wp-trackback.php in versions up to 6.0.3. This is due to the fact that the any request to wp-trackback.php would assume the identity of the user whose cookies are sent with the request. This would make it possible for an unauthenticated user to trigger a trackback assuming the identity of another user, granted they could trick that other user into performing the action. In new versions of WordPress, the identity will always be a non-existent user with the ID of 0, which represents an unauthenticated user.

- **WordPress Core &lt; 6.0.3 - Information Disclosure (Email Address)**: WordPress Core is vulnerable to Information Disclosure of in versions up to 6.0.3. When the post by email functionality is enabled, it may log post author&#039;s email addresses in a way that may be publicly accessible. This could make it possible for attackers to steal post author&#039;s email addresses and use that for further attacks.

- **WordPress Core &lt; 6.0.3 - Authenticated (Editor+) Stored Cross-Site Scripting via Comments**: WordPress Core is vulnerable to Stored Cross-Site Scripting, exploitable during comment editing, in versions up to 6.0.3. This is due to insufficient escaping and sanitization on the values being stored during a comment update. This makes it possible for authenticated users with high level permissions, such as an editor, to modify post comments to include malicious web scripts that will execute whenever someone accesses the comment.

- **WordPress Core &lt; 6.0.3 - SQL Injection via WP_Date_Query**: WordPress Core is vulnerable to SQL Injection in versions up to 6.0.3. This is due to insufficient escaping on where &ldquo;AND&rdquo; and &ldquo;OR&rdquo; present in the query. This may make it possible for attackers to achieve SQL Injection when another plugin or theme is installed on the site that allows WP_Date_Query to be used insecurely.

- **WordPress Core &lt; 6.0.2 - Authenticated SQL Injection**: WordPress Core, in versions up to 6.0.2, is vulnerable to SQL Injection that can be exploited by authenticated users via the LIMIT parameter passed through the get_bookmarks function. This can be exploited on default WordPress installations by users with high-level privileges, such as an editor or administrator, and it may be possible for this to be exploited by lower-privileged users if a plugin/theme passes an unescaped user supplied LIMIT value from those level users to the get_bookmarks function.

- **WordPress Core &lt; 6.0.2 - Stored Cross-Site Scripting via Plugin Deactivation and Deletion Errors**: WordPress Core, in versions up to 6.0.2, is vulnerable to Stored Cross-Site Scripting that can be exploited when malicious content is injected into plugin code that triggers when an error occurs during plugin de-activation or during deletion. This requires an attacker have access to the modify the error message that is displayed either in the plugin&#039;s code or via a request parameter, in most cases it is likely to be the latter.

- **WordPress Core &lt; 6.0.2 - Authenticated (Contributor+) Stored Cross-Site Scripting via use of the_meta(); function**: WordPress Core, in versions up to 6.0.2, is vulnerable to Authenticated Stored Cross-Site Scripting that can be exploited by users with access to the WordPress post and page editor, typically consisting of Authors, Contributors, and Editors making it possible to inject arbitrary web scripts into posts and pages that execute if the the_meta(); function is called on that page.

- **WordPress Core 5.9 - 5.9.1 - Authenticated (Contributor+) Stored Cross-Site Scripting**: WordPress Core in versions 5.9 - 5.9.1 is vulnerable to Contributor+ stored Cross-Site Scripting via the double JSON encoded payloads set in the &#039;isGlobalStylesUserThemeJSON&#039; parameter which is updatable via the post editor.

- **CVE-2021-20083**: Improperly Controlled Modification of Object Prototype Attributes ('Prototype Pollution') in jquery-plugin-query-object 2.2.3 allows a malicious user to inject properties into Object.prototype.

- **WordPress Core &lt; 5.9.1 - jQuery Prototype Pollution**: Improperly Controlled Modification of Object Prototype Attributes (&#039;Prototype Pollution&#039;) in jquery-plugin-query-object 2.2.3 allows a malicious user to inject properties into Object.prototype.

- **WordPress Core &lt; 5.8.2 - ca-bundle.crt contains expired certificate DST Root CA X3**: WordPress Core in various versions less than version 5.8.2 contained an expired DST Root CA X3 certificate. There is no significant security risk to most WordPress users.

- **CVE-2020-8203**: Prototype pollution attack when using _.zipObjectDeep in lodash before 4.17.20.

- **WordPress Core &lt; 5.8.1 - LoDash Update**: WordPress Core is vulnerable to prototype pollution in various versions less than 5.8.1 due to a vulnerability in the LoDash component which is identified as CVE-2020-8203.

- **CVE-2021-29476**: Requests is a HTTP library written in PHP. Requests mishandles deserialization in FilteredIterator. The issue has been patched and users of `Requests` 1.6.0, 1.6.1 and 1.7.0 should update to version 1.8.0.

- **CVE-2021-23337**: Lodash versions prior to 4.17.21 are vulnerable to Command Injection via the template function.

- **CVE-2022-3590**: WordPress is affected by an unauthenticated blind SSRF in the pingback feature. Because of a TOCTOU race condition between the validation checks and the HTTP request, attackers can reach internal hosts that are explicitly forbidden.

**It is recommended to update to the latest version of WordPress to fix these possible exploits.**

## WordPress Plugin discovery and vulnerabilities
Here is the list with all of the plugins found by scanning (passive scan, watching for css links and watching for *wp-content/plugins*):

- **ele-custom-skin**

There were plugins added manually by the user of the scanner to be found and tested for vulnerabilities:

- **duplicator**

- **w3-total-cache**

- **anomify**

## WordPress Plugins used on http://192.168.100.28:8000/
1. **ele-custom-skin** has the version **3.1.3**

1. **duplicator**'s version cannot be found in /wp-content/plugins/duplicator/*readme.txt*

1. **w3-total-cache** has the version **0.9.2.8**

1. **anomify**'s version could not be found with the given methods.

## Plugin vulnerability analysis:
- **ele-custom-skin** -> No vulnerability found for this plugin on the base API (*vulnerability field is null*)

- **w3-total-cache** version **0.9.2.8** -> **CVE-2021-24452** : *The W3 Total Cache WordPress plugin before 2.1.5 was affected by a reflected Cross-Site Scripting (XSS) issue within the "extension" parameter in the Extensions dashboard, when the 'Anonymously track usage to improve product quality' setting is enabled, as the parameter is output in a JavaScript context without proper escaping. This could allow an attacker, who can convince an authenticated admin into clicking a link, to run malicious JavaScript within the user's web browser, which could lead to full site compromise.*

- **w3-total-cache** version **0.9.2.8** -> **CVE-2021-24436** : *The W3 Total Cache WordPress plugin before 2.1.4 was vulnerable to a reflected Cross-Site Scripting (XSS) security vulnerability within the "extension" parameter in the Extensions dashboard, which is output in an attribute without being escaped first. This could allow an attacker, who can convince an authenticated admin into clicking a link, to run malicious JavaScript within the user's web browser, which could lead to full site compromise.*

- **w3-total-cache** version **0.9.2.8** -> **CVE-2021-24427** : *The W3 Total Cache WordPress plugin before 2.1.3 did not sanitise or escape some of its CDN settings, allowing high privilege users to use JavaScript in them, which will be output in the page, leading to an authenticated Stored Cross-Site Scripting issue*

- **w3-total-cache** version **0.9.2.8** -> **CVE-2013-2010** : *WordPress W3 Total Cache Plugin 0.9.2.8 has a Remote PHP Code Execution Vulnerability*

- **w3-total-cache** version **0.9.2.8** -> **CVE-2019-6715** : *pub/sns.php in the W3 Total Cache plugin before 0.9.4 for WordPress allows remote attackers to read arbitrary files via the SubscribeURL field in SubscriptionConfirmation JSON data.*

- **w3-total-cache** version **0.9.2.8** -> **CVE-2014-9414** : *The W3 Total Cache plugin before 0.9.4.1 for WordPress does not properly handle empty nonces, which allows remote attackers to conduct cross-site request forgery (CSRF) attacks and hijack the authentication of administrators for requests that change the mobile site redirect URI via the mobile_groups[*][redirect] parameter and an empty _wpnonce parameter in the w3tc_mobile page to wp-admin/admin.php.*

- **w3-total-cache** version **0.9.2.8** -> **CVE-2014-8724** : *Cross-site scripting (XSS) vulnerability in the W3 Total Cache plugin before 0.9.4.1 for WordPress, when debug mode is enabled, allows remote attackers to inject arbitrary web script or HTML via the "Cache key" in the HTML-Comments, as demonstrated by the PATH_INFO to the default URI.*

- **w3-total-cache** version **0.9.2.8** -> **WordPress W3 Total Cache plugin <= 0.9.7.3 - Cross-Site Scripting (XSS) vulnerability** : *Cross-Site Scripting (XSS) vulnerability found by Thomas Chauchefoin in WordPress W3 Total Cache plugin (versions <= 0.9.7.3).*

- **w3-total-cache** version **0.9.2.8** -> **WordPress W3 Total Cache Plugin <= 0.9.4.1 - Bypass** : *This plugin is prone to unauthenticated security token bypass vulnerability.
Update the plugin.*

- **w3-total-cache** version **0.9.2.8** -> **WordPress W3 Total Cache Plugin <= 0.9.4.1 - Arbitrary File Upload** : *This plugin is prone to an authenticated arbitrary file upload vulnerability.
Update the plugin.*

- **w3-total-cache** version **0.9.2.8** -> **WordPress W3 Total Cache Plugin <= 0.9.4.1 - Arbitrary File Download** : *This plugin is prone to  authenticated arbitrary file download vulnerability.
Update the plugin.*

- **w3-total-cache** version **0.9.2.8** -> **WordPress W3 Total Cache Plugin <= 0.9.4.1 - Arbitrary PHP Code Execution** : *This plugin is prone to an authenticated arbitrary PHP code execution vulnerability.
Update the plugin.*

- **w3-total-cache** version **0.9.2.8** -> **WordPress W3 Total Cache Plugin <= 0.9.4.1 - Reflected Cross Site Scripting** : *Because of this vulnerability, the attackers can inject arbitrary JavaScript or HTML code.
Update the plugin.*

- **w3-total-cache** version **0.9.2.8** -> **WordPress W3 Total Cache Plugin <= 0.9.4 - Cross Site Request Forgery** : *This plugin is prone to edge mode enabling cross site request forgery vulnerability.
Update the plugin.*

- **w3-total-cache** version **0.9.2.8** -> **WordPress W3 Total Cache plugin <= 0.9.2.8 - PHP Code Execution vulnerability** : *W3 Total Cache plugin is prone to a PHP code execution vulnerability because of the handling of certain macros such as "mfunc" that allows arbitrary PHP code injection.
Update the WordPress W3 Total Cache plugin to the latest available version (at least 0.9.2.9).*

- **w3-total-cache** version **0.9.2.8** -> **W3 Total Cache &lt; 0.9.7.3 - Cryptographic Signature Bypass** : *The return value of `openssl_verify` is not properly validated, which allows to bypass the cryptographic check.*

- **w3-total-cache** version **0.9.2.8** -> **W3 Total Cache &lt; 0.9.7.4 - Blind SSRF and RCE via phar** : *The implementation of `opcache_flush_file` calls `file_exists` with a parameter fully controlled by the user.*

- **w3-total-cache** version **0.9.2.8** -> **W3 Total Cache &lt;= 0.9.7.3 - Cross-Site Scripting (XSS)** : *The W3 Total Cache WordPress plugin was affected by a Cross-Site Scripting (XSS) security vulnerability.*

- **w3-total-cache** version **0.9.2.8** -> **W3 Total Cache &lt;= 0.9.4.1 - Weak Validation of Amazon SNS Push Messages** : *The W3 Total Cache WordPress plugin was affected by a Weak Validation of Amazon SNS Push Messages security vulnerability.*

- **w3-total-cache** version **0.9.2.8** -> **W3 Total Cache &lt;= 0.9.4.1 - Information Disclosure Race Condition** : *The W3 Total Cache WordPress plugin was affected by an Information Disclosure Race Condition security vulnerability.*

- **w3-total-cache** version **0.9.2.8** -> **W3 Total Cache &lt;= 0.9.4 - Unauthenticated Server Side Request Forgery (SSRF)** : *The W3 Total Cache WordPress plugin was affected by an Unauthenticated Server Side Request Forgery (SSRF) security vulnerability.*

- **w3-total-cache** version **0.9.2.8** -> **W3 Total Cache &lt;= 0.9.4.1 &ndash; Authenticated Arbitrary File Download** : *When you&#039;re creating a support ticket in the plugin page, you can add one or more of your your template themes.

Then this file will be send to the author to help him resolving the issue.

Now you select one, you send the form and same as for the files before, you will send it to the author to help him to fix the issue.

How does it work:
**********
        /**
         * Attach templates
         */
        foreach ($templates as $template) {
            if (!empty($template)) {
                $attachments[] = $template;
            }
        }
**********
        foreach ($attachments as $attachment) {
            if (is_network_admin())
                update_site_option(&#039;attachment_&#039; . md5($attachment), $attachment);
            else
                update_option(&#039;attachment_&#039; . md5($attachment), $attachment);
        }
**********
        /**
         * Remove temporary files
         */
        foreach ($attachments as $attachment) {
// ...
            if (is_network_admin())
                delete_site_option(&#039;attachment_&#039; . md5($attachment));
            else
                delete_option(&#039;attachment_&#039; . md5($attachment));
        }
**********
$attachment_location = filter_var(urldecode($_REQUEST[&#039;file&#039;]), FILTER_SANITIZE_STRING);
$md5 = md5($attachment_location);
$nonce = $_REQUEST[&#039;nonce&#039;];
$stored_nonce = get_site_option(&#039;w3tc_support_request&#039;) ? get_site_option(&#039;w3tc_support_request&#039;) : get_option(&#039;w3tc_support_request&#039;);
$stored_attachment = get_site_option(&#039;w3tc_support_request&#039;) ? get_site_option(&#039;attachment_&#039; . $md5) : get_option(&#039;attachment_&#039; . $md5);

if (file_exists($attachment_location) &amp;&amp; $nonce == $stored_nonce &amp;&amp; !empty($stored_nonce) &amp;&amp; $stored_attachment == $attachment_location) {
**********

First, our choices are added to the attachments array, second an option is added, this will be used to be sure that this file was chosen from this support form, then this options are deleted when the submission is done.

Between the option creation and delete that the files.php is called to get the attachment, verified with a nonce and with the created option.

The vulnerability stays in the fact that we can modify &ndash; using firebug for example &ndash; the templates name to another existing file from the site, like wp-config.php.

So now, an option has been created with this fake theme template. Then using the same type juggling flaw as before, I can validate the nonce because of the ==.

You also have to add a 20 Mb file to gain time to exploit this.

Pointing on the files.php URL like that can help me to download the wp-config.php, because for the same reason as before, an administrator is not always allowed to read the config file, he&#039;s not the webmaster but a WordPress administrator, so this represent a vulnerability.*

- **w3-total-cache** version **0.9.2.8** -> **W3 Total Cache &lt;= 0.9.4.1 &ndash; Authenticated Arbitrary File Upload** : *When you&#039;re creating a support ticket in the plugin page, you can add one or more of your files from your computer.

Then this file will be send to the author to help him resolving the issue.

When we look at the code, W3TC is doing that:
**********
        /**
         * Attach other files
         */
        if (!empty($_FILES[&#039;files&#039;])) {
            $files = (array)$_FILES[&#039;files&#039;];
            for ($i = 0, $l = count($files); $i &lt; $l; $i++) {
                if (isset($files[&#039;tmp_name&#039;][$i]) &amp;&amp; isset($files[&#039;name&#039;][$i]) &amp;&amp; isset($files[&#039;error&#039;][$i]) &amp;&amp; $files[&#039;error&#039;][$i] == UPLOAD_ERR_OK) {
                    $path = W3TC_CACHE_TMP_DIR . &#039;/&#039; . $files[&#039;name&#039;][$i];
                    if (@move_uploaded_file($files[&#039;tmp_name&#039;][$i], $path)) {
                        $attachments[] = $path;
                    }
                }
            }
        }
**********
and
**********
        /**
         * Remove temporary files
         */
        foreach ($attachments as $attachment) {
            if (strstr($attachment, W3TC_CACHE_TMP_DIR) !== false) {
                @unlink($attachment);
            }
**********

Ok, so, when you submit the form as an administrator, W3TC uploads our file in its temporary folder /wp-content/cache/tmp/ then will delete them right after that, the file will live only a few milliseconds.

But what if I try to send 2 files, the first one is a 2 Kb malicious PHP file containing a backdoor, the second one is a 20 Mb file. The submission will last more longer, the first file won&#039;t be deleted since the second one is not uploaded, I can now access to the first file.

An administrator is not always allowed to execute custom PHP code, he&#039;s not the webmaster but a WordPress administrator, so this represent a vulnerability.*

- **w3-total-cache** version **0.9.2.8** -> **W3 Total Cache &lt;= 0.9.4.1 &ndash; Authenticated Arbitrary PHP Code Execution** : *This one is so mush easy to exploit using the import settings feature, this is what W3TC will do one your file is uploaded:
**********
    /**
     * Imports config content
     *
     * @param string $filename
     * @return boolean
     */
    function import($filename) {
        if (file_exists($filename) &amp;&amp; is_readable($filename)) {
            $data = file_get_contents($filename);
            if (substr($data, 0, 5) == &#039;&lt;?php&#039;)
                $data = substr($data, 5);

            $config = eval($data);

            if (is_array($config)) {
                foreach ($config as $key =&gt; $value)
                  $this-&gt;set($key, $value);

                return true;
            }
        }

        return false;
    }
**********
The bad line is $config = eval($data); because it means that all my file content will be evaluated like any other PHP code. Basically we can send a PHP script that will create a backdoor.*

- **w3-total-cache** version **0.9.2.8** -> **W3 Total Cache &lt;= 0.9.4.1 &ndash; Unauthenticated Security Token Bypass** : *The /pub/apc.php file is used to empty the OPCache/APC. The script seems protected by a nonce (aka security token):
***********
$nonce = W3_Request::get_string(&#039;nonce&#039;);
$uri = $_SERVER[&#039;REQUEST_URI&#039;];

if (wp_hash($uri) == $nonce) {
************

But the flaw stays in the == operator which is not the one to use when you want to compare hashes because of php type juggling.

You can find an example of type juggling on https://3v4l.org/tT4l8

To exploit the vulnerability, the token has to start with `0e` and all other chars have to be numbers, then the user can just add a param in the url like `?nonce=0` and it will be validated.*

- **w3-total-cache** version **0.9.2.8** -> **W3 Total Cache &lt;= 0.9.4.1 - Authenticated Reflected Cross-Site Scripting (XSS)** : *The W3 Total Cache WordPress plugin was affected by an Authenticated Reflected Cross-Site Scripting (XSS) security vulnerability.*

- **w3-total-cache** version **0.9.2.8** -> **W3 Total Cache 0.9.4 - Edge Mode Enabling CSRF** : *The W3 Total Cache WordPress plugin was affected by an Edge Mode Enabling CSRF security vulnerability.*

- **w3-total-cache** version **0.9.2.8** -> **CVE-2022-31090** : *Guzzle, an extensible PHP HTTP client. `Authorization` headers on requests are sensitive information. In affected versions when using our Curl handler, it is possible to use the `CURLOPT_HTTPAUTH` option to specify an `Authorization` header. On making a request which responds with a redirect to a URI with a different origin (change in host, scheme or port), if we choose to follow it, we should remove the `CURLOPT_HTTPAUTH` option before continuing, stopping curl from appending the `Authorization` header to the new request. Affected Guzzle 7 users should upgrade to Guzzle 7.4.5 as soon as possible. Affected users using any earlier series of Guzzle should upgrade to Guzzle 6.5.8 or 7.4.5. Note that a partial fix was implemented in Guzzle 7.4.2, where a change in host would trigger removal of the curl-added Authorization header, however this earlier fix did not cover change in scheme or change in port. If you do not require or expect redirects to be followed, one should simply disable redirects all together. Alternatively, one can specify to use the Guzzle steam handler backend, rather than curl.*

- **w3-total-cache** version **0.9.2.8** -> **W3 Total Cache &lt;= 0.9.7.3 - Server Side Request Forgery** : *The W3 Total Cache plugin for WordPress is vulnerable to Server Side Request Forgery in versions up to, and including 0.9.7.3, due to insufficient user input validation in the opcache_flush_file file.*

- **w3-total-cache** version **0.9.2.8** -> **W3 Total Cache &lt;= 0.9.7.3 - Improper Input Validation via openssl_verify** : *W3 Total Cache in versions 0.5 up to 0.9.7.3 does not sufficiently validate the &quot;openssl_verify&quot; result in &quot;/services/MessageValidator/MessageValidator.php&quot;. A remote attacker can create a specially crafted certificate and bypass cryptographic checks.*

- **w3-total-cache** version **0.9.2.8** -> **W3 Total Cache plugin &lt;= 0.9.7.3 - Reflected Cross-Site Scripting** : *The W3 Total Cache plugin for WordPress is vulnerable to Reflected Cross-Site Scripting due to insufficient input validation on the $command variable, which makes it possible for attackers to inject arbitrary web sites in victims browsers in versions up to, and including, 0.9.7.3.*

- **w3-total-cache** version **0.9.2.8** -> **W3 Total Cache &lt;= 0.9.4.1 - Weak validation of Amazon SNS push messages** : *The W3 Total Cache plugin for WordPress is vulnerable to weak validation of Amazon SNS push messages in versions up to, and including, 0.9.4.1. This makes it possible for attackers to perform a variety of actions concerning the server&#039;s cache, such as performing a Denial of Service attack on the site.*

- **w3-total-cache** version **0.9.2.8** -> **W3 Total Cache &lt;= 0.9.4 - Server-Side Request Forgery leading to Host Information Disclosure** : *The W3 Total Cache plugin for WordPress is vulnerable to Server-Side Request Forgery in versions up to, and including, 0.9.4. This is due to a minify function incorrectly restricting path input. This makes it possible for attackers to access restricted resources on private networks by using a vulnerable installation as a limited HTTP GET proxy.*

- **w3-total-cache** version **0.9.2.8** -> **W3 Total Cache &lt;= 0.9.4.1 - Security Token Bypass via Type Juggling** : *The W3 Total Cache plugin for WordPress is vulnerable to authorization bypass due to the use of loose comparison on the nonce value in the /pub/apc.php file. This affects versions up to, and including, 0.9.4.1. This makes it possible for attackers to bypass nonce protections if a valid nonce starts with 0e.  In the right situation this bypass can be used to empty the OPCache.*

- **w3-total-cache** version **0.9.2.8** -> **W3 Total Cache &lt;= 0.9.4.1 - Arbitrary File Upload** : *The W3 Total Cache plugin for WordPress is vulnerable to arbitrary file uploads due to missing file type validation in versions up to, and including, 0.9.4.1. This makes it possible for authenticated attackers to upload arbitrary files on the affected sites server which may make remote code execution possible.*

- **w3-total-cache** version **0.9.2.8** -> **W3 Total Cache &lt;= 0.9.4.1 - Authenticated Arbitrary File Download** : *The W3 Total Cache plugin for WordPress is vulnerable to Arbitrary File Download in versions up to, and including, 0.9.4.1 This can allow an administrator attacker to extract sensitive data from wp-config.php that could be used to fully take over the site.*

- **w3-total-cache** version **0.9.2.8** -> **W3 Total Cache &lt;= 0.9.4.1 - Arbitrary Code Execution via settings import** : *The W3 Total Cache plugin for WordPress is vulnerable to Authenticated Arbitrary Code Execution via settings import in versions up to, and including, 0.9.4.1. This makes it possible for authenticated attackers to inject and execute arbitrary code.*

- **w3-total-cache** version **0.9.2.8** -> **W3 Total Cache &lt;= 0.9.4.1 - Cross-Site Scripting via request_id** : *The W3 Total Cache plugin plugin for WordPress is vulnerable to Cross-Site Scripting via the &#039;request_id&#039; parameter in versions up to, and including, 0.9.4.1 due to insufficient input sanitization and output escaping. This makes it possible for attackers to inject arbitrary web scripts that execute in a victim&#039;s browser.*

- **w3-total-cache** version **0.9.2.8** -> **W3 Total Cache &lt;= 0.9.4 - Cross-Site Request Forgery leading to Stored Cross-Site Scripting** : *The W3 Total Cache plugin for WordPress is vulnerable to Cross-Site Request Forgery in versions up to, and including, 0.9.4. This makes it possible for unauthenticated attackers to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page via forged request granted they can trick a site administrator into performing an action such as clicking on a link.*

## WordPress Theme discovery and vulnerabilities
WordPress theme was found in a **link** tag. The path to the theme is: wp-content/themes/twentytwenty

Version of the theme **twentytwenty** was found: **1.5**

## Theme vulnerability analysis:
No vulnerabilities found for this theme

## Robots.txt content
robots.txt file was found: http://192.168.100.28:8000/robots.txt

```
User-agent: *
Disallow: /wp-admin/
Allow: /wp-admin/admin-ajax.php
```
## Headers that may be useful
**Server** : *Apache/2.4.38 (Debian)*

## Enumerating users via WordPress API
**admin**: *admin*

---
## Testing weak credentials
The scanner found the password: adminNebun123

