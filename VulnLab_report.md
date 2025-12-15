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
