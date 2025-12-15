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
### 5.1 Cross-Site Scripting (XSS)

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

### 5.2 Cross-Site Scripting (XSS)

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

### 5.3 SQL Injection

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

### 5.4 Cross-Site Scripting (XSS)

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

### 5.5 Cross-Site Scripting (XSS)

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
