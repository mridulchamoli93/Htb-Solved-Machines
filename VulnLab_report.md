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

