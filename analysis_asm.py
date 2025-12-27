import json
import re
from pathlib import Path
from collections import defaultdict
import html
from datetime import datetime, timezone

def compliance(input):
    analysis = input["blocking-settings"]["http-protocols"]
    disabled_items = [
        item['description'] for item in analysis if not item.get("enabled", False)
    ]
    result = {
        "total": len(analysis),
        "disabled": len(disabled_items),
        "disabled_items": disabled_items
    }
    return result

def evasion(input):
    analysis=input["blocking-settings"]["evasions"]
    disabled_items = [
        item['description'] for item in analysis if not item.get("enabled", False)
    ]
    result = {
        "total": len(analysis),
        "disabled": len(disabled_items),
        "disabled_items": disabled_items
    }
    return result

def cookies(input):
    analysis=input["cookies"]
    total=0
    staged=0
    staged_cookies=[]
    sig_overrides=0
    overrides_cookies=[]
    sig_disabled=0
    disabled_cookies=[]
    enforced=0
    enforced_cookies=[]
    wildcard_staged=False
    wildcard_sig_disabled=False
    maximumCookieHeaderLength=False
    result={"total":total, "staged":staged, "enforced":enforced, "sig_disabled":sig_disabled, 
            "sig_overrides":sig_overrides, "wildcard_staging":wildcard_staged, "wildcard_sig_disabled":wildcard_sig_disabled,
            "maximumCookieHeaderLength":maximumCookieHeaderLength, "overrides_cookies": overrides_cookies, "enforced_cookies": enforced_cookies, "staged_cookies":staged_cookies, "disabled_cookies":disabled_cookies}

    for item in analysis:
        total+=1
        if item["name"]=="*" and item.get("performStaging", False) is True:
            wildcard_staging=True
        if item["name"]!="*" and item.get("performStaging", False) is True:
            staged +=1
            staged_cookies.append(item["name"])
        if item["name"]=="*" and item.get("attackSignaturesCheck", False) is False:
            wildcard_sig_disabled=True
        if item["name"]!="*" and item.get("attackSignaturesCheck", False) is False:
            sig_disabled +=1
            disabled_cookies.append(item["name"])
        if item["enforcementType"]!="allow":
            enforced +=1
            enforced_cookies.append(item["name"])
        if item.get("signatureOverrides"):
            sig_overrides +=1
            overrides_cookies.append(item["name"])

    
    if input["cookie-settings"]["maximumCookieHeaderLength"]=="any":
        maximumCookieHeaderLength=True

    result={"total":total, "staged":staged, "enforced":enforced, "sig_disabled":sig_disabled, 
            "sig_overrides":sig_overrides, "wildcard_staging":wildcard_staged, "wildcard_sig_disabled":wildcard_sig_disabled,
            "maximumCookieHeaderLength":maximumCookieHeaderLength, "overrides_cookies": overrides_cookies, "enforced_cookies": enforced_cookies, "staged_cookies":staged_cookies, "disabled_cookies":disabled_cookies}
    
    return result

def filetypes(input):
    analysis=input["filetypes"]
    total=0
    staged=0
    staged_filetype=[]
    wildcard_staged=False
    result={"total":total, "staged":staged, "wildcard_staged":wildcard_staged,"staged_filetype":staged_filetype}
    
    for item in analysis:
        total+=1
        if item["allowed"]:
            if item["name"]=="*" and item.get("performStaging", False) is True:
                wildcard_staged=True
            if item["name"]!="*" and item.get("performStaging", False) is True:
                staged_filetype.append(item["name"])
                staged +=1
    
    result={"total":total, "staged":staged, "wildcard_staged":wildcard_staged,"staged_filetype":staged_filetype}
    return result

def headers(input):
    analysis=input["headers"]
    total=0
    sig_overrides=0
    overrides_headers=[]
    sig_disabled=0
    disabled_headers=[]
    wildcard_sig_disabled=False
    maximumHttpHeaderLength=False
    result={"total":total,"sig_disabled":sig_disabled, "sig_overrides":sig_overrides, 
            "wildcard_sig_disabled":wildcard_sig_disabled,"maximumHttpHeaderLength":maximumHttpHeaderLength,"overrides_headers":overrides_headers,"disabled_headers":disabled_headers}

    for item in analysis:
        total+=1
        if item.get("signatureOverrides"):
            sig_overrides +=1
            overrides_headers.append(item["name"])
        if item["name"]!="*" and item["checkSignatures"]==False:
            sig_disabled +=1
            disabled_headers.append(item["name"])
        if item["name"]=="*" and item["checkSignatures"]==False:
            wildcard_sig_disabled=True
    if input["header-settings"]["maximumHttpHeaderLength"]=="any":
        maximumHttpHeaderLength=True
    
    result={"total":total,"sig_disabled":sig_disabled, "sig_overrides":sig_overrides, 
            "wildcard_sig_disabled":wildcard_sig_disabled,"maximumHttpHeaderLength":maximumHttpHeaderLength,"overrides_headers":overrides_headers,"disabled_headers":disabled_headers}
    return result

def parameters(input):
    analysis=input["parameters"]
    total=0
    staged=0
    staged_parameters=[]
    sig_overrides=0
    overrides_parameters=[]
    sig_disabled=0
    disabled_parameters=[]
    wildcard_staged=False
    wildcard_sig_disabled=False
    checkMetachars=0
    metacharsOnValue=0
    sensitive_from_list = len(input.get("sensitive-parameters", []))
    sensitive_flagged = 0
    sensitive_parameters=[]

    
    result={"total":total, "staged":staged, "sig_disabled":sig_disabled, "metacharsOnValue":metacharsOnValue, 
            "sig_overrides":sig_overrides, "wildcard_staged":wildcard_staged, "checkMetachars":checkMetachars, 
            "wildcard_sig_disabled":wildcard_sig_disabled,"sensitive_from_list": sensitive_from_list,"sensitive_flagged": sensitive_flagged,"overrides_parameters":overrides_parameters, "staged_parameters":staged_parameters,"disabled_parameters":disabled_parameters,"sensitive_parameters":sensitive_parameters}

    for item in analysis:
        total+=1
        if item.get("signatureOverrides"):
            sig_overrides+=1
            overrides_parameters.append(item["name"])
        if item["name"]=="*" and item.get("performStaging", False) is True:
            wildcard_staged=True
        if item["name"]!="*" and item.get("performStaging", False) is True:
            staged+=1
            staged_parameters.append(item["name"])
        if item["name"]=="*" and item["attackSignaturesCheck"]==False:
            wildcard_sig_disabled=True
        if item["name"]!="*" and item.get("attackSignaturesCheck", True) is False:
            sig_disabled+=1
            disabled_parameters.append(item["name"])
        if item.get("checkMetachars",True)==False:
            checkMetachars+=1
        if item.get("metacharsOnParameterValueCheck", True)==False:
            metacharsOnValue+=1
        if item.get("sensitiveParameter", False):
            sensitive_flagged += 1
            sensitive_parameters.append(item["name"])


    result={"total":total, "staged":staged, "sig_disabled":sig_disabled, "metacharsOnValue":metacharsOnValue, 
            "sig_overrides":sig_overrides, "wildcard_staged":wildcard_staged, "checkMetachars":checkMetachars, 
            "wildcard_sig_disabled":wildcard_sig_disabled,"sensitive_from_list": sensitive_from_list,"sensitive_flagged": sensitive_flagged,"overrides_parameters":overrides_parameters, "staged_parameters":staged_parameters,"disabled_parameters":disabled_parameters,"sensitive_parameters":sensitive_parameters}

    return result

def urls(input):
    analysis=input["urls"]
    total=0
    staged=0
    staged_urls=[]
    sig_overrides=0
    overrides_urls=[]
    sig_disabled=0
    disabled_urls=[]
    wildcard_staged=False
    wildcard_sig_disabled=False
    result={"total":total, "staged":staged, "sig_disabled":sig_disabled, 
            "sig_overrides":sig_overrides, "wildcard_staging":wildcard_staged,
            "wildcard_sig_disabled":wildcard_sig_disabled, "disabled_urls":disabled_urls, "overrides_urls":overrides_urls, "staged_urls":staged_urls}

    for item in analysis:
        total+=1
        if item.get("signatureOverrides"):
            sig_overrides +=1
            overrides_urls.append(item["name"])
        if item["name"]=="*" and item.get("performStaging", False) is True:
            wildcard_staged=True
        if item["name"]!="*" and item.get("performStaging", False) is True:
            staged +=1
            staged_urls.append(item["name"])
        if item["name"]=="*" and item.get("attackSignaturesCheck", True) is False:
            wildcard_sig_disabled=True
        if item["name"]!="*" and item.get("attackSignaturesCheck", True) is False:
            sig_disabled +=1
            disabled_urls.append(item["name"])

    
    result={"total":total, "staged":staged, "sig_disabled":sig_disabled, 
            "sig_overrides":sig_overrides, "wildcard_staging":wildcard_staged,
            "wildcard_sig_disabled":wildcard_sig_disabled, "disabled_urls":disabled_urls, "overrides_urls":overrides_urls, "staged_urls":staged_urls}
    
    return result

def redirection(input):
    analysis=input["redirection-protection"]
    result=False
    if input.get("redirectionProtectionEnabled", False):
        result=True
    return result

def geolocation(input):
    result=False
    if input.get("disallowed-geolocations"):
        result=True
    return result

def icap(input):
    result=False
    if input["antivirus"]["inspectHttpUploads"]==False:
        result=True
    return result

def delete_method(input):
    result=False
    analysis=input["methods"]
    for item in analysis:
        if item["name"]=="DELETE":
            result=True
    return result

def ipi(input):
    total=0
    block_disabled=0
    alarm_disabled=0
    ipi_enabled=False
    if input["ip-intelligence"]["enabled"]==True:
        ipi_enabled=True
    if input["ip-intelligence"].get("ipIntelligenceCategories", False):
        analysis=input["ip-intelligence"]["ipIntelligenceCategories"]
        for item in analysis:
            total+=1
            if item["block"]==False:
                block_disabled+=1
            elif item["alarm"]==False:
                alarm_disabled+=1

    result={"ipi_enabled":ipi_enabled, "total": total, "block_disabled":block_disabled, "alarm_disabled":alarm_disabled}
    return result

def brute_force(input):
    analysis=input["brute-force-attack-preventions"]
    brute=False
    if len(analysis)==1:
        if analysis[0]["bruteForceProtectionForAllLoginPages"]==True:
            brute=True
    if len(analysis)>1:
        brute=True

    analysis=input.get("login-pages",False)
    login_pages=0
    if analysis!=False:
        login_pages=len(analysis)  

    result={"brute":brute, "login_pages": login_pages}

    return result

def caseinsensitive(input):
    result=False
    if input["caseInsensitive"]==False:
        result=True
    return result

def enforcementmode(input):
    result=False
    if input["enforcementMode"]!="blocking":
        result=True
    return result

def response_page(input):
    analysis=input["response-pages"]
    result=False
    for item in analysis:
        if item["responsePageType"]=="default" and item["responseActionType"]=="default":
            result=True
    return result

def signatures_summary(input):
    if input.get("signatures"):
        analysis=input["signatures"]
        count_disabled=0
        count_staging=0
        total=len(analysis)
        for item in analysis:
            if item["enabled"]==False:
                count_disabled +=1
            else:
                if item["performStaging"]==True:
                    count_staging +=1
        result={"total":total,"disabled":count_disabled, "staged":count_staging}
    else:
        result={"total":0,"disabled":0, "staged":0}
    return result

def placeSignaturesInStaging(input):
    result=True
    if input.get("signature-settings") is not None:
        if input["signature-settings"].get("placeSignaturesInStaging", False) == True:
            result=False
    return result

def minimumAccuracyForAutoAddedSignatures(input):
    result="Not Set"
    if input.get("signature-settings") is not None:
        result=input["signature-settings"].get("minimumAccuracyForAutoAddedSignatures", "Not Set")
    return result

def trustedByPolicyBuilder(input):
    count=0
    if input.get("whitelist-ips"):
        analysis=input["whitelist-ips"]
        for item in analysis:
            if item["trustedByPolicyBuilder"]==True:
                count +=1
    return count

def trustAllIps(input):
    result=False
    if input["policy-builder"].get("trustAllIps", False)==True:
        result=True
    return result

def list_to_dict(problems_list: list) -> dict:
    """
    Convert a list of dictionaries into a single dictionary
    using each item's 'name' as the key.
    """
    result = {}
    for item in problems_list:
        name = item.get("name")
        if name is not None:
            result[name] = {k: v for k, v in item.items() if k != "name"}
    return result

def dict_to_list(problems_dict: dict) -> list:
    """
    Convert problems_found = {key: {...}} into a list of dicts,
    keeping the key as 'name' in each item.
    """
    result = []
    for key, value in problems_dict.items():
        entry = value.copy()     # avoid modifying original dict
        entry["name"] = key      # keep the key
        result.append(entry)
    return result

def run_audit(input):
        
    problems_found = {
        "compliance_total": {"title": "", "brief": "", "details": "", "section": "", "rating": "", "issue": False, "additional_info": "", "additional_tex": ""},
        "evasion": {"title": "", "brief": "", "details": "", "section": "", "rating": "", "issue": False, "additional_info": "", "additional_tex": ""},
        "Cookies_staging": {"title": "", "brief": "", "details": "", "section": "", "rating": "", "issue": False},
        "Cookies_enforced": {"title": "", "brief": "", "details": "", "section": "", "rating": "", "issue": False},
        "Cookies_sig_disabled": {"title": "", "brief": "", "details": "", "section": "", "rating": "", "issue": False},
        "Cookies_sig_overrides": {"title": "", "brief": "", "details": "", "section": "", "rating": "", "issue": False},
        "Cookies_wildcard_staging": {"title": "", "brief": "", "details": "", "section": "", "rating": "", "issue": False},
        "Cookies_wildcard_sig_disabled": {"title": "", "brief": "", "details": "", "section": "", "rating": "", "issue": False},
        "wildcard_sig_disabled": {"title": "", "brief": "", "details": "", "section": "", "rating": "", "issue": False},
        "FileType_staged": {"title": "", "brief": "", "details": "", "section": "", "rating": "", "issue": False},
        "FileType_wildcard_staged": {"title": "", "brief": "", "details": "", "section": "", "rating": "", "issue": False},
        "Header_sig_overrides": {"title": "", "brief": "", "details": "", "section": "", "rating": "", "issue": False},
        "Header_sig_disabled": {"title": "", "brief": "", "details": "", "section": "", "rating": "", "issue": False},
        "Header_wildcard_sig_disabled": {"title": "", "brief": "", "details": "", "section": "", "rating": "", "issue": False},
        "maximumHttpHeaderLength": {"title": "", "brief": "", "details": "", "section": "", "rating": "", "issue": False},
        "Parameter_sig_overrides": {"title": "", "brief": "", "details": "", "section": "", "rating": "", "issue": False},
        "Parameter_sig_disabled": {"title": "", "brief": "", "details": "", "section": "", "rating": "", "issue": False},
        "Parameter_staging": {"title": "", "brief": "", "details": "", "section": "", "rating": "", "issue": False},
        "Parameter_wildcard_sig_staged": {"title": "", "brief": "", "details": "", "section": "", "rating": "", "issue": False},
        "Parameter_wildcard_sig_disabled": {"title": "", "brief": "", "details": "", "section": "", "rating": "", "issue": False},
        "Parameter_sensitive": {"title": "", "brief": "", "details": "", "section": "", "rating": "", "issue": False},
        "URL_sig_staging": {"title": "", "brief": "", "details": "", "section": "", "rating": "", "issue": False},
        "URL_sig_disabled": {"title": "", "brief": "", "details": "", "section": "", "rating": "", "issue": False},
        "URL_overrides": {"title": "", "brief": "", "details": "", "section": "", "rating": "", "issue": False},
        "URL_wildcard_sig_staging": {"title": "", "brief": "", "details": "", "section": "", "rating": "", "issue": False},
        "URL_wildcard_sig_disabled": {"title": "", "brief": "", "details": "", "section": "", "rating": "", "issue": False},
        "redirection_protection": {"title": "", "brief": "", "details": "", "section": "", "rating": "", "issue": False},
        "geolocation": {"title": "", "brief": "", "details": "", "section": "", "rating": "", "issue": False},
        "ICAP": {"title": "", "brief": "", "details": "", "section": "", "rating": "", "issue": False},
        "delete_method": {"title": "", "brief": "", "details": "", "section": "", "rating": "", "issue": False},
        "IPI": {"title": "", "brief": "", "details": "", "section": "", "rating": "", "issue": False},
        "brute": {"title": "", "brief": "", "details": "", "section": "", "rating": "", "issue": False},
        "caseinsensitive": {"title": "", "brief": "", "details": "", "section": "", "rating": "", "issue": False},
        "enforcementMode": {"title": "", "brief": "", "details": "", "section": "", "rating": "", "issue": False},
        "Response_page": {"title": "", "brief": "", "details": "", "section": "", "rating": "", "issue": False},
        "no_signatures": {"title": "", "brief": "", "details": "", "section": "", "rating": "", "issue": False},
        "all_signatures_disabled": {"title": "", "brief": "", "details": "", "section": "", "rating": "", "issue": False},
        "many_signatures_disabled": {"title": "", "brief": "", "details": "", "section": "", "rating": "", "issue": False},
        "some_signatures_disabled": {"title": "", "brief": "", "details": "", "section": "", "rating": "", "issue": False},
        "many_signatures_staging": {"title": "", "brief": "", "details": "", "section": "", "rating": "", "issue": False},
        "some_signatures_staging": {"title": "", "brief": "", "details": "", "section": "", "rating": "", "issue": False},
        "placeSignaturesInStaging": {"title": "", "brief": "", "details": "", "section": "", "rating": "", "issue": False},
        "minimumAccuracyForAutoAddedSignatures": {"title": "", "brief": "", "details": "", "section": "", "rating": "", "issue": False},
        "trustedByPolicyBuilder": {"title": "", "brief": "", "details": "", "section": "", "rating": "", "issue": False}
    }

    blocking_settings = list_to_dict(input["blocking-settings"]["violations"])

    # ---------- HTTP Protocol Compliance ----------
    output = compliance(input)
    if output["disabled"] > 0 and blocking_settings["VIOL_HTTP_PROTOCOL"]["block"] is True:
        if output["total"] == output["disabled"]:
            problems_found['compliance_total'] = {
                "brief": "All HTTP protocol compliance checks are disabled even though the main violation is set to block.",
                "details": (
                    "All HTTP protocol compliance sub-violations are disabled, "
                    "even though the main 'HTTP protocol compliance failed' violation is configured to block. "
                    "As a result, malformed or non-RFC-compliant HTTP requests may not be detected or blocked as expected."
                ),
                "title": "HTTP Protocol Compliance disabled",
                "section": "Protocol Compliance",
                "rating": "Medium",
                "issue": True
            }
        else:
            problems_found['compliance_total'] = {
                "brief": "Some HTTP protocol compliance checks are disabled while the main violation is set to block.",
                "details": (
                    f"{output['disabled']} out of {output['total']} HTTP protocol compliance sub-violations are disabled, "
                    "while the main 'HTTP protocol compliance failed' violation is configured to block. "
                    "Review these disabled checks to ensure they were intentionally turned off and do not reduce the desired level of protocol enforcement."
                ),
                "title": "HTTP Protocol Compliance partially disabled",
                "section": "Protocol Compliance",
                "rating": "Medium",
                "issue": True,
                "additional_info": output['disabled_items'],
                "additional_text": "The following HTTP protocol compliance checks are disabled:"
            }

    # ---------- Evasion Techniques ----------
    output = evasion(input)
    if output["disabled"] > 0 and blocking_settings["VIOL_EVASION"]["block"] is True:
        if output["total"] == output["disabled"]:
            problems_found['evasion'] = {
                "brief": "All evasion technique checks are disabled although the evasion violation is configured to block.",
                "details": (
                    "All evasion technique violations are disabled, "
                    "even though the main 'Evasion technique detected' violation is configured to block. "
                    "This may allow attackers to bypass the policy using encoding or obfuscation techniques that are not being inspected."
                ),
                "title": "All Evasion Techniques disabled",
                "section": "Evasions",
                "rating": "High",
                "issue": True
            }
        else:
            problems_found['evasion'] = {
                "brief": "Some evasion technique checks are disabled, which may weaken protection against bypass techniques.",
                "details": (
                    f"{output['disabled']} out of {output['total']} evasion technique violations are disabled. "
                    "Review the disabled techniques to verify they were intentionally excluded and do not expose the application to evasion-based attacks."
                ),
                "title": "Some Evasion Techniques disabled",
                "section": "Evasions",
                "rating": "Medium",
                "issue": True,
                "additional_info": output['disabled_items'],
                "additional_text": "The following Evasion techniques are disabled:"                
            }

    # ---------- Cookies ----------
    output = cookies(input)
    if output["staged"] > 0:
        problems_found['Cookies_staging'] = {
            "brief": "Some cookies are still in staging and only generate logs instead of blocking attacks.",
            "details": (
                f"{output['staged']} out of {output['total']} cookies are still in staging. "
                "While in staging, cookie-related attack signatures generate logs only and do not block requests. "
                "Review these cookies and move them to enforcement once you are confident there are no false positives."
            ),
            "title": "Cookies in Staging",
            "section": "Cookies",
            "rating": "Medium",
            "issue": True,
            "additional_info": output['staged_cookies'],
            "additional_text": "The following Cookies are in staging mode:"   
        }

    if output["enforced"] > 0 and blocking_settings["VIOL_COOKIE_MODIFIED"]["block"] is True:
        problems_found["Cookies_enforced"] = {
            "brief": "Some cookies are configured as enforced and cannot be modified by clients.",
            "details": (
                f"{output['enforced']} cookies are configured as enforced. "
                "Enforced cookies cannot be modified by clients without triggering a policy violation. "
                "Confirm that the enforced cookies are limited to session or security-sensitive cookies to avoid unnecessary blocking."
            ),
            "title": "Enforced Cookies",
            "section": "Cookies",
            "rating": "Medium",
            "issue": True,
            "additional_info": output['enforced_cookies'],
            "additional_text": "The following Cookies are enforced:"   
        }

    if output["sig_disabled"] > 0:
        problems_found["Cookies_sig_disabled"] = {
            "brief": "Some cookies have their attack signatures disabled, reducing cookie-level protection.",
            "details": (
                f"{output['sig_disabled']} out of {output['total']} cookies have their attack signatures disabled. "
                "In this state, signature-based detection of attacks targeting these cookies is not performed. "
                "Review these cookies and re-enable signatures where possible to maintain adequate protection."
            ),
            "title": "Cookies Signature disabled",
            "section": "Cookies",
            "rating": "Medium",
            "issue": True,
            "additional_info": output['disabled_cookies'],
            "additional_text": "The following Cookies have their signatures disabled:"
        }

    if output["sig_overrides"] > 0:
        problems_found["Cookies_sig_overrides"] = {
            "brief": "Few cookies use attack signature overrides that may weaken detection if too broad.",
            "details": (
                f"{output['sig_overrides']} out of {output['total']} cookies have attack signature overrides configured. "
                "Extensive or overly permissive overrides can weaken protection and introduce blind spots. "
                "Review these overrides to ensure they are justified and as narrow as possible."
            ),
            "title": "Cookies Signature Overrides",
            "section": "Cookies",
            "rating": "Low",
            "issue": True,
            "additional_info": output['overrides_cookies'],
            "additional_text": "The following Cookies have signatures overrides:"
        }

    if output["wildcard_staging"] is True:
        problems_found["Cookies_wildcard_staging"] = {
            "brief": "The wildcard cookie is still in staging and only logs attacks instead of blocking them.",
            "details": (
                "The wildcard (*) cookie is configured in staging. "
                "While this setting is active, attacks that match the wildcard cookie pattern will only be logged and not blocked. "
                "Move the wildcard cookie to enforcement or replace it with more specific cookie definitions to ensure proper protection."
            ),
            "title": "Wildcard Cookie in staging",
            "section": "Cookies",
            "rating": "High",
            "issue": True
        }

    if output["wildcard_sig_disabled"] is True:
        problems_found["Cookies_wildcard_sig_disabled"] = {
            "brief": "The wildcard cookie has its attack signatures disabled, creating a broad blind spot.",
            "details": (
                "The wildcard (*) cookie has its attack signatures disabled. "
                "This means that any attack matching the wildcard cookie pattern will not be detected by signatures. "
                "Re-enable signatures or refine the wildcard configuration to avoid creating a broad blind spot."
            ),
            "title": "Wildcard Cookie signatures disabled",
            "section": "Cookies",
            "rating": "High",
            "issue": True
        }

    if output["maximumCookieHeaderLength"] is True and blocking_settings["VIOL_COOKIE_LENGTH"]["block"] is True:
        problems_found["wildcard_sig_disabled"] = {
            "brief": "Cookie length is set to any while illegal cookie length is configured to block.",
            "details": (
                "The maximum cookie header length is configured as 'any', while the 'Illegal cookie length' violation is set to block. "
                "In this configuration, the policy does not enforce a specific cookie length, so the violation is effectively not triggered. "
                "If you want to enforce cookie size limits, configure a concrete maximum length or disable the blocking of this violation."
            ),
            "title": "Cookie Length enforcement",
            "section": "Cookies",
            "rating": "Medium",
            "issue": True
        }

    # ---------- File Types ----------
    output = filetypes(input)

    if output["staged"] > 0:
        problems_found["FileType_staged"] = {
            "brief": "Some file types are still in staging and only log violations.",
            "details": (
                f"{output['staged']} out of {output['total']} file types are still in staging. "
                "While in staging, file-type related signatures will not block requests, only log them. "
                "Review these file types and move them to enforcement once you are satisfied that the policy is accurate."
            ),
            "title": "File Type Staging",
            "section": "File Types",
            "rating": "Low",
            "issue": True,
            "additional_info": output['staged_filetype'],
            "additional_text": "The following FileTypes are in staging mode:"
        }

    if output["wildcard_staged"] is True:
        problems_found["FileType_wildcard_staged"] = {
            "brief": "The wildcard file type entry is still in staging and does not enforce illegal file types.",
            "details": (
                "The wildcard (*) file type entry is still in staging. "
                "In this state, attacks against any file extension covered by the wildcard will not be blocked, only logged. "
                "Replace the wildcard with explicit file types or move it to enforcement to ensure illegal file type extensions are mitigated."
            ),
            "title": "Wildcard File Type in staging",
            "section": "File Types",
            "rating": "High",
            "issue": True
        }

    # ---------- Headers ----------
    output = headers(input)

    if output["sig_overrides"] > 0:
        problems_found["Header_sig_overrides"] = {
            "brief": "Few HTTP headers use attack signature overrides that may reduce header-level protection.",
            "details": (
                f"{output['sig_overrides']} out of {output['total']} HTTP headers have attack signature overrides configured. "
                "While overrides are sometimes necessary to reduce false positives, excessive or overly broad overrides can weaken header-level protection. "
                "Review the configured overrides to ensure they are justified and as specific as possible."
            ),
            "title": "HTTP Header Signature Overrides",
            "section": "HTTP Headers",
            "rating": "Low",
            "issue": True,
            "additional_info": output['overrides_headers'],
            "additional_text": "The following Headers have signatures overrides:"
        }

    if output["sig_disabled"] > 0:
        problems_found["Header_sig_disabled"] = {
            "brief": "Some HTTP headers have their attack signatures disabled, reducing inspection coverage.",
            "details": (
                f"{output['sig_disabled']} out of {output['total']} HTTP headers have their attack signatures disabled. "
                "In this state, signature-based detection for attacks leveraging these headers will not occur. "
                "Re-enable signatures where appropriate to maintain full header inspection coverage."
            ),
            "title": "HTTP Header Signature disabled",
            "section": "HTTP Headers",
            "rating": "Medium",
            "issue": True,
            "additional_info": output['disabled_headers'],
            "additional_text": "The following Headers have their signatures disabled:"
        }

    if output["wildcard_sig_disabled"] is True:
        problems_found["Header_wildcard_sig_disabled"] = {
            "brief": "The wildcard HTTP header entry has signatures disabled, significantly weakening protection.",
            "details": (
                "The wildcard (*) HTTP header entry has its attack signatures disabled. "
                "This effectively disables signature-based inspection for any header matching the wildcard and can significantly reduce protection. "
                "Re-enable signatures for the wildcard header or replace it with more specific header definitions."
            ),
            "title": "Wildcard HTTP Header signatures disabled",
            "section": "HTTP Headers",
            "rating": "High",
            "issue": True
        }

    if output["maximumHttpHeaderLength"] is True and blocking_settings["VIOL_HEADER_LENGTH"]["block"] is True:
        problems_found["maximumHttpHeaderLength"] = {
            "brief": "HTTP header length is set to any while illegal header length is configured to block.",
            "details": (
                "The maximum HTTP header length is configured as 'any', while the 'Illegal header length' violation is set to block. "
                "Because no concrete maximum is defined, this violation will not be triggered by oversized headers. "
                "If you want to enforce header size limits, configure a specific maximum length or disable blocking for this violation."
            ),
            "title": "HTTP Header Length enforcement",
            "section": "HTTP Headers",
            "rating": "Medium",
            "issue": True
        }

    # ---------- Parameters ----------
    output = parameters(input)

    if output["sig_overrides"] > 0:
        problems_found["Parameter_sig_overrides"] = {
            "brief": "Few parameters use attack signature overrides that may weaken parameter-level security.",
            "details": (
                f"{output['sig_overrides']} out of {output['total']} parameters have attack signature overrides configured. "
                "Overrides can help tune false positives, but too many or overly broad overrides may significantly reduce parameter-level protection. "
                "Review these overrides and narrow or remove them where possible."
            ),
            "title": "Parameters Signature Overrides",
            "section": "Parameters",
            "rating": "Low",
            "issue": True,
            "additional_info": output['overrides_parameters'],
            "additional_text": "The following Parameters have signatures overrides:"
        }

    if output["sig_disabled"] > 0:
        problems_found["Parameter_sig_disabled"] = {
            "brief": "Some parameters have their attack signatures disabled, reducing inspection of those fields.",
            "details": (
                f"{output['sig_disabled']} out of {output['total']} parameters have their attack signatures disabled. "
                "In this configuration, signature-based attacks targeting these parameters will not be detected. "
                "Re-enable signatures for critical parameters to maintain appropriate protection."
            ),
            "title": "Parameters Signature disabled",
            "section": "Parameters",
            "rating": "Low",
            "issue": True,
            "additional_info": output['disabled_parameters'],
            "additional_text": "The following Parameters have their signatures disabled:"
        }

    if output["staged"] is True:
        problems_found["Parameter_staging"] = {
            "brief": "Parameters are still in staging so parameter-based attacks are only logged.",
            "details": (
                f"{output['staged']} out of {output['total']} Parameters are still in staging. "
                "While Parameters are in staging, signature-based violations on those URLs are logged but not blocked. "
                "Review these URLs and move them to enforcement when you are comfortable with the behavior."
            ),
            "title": "Wildcard Parameter in staging",
            "section": "Parameters",
            "rating": "High",
            "issue": True,
            "additional_info": output['staged_parameters'],
            "additional_text": "The following Parameters are in staging mode:"
        }

    if output["wildcard_staged"] is True:
        problems_found["Parameter_wildcard_sig_staged"] = {
            "brief": "The wildcard parameter entry is staged and does not enforce parameter signatures.",
            "details": (
                "The wildcard (*) parameter entry is still in staging. "
                "Requests that violate parameter-based signatures under this wildcard will not be blocked. "
                "Review and enforce this wildcard or refine it into explicit parameters."
            ),
            "title": "Wildcard Parameter in staging",
            "section": "Parameters",
            "rating": "High",
            "issue": True
        }

    if output["wildcard_sig_disabled"] is True:
        problems_found["Parameter_wildcard_sig_disabled"] = {
            "brief": "The wildcard parameter entry has signatures disabled, leaving many parameters unprotected.",
            "details": (
                "The wildcard (*) parameter entry has its attack signatures disabled. "
                "This may leave a wide range of parameters unprotected from signature-based detection. "
                "Re-enable signatures or tighten the wildcard definition to avoid broad exposure."
            ),
            "title": "Wildcard Parameter signatures disabled",
            "section": "Parameters",
            "rating": "High",
            "issue": True
        }

    if output["sensitive_from_list"] <= 1 and output["sensitive_flagged"] == 0:
        problems_found["Parameter_sensitive"] = {
            "brief": "Only default sensitive parameters are configured and password fields are not explicitly marked.",
            "details": (
                "Only the default sensitive parameter configuration is in use. "
                "Password fields and other sensitive inputs (such as authentication tokens or payment data) are not explicitly marked as sensitive. "
                "Add all password-related and high-risk parameters as sensitive so they benefit from additional protection and masking in logs."
            ),
            "title": "Sensitive Parameter configuration",
            "section": "Parameters",
            "rating": "High",
            "issue": True,
            "additional_info": output['sensitive_parameters'],
            "additional_text": "The following are the sensitive Parameters configured:"
        }

    # ---------- URLs ----------
    output = urls(input)
    if output["staged"] > 0:
        problems_found["URL_sig_staging"] = {
            "brief": "Some URLs are still in staging, so violations on them are only logged.",
            "details": (
                f"{output['staged']} out of {output['total']} URLs are still in staging. "
                "While URLs are in staging, signature-based violations on those URLs are logged but not blocked. "
                "Review these URLs and move them to enforcement when you are comfortable with the behavior."
            ),
            "title": "URLs in staging",
            "section": "URLs",
            "rating": "Low",
            "issue": True,
            "additional_info": output['staged_urls'],
            "additional_text": "The following Urls are in staging mode:"
        }

    if output["sig_disabled"] > 0:
        problems_found["URL_sig_disabled"] = {
            "brief": "Some URLs have their attack signatures disabled, reducing URL-level protection.",
            "details": (
                f"{output['sig_disabled']} out of {output['total']} URLs have their attack signatures disabled. "
                "Requests to these URLs will not be inspected by signatures, which can reduce overall protection. "
                "Re-enable signatures on critical URLs or justify why they must remain disabled."
            ),
            "title": "URLs Signature disabled",
            "section": "URLs",
            "rating": "Low",
            "issue": True,
            "additional_info": output['disabled_urls'],
            "additional_text": "The following URLs have their signatures disabled:"
        }

    if output["sig_overrides"] > 0:
        problems_found["URL_overrides"] = {
            "brief": "Few URLs use attack signature overrides that may hide real attacks if too permissive.",
            "details": (
                f"{output['sig_overrides']} out of {output['total']} URLs have attack signature overrides configured. "
                "Excessive overrides may indicate tuning issues and can hide real attacks if overly permissive. "
                "Review these URLs and confirm that the overrides are required and tightly scoped."
            ),
            "title": "URLs Signature Overrides",
            "section": "URLs",
            "rating": "Low",
            "issue": True,
            "additional_info": output['overrides_urls'],
            "additional_text": "The following URLs have signatures overrides:"
        }

    if output["wildcard_staging"] is True:
        problems_found["URL_wildcard_sig_staging"] = {
            "brief": "The wildcard URL entry is staged, so wildcard URL attacks are only logged.",
            "details": (
                "The wildcard (*) URL entry is still in staging. "
                "Attacks that match this wildcard URL pattern will not be blocked, only logged. "
                "Move the wildcard URL to enforcement or replace it with explicit URL entries to ensure proper coverage."
            ),
            "title": "Wildcard URL in staging",
            "section": "URLs",
            "rating": "High",
            "issue": True
        }

    if output["wildcard_sig_disabled"] is True:
        problems_found["URL_wildcard_sig_disabled"] = {
            "brief": "The wildcard URL entry has signatures disabled, significantly weakening URL protection.",
            "details": (
                "The wildcard (*) URL entry has its attack signatures disabled. "
                "This effectively disables signature-based inspection for a broad set of URLs, which can significantly weaken protection. "
                "Re-enable signatures or split the wildcard into specific URL entries where tuning can be more precise."
            ),
            "title": "Wildcard URL signatures disabled",
            "section": "URLs",
            "rating": "High",
            "issue": True
        }

    # ---------- Redirection Protection ----------
    output = redirection(input)
    if output is True and blocking_settings["VIOL_REDIRECT"]["block"] is True:
        problems_found["redirection_protection"] = {
            "brief": "Illegal redirection protection is not enabled, so redirection domains are not enforced.",
            "details": (
                "Illegal redirection protection is not enabled under Headers → Redirection Protection. "
                "Without this control, the policy cannot enforce allowed redirection domains or detect malicious redirect attempts. "
                "Enable redirection protection and define allowed domains to prevent open-redirect style attacks."
            ),
            "title": "Redirection Domains Configuration",
            "section": "General",
            "rating": "Low",
            "issue": True
        }

    # ---------- Geolocation ----------
    output = geolocation(input)
    if output is True and blocking_settings["VIOL_GEOLOCATION"]["block"] is True:
        problems_found["geolocation"] = {
            "brief": "No disallowed countries are configured for geolocation-based blocking.",
            "details": (
                "No countries are configured on the disallowed geolocation list. "
                "If you intend to block traffic from specific regions, this configuration will not enforce those restrictions. "
                "Review the geolocation policy and add any countries that should be explicitly blocked."
            ),
            "title": "No Countries configured",
            "section": "General",
            "rating": "Low",
            "issue": True
        }

    # ---------- ICAP / Antivirus ----------
    output = icap(input)
    if output is True and blocking_settings["VIOL_VIRUS"]["block"] is True:
        problems_found["ICAP"] = {
            "brief": "Antivirus inspection via ICAP is not configured for HTTP uploads.",
            "details": (
                "ASM is not configured to inspect HTTP uploads through an antivirus (ICAP) integration. "
                "Without file scanning, malicious content uploaded by users may not be detected at the WAF layer. "
                "If file upload inspection is required, integrate an ICAP antivirus server and enable inspection for HTTP uploads."
            ),
            "title": "ICAP integration",
            "section": "General",
            "rating": "Low",
            "issue": True
        }

    # ---------- HTTP Methods ----------
    output = delete_method(input)
    if output is True and blocking_settings["VIOL_METHOD"]["block"] is True:
        problems_found["delete_method"] = {
            "brief": "The HTTP DELETE method is allowed, which can increase the impact of compromised accounts.",
            "details": (
                "The HTTP DELETE method is configured as an allowed method. "
                "Allowing DELETE can increase the impact of compromised credentials or vulnerabilities, as it enables content removal operations. "
                "Restrict or block DELETE unless it is explicitly required by the application."
            ),
            "title": "HTTP Methods",
            "section": "Methods",
            "rating": "Low",
            "issue": True
        }

    # ---------- IP Intelligence ----------
    output = ipi(input)
    if output["ipi_enabled"] is False:
        problems_found["IPI"] = {
            "brief": "IP Intelligence is disabled and reputation services are not used for blocking.",
            "details": (
                "IP Intelligence is disabled, even though the related blocking violation is enabled in Blocking Settings. "
                "In this state, the policy does not benefit from reputation-based blocking of known bad IPs. "
                "Enable IP Intelligence and configure the relevant categories if you want to leverage IP reputation data."
            ),
            "title": "IP Intelligence disabled",
            "section": "IP Intelligence",
            "rating": "Medium",
            "issue": True
        }
    else:
        if output["block_disabled"] > 0:
            if output["total"] == output["block_disabled"]:
                problems_found["IPI"] = {
                    "brief": "All IP Intelligence categories have blocking disabled and only log events.",
                    "details": (
                        "All IP Intelligence categories have blocking disabled. "
                        "Although IP Intelligence is enabled, no categories will actually block requests, only log them. "
                        "Review the categories and enable blocking for those that should actively mitigate malicious sources."
                    ),
                    "title": "All IP Intelligence Categories blocking disabled",
                    "section": "IP Intelligence",
                    "rating": "Medium",
                    "issue": True
                }
            else:
                problems_found["IPI"] = {
                    "brief": "Some IP Intelligence categories only log and do not block malicious IPs.",
                    "details": (
                        f"{output['block_disabled']} out of {output['total']} IP Intelligence categories have blocking disabled. "
                        "These categories will only log events without actively blocking traffic. "
                        "Review the configuration and enable blocking on categories where you expect automated mitigation."
                    ),
                    "title": "IP Intelligence Categories blocking disabled",
                    "section": "IP Intelligence",
                    "rating": "Medium",
                    "issue": True
                }

        if output["alarm_disabled"] > 0:
            problems_found["IPI"] = {
                "brief": "Some IP Intelligence categories block without logging, limiting troubleshooting visibility.",
                "details": (
                    "Some IP Intelligence categories have blocking enabled without corresponding logging. "
                    "Without logging, it may be difficult to troubleshoot or audit why specific clients were blocked. "
                    "Enable logging (alarm) for IP Intelligence categories where visibility is required."
                ),
                "title": "IP Intelligence Logging",
                "section": "IP Intelligence",
                "rating": "Low",
                "issue": True
            }

    # ---------- Brute Force ----------
    output = brute_force(input)

    if output["brute"] is False and blocking_settings["VIOL_BRUTE_FORCE"]["block"] is True:
        problems_found["brute"] = {
            "brief": "Brute force protection is disabled even though the brute force violation is configured to block.",
            "details": (
                "Brute force protection is disabled, even though the 'Login URL detected as a brute force attack' violation is configured to block. "
                "In this state, repeated failed login attempts will not be mitigated by the WAF. "
                "Enable brute force protection and configure appropriate thresholds to protect authentication endpoints."
            ),
            "title": "Brute Force disabled",
            "section": "Brute Force",
            "rating": "Low",
            "issue": True
        }
    else:
        if output["login_pages"] <= 1:
            problems_found["brute"] = {
                "brief": "Brute force protection is enabled but login pages are not properly defined.",
                "details": (
                    "Brute force protection is enabled but no dedicated login pages (or only the default) are configured. "
                    "Without properly defined login URLs, the system cannot accurately detect and enforce brute force thresholds. "
                    "Configure all relevant login pages so brute force protection can be applied effectively."
                ),
                "title": "Login Pages missing",
                "section": "Brute Force",
                "rating": "Medium",
                "issue": True
            }

    # ---------- Case Sensitivity ----------
    output = caseinsensitive(input)
    if output is True:
        problems_found["caseinsensitive"] = {
            "brief": "The policy is case-sensitive, which can make maintenance and tuning more complex.",
            "details": (
                "The policy is configured as case-sensitive. "
                "Case-sensitive policies can be harder to maintain and may lead to unexpected differences between similar objects. "
                "For ease of use and consistency, consider switching to a case-insensitive policy unless there is a specific requirement."
            ),
            "title": "Case-sensitive Policy",
            "section": "General",
            "rating": "Info",
            "issue": True
        }

    # ---------- Enforcement Mode ----------
    output = enforcementmode(input)
    if output is True:
        problems_found["enforcementMode"] = {
            "brief": "The ASM policy runs in Transparent mode and does not block violations.",
            "details": (
                "The ASM policy is running in Transparent mode. "
                "In this mode, violations are logged but not blocked, so the application is effectively unprotected from active enforcement. "
                "When you are confident about the policy tuning, switch the policy to Blocking mode to start mitigating attacks."
            ),
            "title": "Policy in Transparent Mode",
            "section": "General",
            "rating": "Critical",
            "issue": True
        }

    # ---------- Response Page ----------
    output = response_page(input)
    if output is True:
        problems_found["Response_page"] = {
            "brief": "The default blocking page is used instead of a customized response page.",
            "details": (
                "The default blocking page is in use. "
                "Using a customized blocking page that matches the application's look and feel can provide a better user experience and clearer guidance to legitimate users. "
                "Consider customizing the response page to align with your corporate branding and messaging."
            ),
            "title": "Default Blocking Page",
            "section": "General",
            "rating": "Info",
            "issue": True
        }

    # ---------- Signatures Summary ----------
    output = signatures_summary(input)
    if output["total"] == 0:
        problems_found["no_signatures"] = {
            "brief": "No attack signatures are enabled for this policy.",
            "details": (
                "No attack signatures are enabled for this ASM policy. "
                "Without signatures, the policy will not detect a wide range of known attack patterns (for example SQLi, XSS, RFI). "
                "Enable appropriate signature sets to provide baseline protection for the application."
            ),
            "title": "No Signatures enabled",
            "section": "Signatures",
            "rating": "Critical",
            "issue": True
        }
    elif output["total"] == output["disabled"]:
        problems_found["all_signatures_disabled"] = {
            "brief": "All configured attack signatures are disabled.",
            "details": (
                "All attack signatures configured on this policy are disabled. "
                "In this state, the WAF will not detect any signature-based attacks, significantly reducing effectiveness. "
                "Review why signatures have been disabled and re-enable the relevant sets as soon as possible."
            ),
            "title": "All Signatures are disabled",
            "section": "Signatures",
            "rating": "Critical",
            "issue": True
        }
    elif output["total"] == output["staged"]:
        problems_found["all_signatures_disabled"] = {  # keep key name for backward compatibility
            "brief": "All signatures are in staging mode and only log attacks.",
            "details": (
                "All attack signatures are currently in staging. "
                "While in staging, signatures only generate logs and do not block malicious requests. "
                "Once you have validated that there are no false positives, move the signatures to enforcement to fully protect the application."
            ),
            "title": "All Signatures in staging",
            "section": "Signatures",
            "rating": "Critical",
            "issue": True
        }
    else:
        if output["disabled"] > 20:
            problems_found["many_signatures_disabled"] = {
                "brief": "A large number of signatures are disabled, which may create coverage gaps.",
                "details": (
                    f"Many signatures ({output['disabled']} out of {output['total']}) are disabled. "
                    "Large numbers of disabled signatures may indicate overly aggressive tuning and can leave significant attack coverage gaps. "
                    "Review the disabled signatures and re-enable those that are still relevant to your application."
                ),
                "title": "Many Signatures disabled",
                "section": "Signatures",
                "rating": "High",
                "issue": True
            }
        elif output["disabled"] > 0:
            problems_found["some_signatures_disabled"] = {
                "brief": "Some signatures are disabled and may remove important detections.",
                "details": (
                    f"Some signatures ({output['disabled']} out of {output['total']}) are disabled. "
                    "While disabling specific signatures can reduce false positives, it may also remove important detections. "
                    "Verify that each disabled signature has a clear justification and does not expose the application to known attacks."
                ),
                "title": "Some Signatures disabled",
                "section": "Signatures",
                "rating": "Low",
                "issue": True
            }

        if output["staged"] > 20:
            problems_found["many_signatures_staging"] = {
                "brief": "Many signatures are still in staging and do not yet block traffic.",
                "details": (
                    f"Many signatures ({output['staged']} out of {output['total']}) are still in staging. "
                    "Prolonged staging for a large number of signatures may delay full protection for the application. "
                    "Review the staged signatures and move them to enforcement when you are comfortable with their behavior."
                ),
                "title": "Many Signatures in staging",
                "section": "Signatures",
                "rating": "High",
                "issue": True
            }
        elif output["staged"] > 0:
            problems_found["some_signatures_staging"] = {
                "brief": "Some signatures are still in staging and only log attacks.",
                "details": (
                    f"Some signatures ({output['staged']} out of {output['total']}) are still in staging. "
                    "While in staging, these signatures generate logs but do not block traffic. "
                    "After validating that they do not generate false positives, move them to enforcement to complete the protection profile."
                ),
                "title": "Some Signatures in staging",
                "section": "Signatures",
                "rating": "Medium",
                "issue": True
            }

    # ---------- Place new/updated signatures in staging ----------
    output = placeSignaturesInStaging(input)
    if output is True:
        problems_found["placeSignaturesInStaging"] = {
            "brief": "New and updated signatures are not automatically placed in staging.",
            "details": (
                "The option to automatically place new and updated signatures in staging is currently disabled. "
                "Without this staging period, new signatures will immediately enforce and may cause unexpected blocking. "
                "It is recommended to enable 'placeSignaturesInStaging' so you can monitor logs and tune false positives before enabling blocking."
            ),
            "title": "Place New/Updated Signatures in staging",
            "section": "Signatures",
            "rating": "Low",
            "issue": True
        }

    # ---------- Minimum Accuracy for auto-added signatures ----------
    output = minimumAccuracyForAutoAddedSignatures(input)
    if output == "medium":
        problems_found["minimumAccuracyForAutoAddedSignatures"] = {
            "brief": "Auto-added signatures use a medium accuracy threshold.",
            "details": (
                f"The minimum accuracy for auto-added signatures is configured as '{output}'. "
                "Higher accuracy levels reduce the likelihood of false positives but may detect fewer attack variants. "
                "Review this setting to ensure it aligns with your risk tolerance and tuning approach."
            ),
            "title": "Minimum Accuracy of auto added Signatures",
            "section": "Signatures",
            "rating": "Info",
            "issue": True
        }

    # ---------- Trusted IPs / Policy Builder ----------
    output = trustedByPolicyBuilder(input)
    if output == 0:
        problems_found["trustedByPolicyBuilder"] = {
            "brief": "No trusted IPs are defined for Policy Builder learning.",
            "details": (
                "No trusted IP addresses are configured for policy building. "
                "Trusted IPs help the Policy Builder learn from known good traffic and accelerate accurate policy creation. "
                "Define one or more trusted sources (for example, QA, administrators, or internal users) to improve the quality of automatic learning."
            ),
            "title": "Trusted IPs for Policy building",
            "section": "PolicyBuilder",
            "rating": "Info",
            "issue": True
        }

    output = trustAllIps(input)
    if output is True:
        problems_found["trustedByPolicyBuilder"] = {
            "brief": "Policy Builder trusts all IPs, allowing untrusted sources to influence learning.",
            "details": (
                "Policy Builder is configured to trust all IP addresses. "
                "Trusting all sources can allow malicious traffic to influence the learning process and relax the policy incorrectly. "
                "Restrict trusted IPs to a small set of known good sources instead of using 'trust all IPs'."
            ),
            "title": "Change 'Trusted IPs' from All to Selected IPs",
            "section": "PolicyBuilder",
            "rating": "Info",
            "issue": True
        }

    return problems_found


if __name__ == "__main__":

    input = Path("policy.json")
    try:
        with open(input, "r", encoding="utf-8") as f:
            data = json.load(f)

    except Exception as e:
        print(f"Error reading {input.name}: {e}")
        exit()


    output = run_audit(data["policy"])
    print(json.dumps(output, indent=4))





